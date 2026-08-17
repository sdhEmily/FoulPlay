#import "InProcessDecrypt.h"
#import "LogHelper.h"

#include <dlfcn.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <mach-o/loader.h>
#include <mach-o/fat.h>

// csops — private syscall, not in SDK headers
#define CS_OPS_STATUS 0
extern int csops(pid_t pid, unsigned int ops, void *useraddr, size_t usersize);

#define FPLog(...) FPFileLog(@"Dec", __VA_ARGS__)

// ── mremap_encrypted ──────────────────────────────────────────────────────────
//
// Private Apple syscall: applies FairPlay decryption to a MAP_PRIVATE region.
// On a Dopamine-patched kernel the CS_PLATFORM_BINARY requirement is expected
// to be removed, so we call it directly without any privilege setup.
//
typedef int (*mremap_encrypted_fn)(void *, size_t, uint32_t, uint32_t, uint32_t);

static mremap_encrypted_fn resolve_mremap_encrypted(void) {
    static mremap_encrypted_fn fn = NULL;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        fn = (mremap_encrypted_fn)dlsym(RTLD_DEFAULT, "mremap_encrypted");
        if (fn)
            FPLog(@"mremap_encrypted resolved @ %p", (void *)fn);
        else
            FPLog(@"mremap_encrypted NOT found in dyld shared cache");
    });
    return fn;
}

// ── Mach-O parsing ────────────────────────────────────────────────────────────

typedef struct {
    uint64_t sliceFileOffset;
    uint64_t sliceSize;
    uint32_t cryptoff;
    uint32_t cryptsize;
    uint32_t cryptid;
    uint64_t cryptCmdOffset;   // absolute file offset of LC_ENCRYPTION_INFO_64
    BOOL     valid;
} EncryptionRegion;

static BOOL readAt(int fd, off_t offset, void *buf, size_t size) {
    if (lseek(fd, offset, SEEK_SET) < 0) return NO;
    size_t done = 0;
    while (done < size) {
        ssize_t n = read(fd, (uint8_t *)buf + done, size - done);
        if (n <= 0) return NO;
        done += n;
    }
    return YES;
}

static EncryptionRegion parseEncryptionRegion(int fd) {
    EncryptionRegion r = {0};

    uint32_t magic = 0;
    if (!readAt(fd, 0, &magic, 4)) return r;

    uint64_t sliceOff = 0, sliceSize = 0;

    if (magic == FAT_CIGAM) {
        struct fat_header fh;
        if (!readAt(fd, 0, &fh, sizeof(fh))) return r;
        uint32_t nArch = OSSwapBigToHostInt32(fh.nfat_arch);
        for (uint32_t i = 0; i < nArch; i++) {
            struct fat_arch arch;
            off_t archOff = (off_t)(sizeof(fh) + i * sizeof(arch));
            if (!readAt(fd, archOff, &arch, sizeof(arch))) return r;
            if ((cpu_type_t)OSSwapBigToHostInt32(arch.cputype) == CPU_TYPE_ARM64) {
                sliceOff  = OSSwapBigToHostInt32(arch.offset);
                sliceSize = OSSwapBigToHostInt32(arch.size);
                break;
            }
        }
        if (!sliceOff) return r;
    } else if (magic == MH_MAGIC_64) {
        struct stat st;
        if (fstat(fd, &st) != 0) return r;
        sliceOff  = 0;
        sliceSize = (uint64_t)st.st_size;
    } else {
        return r;
    }

    r.sliceFileOffset = sliceOff;
    r.sliceSize       = sliceSize;

    struct mach_header_64 hdr;
    if (!readAt(fd, (off_t)sliceOff, &hdr, sizeof(hdr))) return r;
    if (hdr.magic != MH_MAGIC_64) return r;

    uint64_t cmdOff = sliceOff + sizeof(hdr);
    for (uint32_t i = 0; i < hdr.ncmds; i++) {
        struct load_command lc;
        if (!readAt(fd, (off_t)cmdOff, &lc, sizeof(lc))) break;
        if (lc.cmd == LC_ENCRYPTION_INFO_64) {
            struct encryption_info_command_64 enc;
            if (!readAt(fd, (off_t)cmdOff, &enc, sizeof(enc))) break;
            r.cryptoff       = enc.cryptoff;
            r.cryptsize      = enc.cryptsize;
            r.cryptid        = enc.cryptid;
            r.cryptCmdOffset = cmdOff;
            r.valid          = YES;
            break;
        }
        cmdOff += lc.cmdsize;
    }
    return r;
}

// ── Public entry point ────────────────────────────────────────────────────────
//
// Decrypts the FairPlay-encrypted arm64 slice of `binaryPath` in-place.
// `appBundleDir` must contain SC_Info/<binary>.sinf.
//
// No jailbreak primitives used: mremap_encrypted is called directly.
// On a Dopamine-patched kernel the CS_PLATFORM_BINARY guard is expected to
// be absent; on a stock kernel this returns an error with errno=EPERM.
//
BOOL decryptBinaryAtPath(NSString *binaryPath,
                         NSString *appBundleDir,
                         NSString **errorOut) {

    // ── Step 1: Log csflags (diagnostic only — we don't modify them) ─────────
    uint32_t csFlags = 0;
    csops(getpid(), CS_OPS_STATUS, &csFlags, sizeof(csFlags));
    FPLog(@"csflags=0x%x  platform=%d  euid=%d",
          csFlags, !!(csFlags & 0x04000000), (int)geteuid());

    // ── Step 2: Resolve mremap_encrypted ─────────────────────────────────────
    mremap_encrypted_fn mremap_enc = resolve_mremap_encrypted();
    if (!mremap_enc) {
        if (errorOut) *errorOut = @"mremap_encrypted not found in dyld shared cache";
        return NO;
    }

    // ── Step 3: Change CWD to the app bundle directory ───────────────────────
    // The kernel locates SC_Info/<binary>.sinf relative to the binary's dir.
    char prevCWD[PATH_MAX];
    getcwd(prevCWD, sizeof(prevCWD));
    if (chdir(appBundleDir.UTF8String) != 0) {
        FPLog(@"chdir %@ failed: %s (non-fatal)", appBundleDir, strerror(errno));
    } else {
        FPLog(@"CWD → %@", appBundleDir);
    }

    // ── Step 4: Open binary read-write ───────────────────────────────────────
    int fd = open(binaryPath.UTF8String, O_RDWR);
    if (fd < 0) {
        chdir(prevCWD);
        if (errorOut) *errorOut = [NSString stringWithFormat:
            @"open(%@): %s", binaryPath.lastPathComponent, strerror(errno)];
        return NO;
    }

    // ── Step 5: Parse encryption info ────────────────────────────────────────
    EncryptionRegion enc = parseEncryptionRegion(fd);
    if (!enc.valid) {
        close(fd); chdir(prevCWD);
        FPLog(@"No LC_ENCRYPTION_INFO_64 — binary not encrypted, done");
        return YES;
    }
    if (enc.cryptid == 0) {
        close(fd); chdir(prevCWD);
        FPLog(@"cryptid==0 already — skipping");
        return YES;
    }

    FPLog(@"slice=0x%llx  cryptoff=0x%x  cryptsize=0x%x  cryptid=%u",
          enc.sliceFileOffset, enc.cryptoff, enc.cryptsize, enc.cryptid);

    uint64_t cryptFileOff = enc.sliceFileOffset + enc.cryptoff;

    // ── Step 6: mmap the file read-write (MAP_SHARED) for writing back ───────
    struct stat st;
    fstat(fd, &st);
    size_t fileSize = (size_t)st.st_size;

    void *fileMem = mmap(NULL, fileSize, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (fileMem == MAP_FAILED) {
        close(fd); chdir(prevCWD);
        if (errorOut) *errorOut = [NSString stringWithFormat:
            @"mmap MAP_SHARED: %s", strerror(errno)];
        return NO;
    }

    uint8_t *destBase = (uint8_t *)fileMem + cryptFileOff;

    // ── Step 7: Decrypt in 16 MB chunks ──────────────────────────────────────
    const size_t PAGE      = (size_t)sysconf(_SC_PAGESIZE);
    const size_t CHUNK_MAX = 16 * 1024 * 1024;

    BOOL ok = YES;
    uint32_t processed = 0;

    while (processed < enc.cryptsize) {
        uint32_t remaining = enc.cryptsize - processed;
        size_t chunkSize   = (remaining < (uint32_t)CHUNK_MAX)
                             ? (size_t)remaining : CHUNK_MAX;
        size_t alignedSize = (chunkSize + PAGE - 1) & ~(PAGE - 1);
        if (processed + alignedSize > enc.cryptsize)
            alignedSize = enc.cryptsize - processed;

        off_t chunkFileOffset = (off_t)(cryptFileOff + processed);

        void *chunk = mmap(NULL, alignedSize, PROT_READ,
                           MAP_PRIVATE, fd, chunkFileOffset);
        if (chunk == MAP_FAILED) {
            FPLog(@"mmap chunk @0x%llx: %s",
                  (uint64_t)chunkFileOffset, strerror(errno));
            ok = NO; break;
        }

        // cryptid=2 is the FairPlay "model" algorithm identifier
        int ret = mremap_enc(chunk, alignedSize,
                             /*cryptid=*/2,
                             (uint32_t)CPU_TYPE_ARM64,
                             (uint32_t)CPU_SUBTYPE_ARM64_ALL);
        if (ret != 0) {
            int savedErrno = errno;
            FPLog(@"mremap_encrypted @0x%llx: ret=%d errno=%d (%s)",
                  (uint64_t)chunkFileOffset, ret, savedErrno, strerror(savedErrno));
            munmap(chunk, alignedSize);
            ok = NO;
            if (errorOut) *errorOut = [NSString stringWithFormat:
                @"mremap_encrypted failed: errno=%d (%s)\n"
                @"csflags=0x%x — kernel patch may not bypass CS_PLATFORM_BINARY check",
                savedErrno, strerror(savedErrno), csFlags];
            break;
        }

        memcpy(destBase + processed, chunk, chunkSize);
        munmap(chunk, alignedSize);

        processed += (uint32_t)chunkSize;
        FPLog(@"decrypted %u / %u bytes", processed, enc.cryptsize);
    }

    // ── Step 8: Zero cryptid in LC_ENCRYPTION_INFO_64 ────────────────────────
    if (ok) {
        struct encryption_info_command_64 *encCmd =
            (struct encryption_info_command_64 *)
            ((uint8_t *)fileMem + enc.cryptCmdOffset);
        encCmd->cryptid = 0;
        msync(fileMem, fileSize, MS_SYNC);
        FPLog(@"cryptid → 0, msync done");
    }

    munmap(fileMem, fileSize);
    close(fd);
    chdir(prevCWD);

    return ok;
}
