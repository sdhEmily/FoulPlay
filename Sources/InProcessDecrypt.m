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

#define FPLog(...) FPLogger(@"Dec", __VA_ARGS__)

// ── mremap_encrypted ──────────────────────────────────────────────────────────
//
// Private Apple syscall: applies FairPlay decryption to a MAP_PRIVATE region.
// It requires the calling process to be a platform binary. The jailbreak
// platformizes apps under /var/jb/Applications, so that check *passes* — it is
// not removed or patched out, which is why csflags below reads platform=1 and
// why this works identically under Dopamine and palera1n.
//
// EPERM here with the platform bit already set means FairPlay has no key for
// this app on this device, not that we lack permission to ask.
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

#ifndef CPU_SUBTYPE_ARM64E
#define CPU_SUBTYPE_ARM64E 2
#endif

typedef struct {
    uint64_t sliceFileOffset;
    uint64_t sliceSize;
    uint32_t cryptoff;
    uint32_t cryptsize;
    uint32_t cryptid;
    uint32_t cputype;
    uint32_t cpusubtype;
    uint64_t cryptCmdOffset;   // absolute file offset of LC_ENCRYPTION_INFO_64
    BOOL     encrypted;        // found an encrypted arm64 slice
} EncryptionRegion;

typedef struct {
    EncryptionRegion region;
    BOOL readable;             // parsed the container at all
    BOOL foundArm64;           // a plain arm64 slice was present
    BOOL sawArm64e;
    BOOL saw32bit;
} ScanResult;

// pread rather than lseek+read: half the syscalls, and no dependence on the
// file position, which matters because the same fd is used for mmap below.
static BOOL readAt(int fd, off_t offset, void *buf, size_t size) {
    size_t done = 0;
    while (done < size) {
        ssize_t n = pread(fd, (uint8_t *)buf + done, size - done, offset + (off_t)done);
        if (n <= 0) return NO;
        done += (size_t)n;
    }
    return YES;
}

// Inspect one slice. Fills `out` only for a plain arm64 slice; arm64e and
// 32-bit slices are just recorded in the flags so the caller can say which
// unsupported thing it found instead of failing vaguely.
static void scanSlice(int fd, uint64_t fileSize, uint64_t sliceOff,
                      uint64_t sliceSize, ScanResult *res) {
    if (sliceOff > fileSize || sliceSize > fileSize - sliceOff) return;

    uint32_t magic = 0;
    if (!readAt(fd, (off_t)sliceOff, &magic, 4)) return;
    if (magic == MH_MAGIC || magic == MH_CIGAM) { res->saw32bit = YES; return; }
    if (magic != MH_MAGIC_64) return;

    struct mach_header_64 hdr;
    if (!readAt(fd, (off_t)sliceOff, &hdr, sizeof(hdr))) return;

    uint32_t subtype = (uint32_t)hdr.cpusubtype & ~CPU_SUBTYPE_MASK;
    if ((uint32_t)hdr.cputype != (uint32_t)CPU_TYPE_ARM64) return;
    if (subtype == CPU_SUBTYPE_ARM64E) { res->sawArm64e = YES; return; }

    res->foundArm64 = YES;
    if (res->region.encrypted) return;             // already have one

    // Pull the whole load-command block in one read and walk it in memory.
    // Doing it per-command cost a syscall each, and the pre-flight runs this
    // over every framework and appex in the bundle, not just the main binary.
    uint64_t cmdOff = sliceOff + sizeof(hdr);
    if (hdr.sizeofcmds == 0 || hdr.sizeofcmds > (16u << 20)) return;
    if (cmdOff + hdr.sizeofcmds > fileSize) return;
    if (sliceSize && cmdOff + hdr.sizeofcmds > sliceOff + sliceSize) return;

    uint8_t *cmds = malloc(hdr.sizeofcmds);
    if (!cmds) return;
    if (!readAt(fd, (off_t)cmdOff, cmds, hdr.sizeofcmds)) { free(cmds); return; }

    uint32_t pos = 0;
    for (uint32_t i = 0; i < hdr.ncmds; i++) {
        if (pos + sizeof(struct load_command) > hdr.sizeofcmds) break;
        struct load_command lc;
        memcpy(&lc, cmds + pos, sizeof(lc));
        // A zero/undersized cmdsize would spin this loop forever on a corrupt file.
        // The bound is written as a subtraction, not `pos + lc.cmdsize > sizeofcmds`:
        // both are uint32_t, so that sum wraps mod 2^32 and a crafted cmdsize of
        // ~0xFFFFFFF0 slipped past it into the memcpy below, reading off the end of
        // the malloc. The check above guarantees pos <= sizeofcmds, so this cannot
        // underflow.
        if (lc.cmdsize < sizeof(lc) || lc.cmdsize > hdr.sizeofcmds - pos) break;

        if (lc.cmd == LC_ENCRYPTION_INFO_64 &&
            lc.cmdsize >= sizeof(struct encryption_info_command_64)) {
            struct encryption_info_command_64 enc;
            memcpy(&enc, cmds + pos, sizeof(enc));
            if (enc.cryptid == 0) break;           // arm64 slice, already decrypted
            res->region = (EncryptionRegion){
                .sliceFileOffset = sliceOff, .sliceSize = sliceSize,
                .cryptoff = enc.cryptoff,    .cryptsize = enc.cryptsize,
                .cryptid  = enc.cryptid,     .cryptCmdOffset = cmdOff + pos,
                .cputype  = (uint32_t)hdr.cputype, .cpusubtype = subtype,
                .encrypted = YES,
            };
            break;
        }
        pos += lc.cmdsize;
    }
    free(cmds);
}

static ScanResult scanBinary(int fd, uint64_t fileSize) {
    ScanResult res = {0};

    uint32_t magic = 0;
    if (!readAt(fd, 0, &magic, 4)) return res;

    if (magic == FAT_CIGAM || magic == FAT_MAGIC) {
        struct fat_header fh;
        if (!readAt(fd, 0, &fh, sizeof(fh))) return res;
        uint32_t nArch = (magic == FAT_CIGAM)
            ? OSSwapBigToHostInt32(fh.nfat_arch) : fh.nfat_arch;
        if (nArch == 0 || nArch > 32) {
            FPLog(@"fat header claims %u slices — refusing", nArch);
            return res;
        }
        res.readable = YES;
        for (uint32_t i = 0; i < nArch; i++) {
            struct fat_arch arch;
            if (!readAt(fd, (off_t)(sizeof(fh) + i * sizeof(arch)), &arch, sizeof(arch))) break;
            uint64_t off  = (magic == FAT_CIGAM)
                ? OSSwapBigToHostInt32(arch.offset) : arch.offset;
            uint64_t size = (magic == FAT_CIGAM)
                ? OSSwapBigToHostInt32(arch.size)   : arch.size;
            scanSlice(fd, fileSize, off, size, &res);
        }
    } else if (magic == MH_MAGIC_64) {
        res.readable = YES;
        scanSlice(fd, fileSize, 0, fileSize, &res);
    } else if (magic == MH_MAGIC || magic == MH_CIGAM) {
        res.readable = YES;
        res.saw32bit = YES;
    } else if (magic == FAT_CIGAM_64 || magic == FAT_MAGIC_64) {
        // 64-bit fat headers use fat_arch_64; say so rather than misparsing.
        FPLog(@"64-bit fat header (fat_arch_64) — unsupported");
    }
    return res;
}

// Shared by the pre-flight and the decrypt path so they can never disagree
// about what a binary is. Returns nil if there IS a live encrypted arm64
// slice; otherwise a user-facing reason there isn't.
static NSString *classifyReason(ScanResult scan, NSString *name) {
    if (!scan.readable)                        return @"can't parse this binary";
    if (!scan.foundArm64 && scan.sawArm64e)    return @"arm64e binaries are unsupported";
    if (!scan.foundArm64 && scan.saw32bit)     return @"armv7 binaries are unsupported";
    if (!scan.foundArm64)                      return @"can't parse this binary";
    if (!scan.region.encrypted) {
        // An unencrypted arm64 slice does not mean the app is decrypted: a fat
        // binary can carry a small unencrypted arm64 stub alongside encrypted
        // armv7/arm64e slices. Saying "already decrypted" there is wrong.
        if (scan.sawArm64e || scan.saw32bit)
            return @"arm64 slice isn't encrypted (other slices unsupported)";
        return [NSString stringWithFormat:@"%@ is already decrypted", name ?: @"binary"];
    }
    return nil;
}

// The messages above are deliberately short, and two of them are the same
// string for different reasons, so the flags that produced one are logged
// alongside it — otherwise a rejection is untraceable after the fact.
static NSString *classify(ScanResult scan, NSString *name) {
    NSString *why = classifyReason(scan, name);
    if (why)
        FPLog(@"%@: rejected as \"%@\" "
              @"(readable=%d arm64=%d arm64e=%d 32bit=%d encrypted=%d)",
              name ?: @"binary", why, (int)scan.readable, (int)scan.foundArm64,
              (int)scan.sawArm64e, (int)scan.saw32bit, (int)scan.region.encrypted);
    return why;
}

BOOL binaryNeedsDecryption(NSString *binaryPath, NSString *displayName,
                           NSString **reason) {
    int fd = open(binaryPath.UTF8String, O_RDONLY);
    if (fd < 0) {
        if (reason) *reason = [NSString stringWithFormat:
            @"open(%@): %s", binaryPath.lastPathComponent, strerror(errno)];
        return NO;
    }
    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size <= 0) {
        close(fd);
        if (reason) *reason = [NSString stringWithFormat:
            @"fstat(%@): %s", binaryPath.lastPathComponent, strerror(errno)];
        return NO;
    }
    NSString *why = classify(scanBinary(fd, (uint64_t)st.st_size),
                             displayName ?: binaryPath.lastPathComponent);
    close(fd);
    if (why) {
        FPLog(@"%@: %@", binaryPath.lastPathComponent, why);
        if (reason) *reason = why;
        return NO;
    }
    return YES;
}

// ── Public entry point ────────────────────────────────────────────────────────
//
// Decrypts every FairPlay-encrypted slice of `binaryPath` in place.
// Newer App Store builds ship versioned FairPlay supplements alongside the sinf
// (TVRemoteApp.v4.supp, TVRemoteApp.v5.supf). The supf carries the key that
// actually decrypts the Mach-O, so a scheme the running kernel has no crypter
// for makes mremap_encrypted fail to set one up — it returns ENOMEM, which on
// its own reads as an out-of-memory condition and explains nothing.
static BOOL hasVersionedSupplements(NSString *appBundleDir) {
    NSString *dir = [appBundleDir stringByAppendingPathComponent:@"SC_Info"];
    NSArray<NSString *> *names =
        [[NSFileManager defaultManager] contentsOfDirectoryAtPath:dir error:nil];
    for (NSString *name in names) {
        NSString *ext = name.pathExtension;
        if (![ext isEqualToString:@"supf"] && ![ext isEqualToString:@"supp"] &&
            ![ext isEqualToString:@"supx"]) continue;
        // "<name>.v5.supf" -> the component before the extension is "v<digits>"
        NSString *tag = name.stringByDeletingPathExtension.pathExtension;
        if (tag.length < 2 || ![tag hasPrefix:@"v"]) continue;
        NSCharacterSet *nonDigit =
            [[NSCharacterSet decimalDigitCharacterSet] invertedSet];
        if ([[tag substringFromIndex:1] rangeOfCharacterFromSet:nonDigit].location
                == NSNotFound)
            return YES;
    }
    return NO;
}

// `appBundleDir` must contain SC_Info/<binary>.sinf.
//
BOOL decryptBinaryAtPath(NSString *binaryPath,
                         NSString *appBundleDir,
                         BOOL (^isCancelled)(void),
                         NSString **errorOut) {

    uint32_t csFlags = 0;
    csops(getpid(), CS_OPS_STATUS, &csFlags, sizeof(csFlags));
    FPLog(@"csflags=0x%x  platform=%d  euid=%d",
          csFlags, !!(csFlags & 0x04000000), (int)geteuid());

    mremap_encrypted_fn mremap_enc = resolve_mremap_encrypted();
    if (!mremap_enc) {
        if (errorOut) *errorOut = @"mremap_encrypted not found in dyld shared cache";
        return NO;
    }

    // The kernel locates SC_Info/<binary>.sinf relative to the CWD. chdir is
    // process-global, so callers must not run two decryptions concurrently.
    char cwdBuf[PATH_MAX];
    const char *prevCWD = getcwd(cwdBuf, sizeof(cwdBuf));
    if (chdir(appBundleDir.UTF8String) != 0)
        FPLog(@"chdir %@ failed: %s (non-fatal)", appBundleDir, strerror(errno));
    void (^restoreCWD)(void) = ^{ if (prevCWD) chdir(prevCWD); };

    int fd = open(binaryPath.UTF8String, O_RDWR);
    if (fd < 0) {
        restoreCWD();
        if (errorOut) *errorOut = [NSString stringWithFormat:
            @"open(%@): %s", binaryPath.lastPathComponent, strerror(errno)];
        return NO;
    }

    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size <= 0) {
        close(fd); restoreCWD();
        if (errorOut) *errorOut = [NSString stringWithFormat:
            @"fstat(%@): %s", binaryPath.lastPathComponent, strerror(errno)];
        return NO;
    }
    size_t fileSize = (size_t)st.st_size;

    ScanResult scan = scanBinary(fd, fileSize);

    // "Couldn't parse this", "this arch isn't supported" and "this isn't
    // encrypted" are three different answers. Collapsing them into success
    // produced a cheerful tick over an IPA that was still fully encrypted.
    NSString *why = classify(scan, binaryPath.lastPathComponent);
    if (why) {
        close(fd); restoreCWD();
        FPLog(@"%@: %@", binaryPath.lastPathComponent, why);
        if (errorOut) *errorOut = why;
        return NO;
    }
    EncryptionRegion enc = scan.region;

    if (scan.sawArm64e)
        FPLog(@"%@: fat binary also has an arm64e slice — left encrypted",
              binaryPath.lastPathComponent);

    FPLog(@"%@: slice=0x%llx cryptoff=0x%x cryptsize=0x%x cryptid=%u cpu=%u/%u",
          binaryPath.lastPathComponent, enc.sliceFileOffset, enc.cryptoff,
          enc.cryptsize, enc.cryptid, enc.cputype, enc.cpusubtype);

    if (enc.cryptoff > enc.sliceSize || enc.cryptsize > enc.sliceSize - enc.cryptoff) {
        close(fd); restoreCWD();
        if (errorOut) *errorOut = @"LC_ENCRYPTION_INFO_64 region is out of bounds";
        return NO;
    }

    uint64_t cryptFileOff = enc.sliceFileOffset + enc.cryptoff;
    const size_t PAGE = (size_t)sysconf(_SC_PAGESIZE);
    if (cryptFileOff & (PAGE - 1)) {
        close(fd); restoreCWD();
        if (errorOut) *errorOut = @"encrypted region is not page-aligned";
        return NO;
    }

    void *fileMem = mmap(NULL, fileSize, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (fileMem == MAP_FAILED) {
        close(fd); restoreCWD();
        if (errorOut) *errorOut = [NSString stringWithFormat:
            @"mmap MAP_SHARED: %s", strerror(errno)];
        return NO;
    }

    uint8_t *destBase = (uint8_t *)fileMem + cryptFileOff;
    const size_t CHUNK_MAX = 16 * 1024 * 1024;
    BOOL ok = YES;
    uint32_t processed = 0;

    while (processed < enc.cryptsize) {
        // Checked per chunk — a large binary is the longest single stretch of
        // work in a run, so this is where a cancel needs to land promptly.
        if (isCancelled && isCancelled()) {
            FPLog(@"cancelled after %u / %u bytes", processed, enc.cryptsize);
            ok = NO;
            if (errorOut) *errorOut = @"cancelled";
            break;
        }
        uint32_t remaining = enc.cryptsize - processed;
        size_t chunkSize   = (remaining < CHUNK_MAX) ? (size_t)remaining : CHUNK_MAX;
        off_t chunkFileOffset = (off_t)(cryptFileOff + processed);

        void *chunk = mmap(NULL, chunkSize, PROT_READ, MAP_PRIVATE, fd, chunkFileOffset);
        if (chunk == MAP_FAILED) {
            FPLog(@"mmap chunk @0x%llx: %s", (uint64_t)chunkFileOffset, strerror(errno));
            if (errorOut) *errorOut = [NSString stringWithFormat:
                @"mmap chunk: %s", strerror(errno)];
            ok = NO; break;
        }

        // cryptid=2 is the FairPlay algorithm identifier the kernel expects
        // here — it is not the cryptid from the load command.
        int ret = mremap_enc(chunk, chunkSize, /*cryptid=*/2,
                             enc.cputype, enc.cpusubtype);
        if (ret != 0) {
            int savedErrno = errno;
            FPLog(@"mremap_encrypted @0x%llx: ret=%d errno=%d (%s)",
                  (uint64_t)chunkFileOffset, ret, savedErrno, strerror(savedErrno));
            munmap(chunk, chunkSize);
            ok = NO;
            // EPERM with CS_PLATFORM_BINARY already set means the check we
            // could fail is satisfied, so the refusal is FairPlay itself. The
            // keybag is per-Apple-ID and provisioned on a device by its first
            // App Store download — not per app — so this means the device has
            // no keybag yet, or the IPA belongs to a different Apple ID.
            // The numbers stay in the log; the label says the short version.
            BOOL isPlatform = (csFlags & 0x04000000) != 0;
            if (errorOut) {
                if (savedErrno == EPERM && isPlatform) {
                    *errorOut = @"FairPlay keys missing";
                } else if (savedErrno == ENOMEM &&
                           hasVersionedSupplements(appBundleDir)) {
                    *errorOut = @"SC_Info format unsupported";
                } else {
                    *errorOut = [NSString stringWithFormat:
                        @"mremap_encrypted failed: errno=%d (%s)\ncsflags=0x%x (%@)",
                        savedErrno, strerror(savedErrno), csFlags,
                        isPlatform ? @"platform binary"
                                   : @"not a platform binary — check the kernel patch"];
                }
            }
            break;
        }

        memcpy(destBase + processed, chunk, chunkSize);
        munmap(chunk, chunkSize);
        processed += (uint32_t)chunkSize;
        FPLog(@"decrypted %u / %u bytes", processed, enc.cryptsize);
    }

    if (ok) {
        struct encryption_info_command_64 *cmd =
            (struct encryption_info_command_64 *)
            ((uint8_t *)fileMem + enc.cryptCmdOffset);
        cmd->cryptid = 0;
        // MS_ASYNC, not MS_SYNC: a synchronous flush blocks the worker for as
        // long as it takes to push the whole crypt region to flash, and this
        // file is about to be read straight back out of page cache by the
        // repack and then deleted. munmap below still commits the dirty pages.
        msync(fileMem, fileSize, MS_ASYNC);
        FPLog(@"cryptid -> 0, msync queued");
    }

    munmap(fileMem, fileSize);
    close(fd);
    restoreCWD();
    return ok;
}
