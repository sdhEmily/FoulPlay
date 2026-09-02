#import "Decryptor.h"
#import "InProcessDecrypt.h"
#import "LogHelper.h"

#import "ArchiveAPI.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// ── Helpers ───────────────────────────────────────────────────────────────────

NSString *const FoulPlayErrorDomain = @"gay.sdh.foulplay";

static NSError *FPError(NSString *msg) {
    return [NSError errorWithDomain:FoulPlayErrorDomain
                               code:FoulPlayErrorFailed
                           userInfo:@{NSLocalizedDescriptionKey: msg}];
}

static NSError *FPCancelled(void) {
    return [NSError errorWithDomain:FoulPlayErrorDomain
                               code:FoulPlayErrorCancelled
                           userInfo:@{NSLocalizedDescriptionKey: @"Cancelled"}];
}

// libarchive's last error for `a`, prefixed with what we were attempting.
// errno is included when set — "Failed to open <path>" alone did not
// distinguish a missing directory from a sandbox denial.
static NSString *archiveError(struct archive *a, NSString *what) {
    const char *e = archive_error_string(a);
    int err = archive_errno(a);
    if (err)
        return [NSString stringWithFormat:@"%@: %s (errno=%d %s)",
                what, e ?: "unknown error", err, strerror(err)];
    return [NSString stringWithFormat:@"%@: %s", what, e ?: "unknown error"];
}

// Extract a ZIP into destDir in-process via libarchive.
// Returns nil on success, an error string on failure.
static NSString *extractZIP(NSString *zipPath, NSString *destDir,
                            BOOL (^isCancelled)(void)) {
    struct archive *ar = archive_read_new();
    archive_read_support_format_zip(ar);

    struct archive *wr = archive_write_disk_new();
    archive_write_disk_set_options(wr,
        ARCHIVE_EXTRACT_TIME | ARCHIVE_EXTRACT_PERM |
        ARCHIVE_EXTRACT_SECURE_NODOTDOT | ARCHIVE_EXTRACT_SECURE_SYMLINKS);

    if (archive_read_open_filename(ar, zipPath.UTF8String, 65536) != ARCHIVE_OK) {
        // "Unrecognized archive format" means the file isn't a zip at all, which
        // is a user mistake rather than a fault worth spelling out. libarchive
        // reports it as EFTYPE on Darwin, but not always with errno set, so the
        // message is matched too. The raw error still goes to the debug log.
        int aerr = archive_errno(ar);
        const char *astr = archive_error_string(ar);
        BOOL notAnArchive = (aerr == EFTYPE) ||
            (astr && strstr(astr, "Unrecognized archive format") != NULL);

        NSString *msg = archiveError(ar, @"open IPA");
        FPLogger(@"Dec", @"%@", msg);
        if (notAnArchive) msg = @"This isn't an IPA, silly!";

        archive_read_free(ar); archive_write_free(wr);
        return msg;
    }

    NSString *err = nil;
    struct archive_entry *entry;
    int r;

    while ((r = archive_read_next_header(ar, &entry)) == ARCHIVE_OK) {
        if (isCancelled && isCancelled()) break;   // caller checks the flag
        NSString *rel = @(archive_entry_pathname(entry));
        NSString *abs = [destDir stringByAppendingPathComponent:rel];
        archive_entry_set_pathname(entry, abs.UTF8String);

        if (archive_write_header(wr, entry) != ARCHIVE_OK) {
            err = archiveError(wr, ([NSString stringWithFormat:@"create %@", rel]));
            break;
        }

        const void *buf; size_t sz; la_int64_t off;
        int d;
        while ((d = archive_read_data_block(ar, &buf, &sz, &off)) == ARCHIVE_OK) {
            if (archive_write_data_block(wr, buf, sz, off) != ARCHIVE_OK) {
                err = archiveError(wr, ([NSString stringWithFormat:@"write %@", rel]));
                break;
            }
        }
        if (err) break;
        if (d != ARCHIVE_EOF) {
            err = archiveError(ar, ([NSString stringWithFormat:@"read %@", rel]));
            break;
        }
        archive_write_finish_entry(wr);
    }

    // r == ARCHIVE_OK means the loop broke early on cancel, not an error.
    if (!err && r != ARCHIVE_EOF && r != ARCHIVE_OK)
        err = archiveError(ar, @"read IPA");

    archive_read_close(ar); archive_read_free(ar);
    archive_write_close(wr); archive_write_free(wr);
    return err;
}

// Payload types that are already compressed. Deflating them costs CPU and
// returns nothing: measured on a representative payload, storing these instead
// cut packing time 45% (0.98s -> 0.54s) for a byte-identical archive.
static BOOL isPrecompressed(NSString *path) {
    static NSSet<NSString *> *exts;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        exts = [NSSet setWithArray:@[@"png", @"jpg", @"jpeg", @"gif", @"heic",
                                     @"webp", @"mp3", @"m4a", @"aac", @"mp4",
                                     @"m4v", @"mov", @"woff", @"woff2", @"zip",
                                     @"gz", @"bz2", @"xz", @"jar", @"ipa", @"tipa"]];
    });
    return [exts containsObject:path.pathExtension.lowercaseString];
}

// Zip up rootDir/subDir into outPath, with entry paths relative to rootDir
// (e.g. "Payload/App.app/Info.plist"). Returns nil on success.
static NSString *createZIP(NSString *outPath, NSString *rootDir, NSString *subDir,
                           BOOL (^isCancelled)(void)) {
    struct archive *zip = archive_write_new();
    archive_write_set_format_zip(zip);
    // libarchive defaults to 10 KB blocks, so a ~900 MB IPA costs ~88k write()
    // syscalls instead of ~860.
    archive_write_set_bytes_per_block(zip, 1 << 20);
    // Deflate defaults to level 6. An IPA is mostly already-compressed assets,
    // so the high levels burn a lot of CPU for very little size — level 1 still
    // compresses the decrypted Mach-O well and makes packing far quicker.
    archive_write_set_options(zip, "zip:compression-level=1");

    if (archive_write_open_filename(zip, outPath.UTF8String) != ARCHIVE_OK) {
        NSString *err = archiveError(zip, @"create IPA");
        archive_write_free(zip);
        return err;
    }

    struct archive *disk = archive_read_disk_new();
    archive_read_disk_set_symlink_physical(disk);

    NSString *startPath = [rootDir stringByAppendingPathComponent:subDir];
    NSUInteger prefixLen = rootDir.length + 1;   // strip "rootDir/"

    if (archive_read_disk_open(disk, startPath.UTF8String) != ARCHIVE_OK) {
        NSString *err = archiveError(disk, @"scan Payload");
        archive_read_free(disk); archive_write_free(zip);
        return err;
    }

    NSString *err = nil;
    struct archive_entry *entry = archive_entry_new();
    int r;

    while ((r = archive_read_next_header2(disk, entry)) == ARCHIVE_OK) {
        if (isCancelled && isCancelled()) break;   // caller checks the flag
        archive_read_disk_descend(disk);

        const char *srcpath = archive_entry_sourcepath(entry);
        NSString *fullPath = @(srcpath);
        if (fullPath.length <= prefixLen) continue;
        archive_entry_set_pathname(entry,
            [fullPath substringFromIndex:prefixLen].UTF8String);

        if (isPrecompressed(fullPath)) archive_write_zip_set_compression_store(zip);
        else                           archive_write_zip_set_compression_deflate(zip);

        if (archive_write_header(zip, entry) != ARCHIVE_OK) {
            err = archiveError(zip, @"zip header");
            break;
        }

        if (archive_entry_size(entry) > 0) {
            int fd = open(srcpath, O_RDONLY);
            if (fd < 0) {
                err = [NSString stringWithFormat:@"open %s: %s", srcpath, strerror(errno)];
                break;
            }
            char buf[65536]; ssize_t n;
            while ((n = read(fd, buf, sizeof(buf))) > 0) {
                if (archive_write_data(zip, buf, (size_t)n) < 0) {
                    err = archiveError(zip, @"zip write");
                    break;
                }
            }
            // n < 0 is an I/O error, not end of file; without this the entry is
            // silently truncated and the run still reports success.
            if (!err && n < 0)
                err = [NSString stringWithFormat:@"read %s: %s", srcpath, strerror(errno)];
            close(fd);
            if (err) break;
        }
    }

    if (!err && r != ARCHIVE_EOF && r != ARCHIVE_OK)
        err = archiveError(disk, @"zip walk");

    archive_entry_free(entry);
    archive_read_close(disk); archive_read_free(disk);
    // close() writes the final block and the central directory — a failure here
    // (ENOSPC being the realistic one) means the zip is unusable, so it cannot
    // be discarded the way a read-side close can.
    if (!err && archive_write_close(zip) != ARCHIVE_OK)
        err = archiveError(zip, @"finish IPA");
    archive_write_free(zip);
    return err;
}

// Main executable of a bundle, per its own Info.plist.
static NSString *bundleExecutable(NSString *bundlePath) {
    NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:
        [bundlePath stringByAppendingPathComponent:@"Info.plist"]];
    NSString *exec = info[@"CFBundleExecutable"];
    if (!exec.length) return nil;
    NSString *path = [bundlePath stringByAppendingPathComponent:exec];
    return [[NSFileManager defaultManager] fileExistsAtPath:path] ? path : nil;
}

// ── Decryptor ─────────────────────────────────────────────────────────────────

@interface Decryptor ()
@property (nonatomic, copy) NSString          *ipaPath;
@property (nonatomic, copy) FoulPlayProgress  progressHandler;
@property (nonatomic, copy, readwrite) NSString *appName;
/// SC_Info dirs we created inside nested bundles, removed before repacking.
@property (nonatomic, strong) NSMutableArray<NSString *> *stagedSCInfo;
/// Atomic — set from the main thread, read from the worker queue.
@property (atomic, assign) BOOL cancelled;
@end

@implementation Decryptor

- (instancetype)initWithIPAPath:(NSString *)ipaPath {
    self = [super init];
    _ipaPath = ipaPath;
    _stagedSCInfo = [NSMutableArray array];
    return self;
}

- (void)cancel {
    self.cancelled = YES;
    FPLogger(@"Dec", @"cancel requested");
}

- (void)decryptWithProgress:(FoulPlayProgress)progress
                 completion:(FoulPlayCompletion)completion {
    _progressHandler = progress;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSError *err = nil;
        NSString *out = [self _run:&err];
        dispatch_async(dispatch_get_main_queue(), ^{
            if (completion) completion(out, err);
        });
    });
}

- (void)_log:(NSString *)msg {
    FPLogger(@"Dec", @"%@", msg);
    if (!_progressHandler) return;
    dispatch_async(dispatch_get_main_queue(), ^{
        if (self->_progressHandler) self->_progressHandler(msg);
    });
}

// ── Main pipeline ─────────────────────────────────────────────────────────────
- (NSString *)_run:(NSError **)outErr {
    [self _log:[NSString stringWithFormat:@"_run started, ipaPath=%@", _ipaPath]];
    NSFileManager *fm = [NSFileManager defaultManager];

    // ── 1. Work directory in /var/tmp/ ────────────────────────────────────────
    NSString *workDir = [@"/var/tmp" stringByAppendingPathComponent:
        [NSString stringWithFormat:@"FoulPlay_%@",
         [[[NSUUID UUID] UUIDString] substringToIndex:8]]];

    NSError *fsErr = nil;
    [fm createDirectoryAtPath:workDir withIntermediateDirectories:YES
                   attributes:nil error:&fsErr];
    if (fsErr) {
        if (outErr) *outErr = FPError(
            [NSString stringWithFormat:@"mkdir work dir: %@", fsErr.localizedDescription]);
        return nil;
    }

    // /var is a symlink to /private/var on iOS, and libarchive's
    // ARCHIVE_EXTRACT_SECURE_SYMLINKS refuses to extract through a symlinked
    // path component. Canonicalise so the guard stays on and still passes.
    char resolved[PATH_MAX];
    if (realpath(workDir.fileSystemRepresentation, resolved))
        workDir = @(resolved);
    [self _log:[NSString stringWithFormat:@"workDir=%@", workDir]];

    void (^cleanup)(void) = ^{
        [[NSFileManager defaultManager] removeItemAtPath:workDir error:nil];
    };

    // _run is invoked from a block that retains self for its whole duration,
    // so these can capture it strongly.
    BOOL (^isCancelled)(void) = ^BOOL{ return self.cancelled; };
    // Returns YES if the caller should unwind. Checked at every stage boundary.
    BOOL (^bail)(void) = ^BOOL{
        if (!self.cancelled) return NO;
        cleanup();
        return YES;
    };

    // ── 2. Extract IPA ────────────────────────────────────────────────────────
    [self _log:@"Extracting"];
    NSString *extractErr = extractZIP(_ipaPath, workDir, isCancelled);
    if (extractErr) {
        cleanup();
        if (outErr) *outErr = self.cancelled ? FPCancelled() : FPError(extractErr);
        return nil;
    }
    if (bail()) { if (outErr) *outErr = FPCancelled(); return nil; }

    // ── 3. Locate .app bundle ─────────────────────────────────────────────────
    NSString *payloadDir = [workDir stringByAppendingPathComponent:@"Payload"];
    NSString *appBundle = nil;
    for (NSString *item in [fm contentsOfDirectoryAtPath:payloadDir error:nil]) {
        if ([item hasSuffix:@".app"]) {
            appBundle = [payloadDir stringByAppendingPathComponent:item];
            break;
        }
    }
    if (!appBundle) {
        cleanup();
        if (outErr) *outErr = FPError(@"No .app found in Payload/");
        return nil;
    }
    [self _log:[NSString stringWithFormat:@"Found: %@", appBundle.lastPathComponent]];

    // ── 4. Main executable from Info.plist ────────────────────────────────────
    NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:
        [appBundle stringByAppendingPathComponent:@"Info.plist"]];
    NSString *execName = info[@"CFBundleExecutable"];
    if (!execName.length) {
        cleanup();
        if (outErr) *outErr = FPError(@"CFBundleExecutable missing from Info.plist");
        return nil;
    }
    // Prefer display name → bundle name → executable name
    self.appName = info[@"CFBundleDisplayName"] ?: info[@"CFBundleName"] ?: execName;
    NSString *appVersion = info[@"CFBundleShortVersionString"] ?: info[@"CFBundleVersion"];

    // ── 5. Decrypt main binary ────────────────────────────────────────────────
    NSString *mainBin = [appBundle stringByAppendingPathComponent:execName];
    [self _log:[NSString stringWithFormat:@"Decrypting %@", execName]];

    NSString *decErr = nil;
    if (![self _decryptBinary:mainBin inBundle:appBundle appBundle:appBundle
                  isCancelled:isCancelled displayName:self.appName error:&decErr]) {
        cleanup();
        if (outErr) *outErr = self.cancelled
            ? FPCancelled() : FPError(decErr ?: @"Main binary decryption failed");
        return nil;
    }

    // ── 6. Decrypt frameworks and app extensions ──────────────────────────────
    // Nested bundles carry their own LC_ENCRYPTION_INFO_64; their sinfs live in
    // the app bundle's SC_Info, which _decryptBinary falls back to.
    //
    // A nested failure fails the whole run. This used to log and carry on, which
    // shipped a half-decrypted IPA reported as "✓ Decrypted" — the frameworks
    // were still encrypted and nothing said so, which is worse than an error
    // because it looks finished.
    NSArray<NSString *> *nested = @[@"Frameworks", @"PlugIns"];

    for (NSString *sub in nested) {
        NSString *dir = [appBundle stringByAppendingPathComponent:sub];
        for (NSString *item in [fm contentsOfDirectoryAtPath:dir error:nil]) {
            if (!([item hasSuffix:@".framework"] || [item hasSuffix:@".appex"])) continue;

            NSString *bundlePath = [dir stringByAppendingPathComponent:item];
            NSString *bin = bundleExecutable(bundlePath);
            if (!bin) continue;

            NSString *label = [item stringByDeletingPathExtension];
            [self _log:[NSString stringWithFormat:@"Decrypting %@", item]];

            if (bail()) { if (outErr) *outErr = FPCancelled(); return nil; }

            // Ask first whether there is anything to do: _decryptBinary returns
            // NO both for "already decrypted / not encrypted" and for a real
            // failure, and an unencrypted framework must not fail the run.
            NSString *skipReason = nil;
            if (!binaryNeedsDecryption(bin, label, &skipReason)) {
                FPLogger(@"Dec", @"%@: nothing to do (%@)", item,
                         skipReason ?: @"not encrypted");
                continue;
            }

            NSString *nErr = nil;
            if (![self _decryptBinary:bin inBundle:bundlePath appBundle:appBundle
                          isCancelled:isCancelled displayName:label error:&nErr]) {
                FPLogger(@"Dec", @"%@ FAILED: %@", item, nErr ?: @"(none)");
                cleanup();
                if (outErr) *outErr = self.cancelled ? FPCancelled()
                    : FPError([NSString stringWithFormat:@"%@: %@", label,
                               nErr ?: @"decryption failed"]);
                return nil;
            }
        }
    }
    // ── 7. Repackage ──────────────────────────────────────────────────────────
    if (bail()) { if (outErr) *outErr = FPCancelled(); return nil; }
    [self _log:@"Packing"];

    for (NSString *dir in self.stagedSCInfo)
        [fm removeItemAtPath:dir error:nil];
    [self.stagedSCInfo removeAllObjects];

    // Purge previous results so /var/tmp does not grow by one IPA per run.
    NSString *outDir = @"/var/tmp/FoulPlay_out";
    [fm removeItemAtPath:outDir error:nil];
    [fm createDirectoryAtPath:outDir withIntermediateDirectories:YES
                   attributes:nil error:nil];

    // AppName_Version_decrypted.ipa. Separators would create directories.
    NSString *baseName = self.appName;
    if (appVersion.length)
        baseName = [NSString stringWithFormat:@"%@_%@", baseName, appVersion];
    baseName = [[baseName componentsSeparatedByCharactersInSet:
                    [NSCharacterSet characterSetWithCharactersInString:@"/\\:"]]
                    componentsJoinedByString:@"-"];

    NSString *outName = [baseName stringByAppendingString:@"_decrypted.ipa"];
    NSString *outPath = [outDir stringByAppendingPathComponent:outName];
    [fm removeItemAtPath:outPath error:nil];   // replace a previous run's file

    NSString *zipErr = createZIP(outPath, workDir, @"Payload", isCancelled);
    // createZIP stops mid-walk on cancel and returns no error, which would have
    // shipped a truncated IPA as "✓ Decrypted". Check before trusting a nil.
    if (bail()) {
        [fm removeItemAtPath:outPath error:nil];
        if (outErr) *outErr = FPCancelled();
        return nil;
    }
    if (zipErr) {
        [fm removeItemAtPath:outPath error:nil];
        cleanup();
        if (outErr) *outErr = self.cancelled ? FPCancelled() : FPError(zipErr);
        return nil;
    }

    cleanup();
    [self _log:@"Done!"];
    return outPath;
}

// ── Per-binary decryption ─────────────────────────────────────────────────────
//
// bundlePath is the bundle the binary lives in (used as CWD for the sinf
// lookup); appBundle is the top-level .app, whose SC_Info holds the sinfs for
// every nested bundle.
//
- (BOOL)_decryptBinary:(NSString *)binaryPath
              inBundle:(NSString *)bundlePath
             appBundle:(NSString *)appBundle
           isCancelled:(BOOL (^)(void))isCancelled
           displayName:(NSString *)displayName
                 error:(NSString **)outErr {
    NSFileManager *fm = [NSFileManager defaultManager];

    // Ask what this binary is BEFORE going looking for a sinf. The sinf only
    // matters if there is something to decrypt, and checking it first reported
    // "No sinf in SC_Info/" for binaries that were simply already decrypted.
    NSString *reason = nil;
    if (!binaryNeedsDecryption(binaryPath, displayName, &reason)) {
        if (outErr) *outErr = reason;
        return NO;
    }

    NSString *scInfoDir = [bundlePath stringByAppendingPathComponent:@"SC_Info"];
    NSString *sinfName  = [binaryPath.lastPathComponent
                            stringByAppendingPathExtension:@"sinf"];
    NSString *sinfPath  = [scInfoDir stringByAppendingPathComponent:sinfName];

    if (![fm fileExistsAtPath:sinfPath]) {
        // Nested bundles have no SC_Info of their own — the sinfs all live in
        // the app bundle. Take the matching one, else the app's own sinf.
        NSString *appSCInfo = [appBundle stringByAppendingPathComponent:@"SC_Info"];
        NSString *source = [appSCInfo stringByAppendingPathComponent:sinfName];

        if (![fm fileExistsAtPath:source]) {
            source = nil;
            for (NSString *item in [fm contentsOfDirectoryAtPath:appSCInfo error:nil]) {
                if ([item hasSuffix:@".sinf"]) {
                    source = [appSCInfo stringByAppendingPathComponent:item];
                    break;
                }
            }
        }
        if (!source) {
            if (outErr) *outErr = [NSString stringWithFormat:
                @"No sinf in SC_Info/ for %@", binaryPath.lastPathComponent];
            return NO;
        }

        // Stage it where the kernel expects to find it for this binary, and
        // remember it so the copy does not end up in the repacked IPA.
        if (![fm fileExistsAtPath:scInfoDir]) {
            [fm createDirectoryAtPath:scInfoDir withIntermediateDirectories:YES
                           attributes:nil error:nil];
            [self.stagedSCInfo addObject:scInfoDir];
        }
        if (![fm copyItemAtPath:source toPath:sinfPath error:nil]) {
            if (outErr) *outErr = [NSString stringWithFormat:
                @"Could not stage sinf for %@", binaryPath.lastPathComponent];
            return NO;
        }
    }

    FPLogger(@"Dec", @"sinf for %@: %@ (%llu bytes)", binaryPath.lastPathComponent,
              sinfPath.lastPathComponent,
              (unsigned long long)[[fm attributesOfItemAtPath:sinfPath error:nil] fileSize]);

    NSString *decErr = nil;
    BOOL ok = decryptBinaryAtPath(binaryPath, bundlePath, isCancelled, &decErr);
    FPLogger(@"Dec", @"decryptBinaryAtPath(%@) ok=%d err=%@",
              binaryPath.lastPathComponent, ok, decErr ?: @"(none)");

    if (!ok && outErr) *outErr = decErr ?: @"mremap_encrypted failed";
    return ok;
}

@end
