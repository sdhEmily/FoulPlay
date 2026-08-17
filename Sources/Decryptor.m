#import "Decryptor.h"
#import "InProcessDecrypt.h"
#import "LogHelper.h"

#include <spawn.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

// ── Helpers ───────────────────────────────────────────────────────────────────

static NSError *FPError(NSString *msg) {
    return [NSError errorWithDomain:@"gay.sdh.foulplay"
                               code:-1
                           userInfo:@{NSLocalizedDescriptionKey: msg}];
}

// Search for a tool by name; uses fileExistsAtPath (not isExecutableFileAtPath)
// since the latter can return NO across sandbox boundaries.
static NSString *findTool(NSString *name) {
    NSArray *dirs = @[@"/var/jb/usr/bin", @"/usr/bin", @"/bin",
                      @"/var/jb/bin", @"/usr/local/bin", @"/var/jb/usr/local/bin"];
    for (NSString *dir in dirs) {
        NSString *p = [dir stringByAppendingPathComponent:name];
        if ([[NSFileManager defaultManager] fileExistsAtPath:p]) {
            FPFileLog(@"tool", @"found %@ at %@", name, p);
            return p;
        }
    }
    FPFileLog(@"tool", @"%@ not found in any search dir", name);
    return nil;
}

// Run a tool, capture its stdout+stderr, and return the trimmed output.
// Returns nil on success (exit 0), the captured text on failure.
static NSString *runToolCaptured(NSString *tool, NSArray<NSString *> *args) {
    if (!tool) return @"tool not found";

    NSMutableArray *all = [@[tool] mutableCopy];
    [all addObjectsFromArray:args];
    FPFileLog(@"tool", @"spawn(capture): %@", [all componentsJoinedByString:@" "]);

    int pfd[2];
    pipe(pfd);

    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_adddup2(&fa, pfd[1], STDOUT_FILENO);
    posix_spawn_file_actions_adddup2(&fa, pfd[1], STDERR_FILENO);
    posix_spawn_file_actions_addclose(&fa, pfd[0]);
    posix_spawn_file_actions_addclose(&fa, pfd[1]);

    const char **argv = calloc(all.count + 1, sizeof(char *));
    for (NSUInteger i = 0; i < all.count; i++) argv[i] = [all[i] UTF8String];
    argv[all.count] = NULL;

    pid_t pid;
    int spawnErr = posix_spawn(&pid, tool.UTF8String, &fa, NULL,
                               (char *const *)argv, environ);
    posix_spawn_file_actions_destroy(&fa);
    free(argv);
    close(pfd[1]);

    if (spawnErr != 0) {
        close(pfd[0]);
        return [NSString stringWithFormat:@"spawn failed: %s", strerror(spawnErr)];
    }

    NSMutableData *buf = [NSMutableData data];
    char chunk[4096];
    ssize_t n;
    while ((n = read(pfd[0], chunk, sizeof(chunk))) > 0)
        [buf appendBytes:chunk length:(NSUInteger)n];
    close(pfd[0]);

    int status = 0;
    waitpid(pid, &status, 0);
    int exitCode = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    FPFileLog(@"tool", @"%@ exited %d", tool.lastPathComponent, exitCode);

    if (exitCode == 0) return nil; // success

    NSString *out = [[NSString alloc] initWithData:buf encoding:NSUTF8StringEncoding];
    out = [out stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    return (out.length ? out : [NSString stringWithFormat:@"exited %d", exitCode]);
}

static BOOL runTool(NSString *tool, NSArray<NSString *> *args) {
    if (!tool) { FPFileLog(@"tool", @"runTool: nil path"); return NO; }

    NSMutableArray *all = [@[tool] mutableCopy];
    [all addObjectsFromArray:args];
    FPFileLog(@"tool", @"spawn: %@", [all componentsJoinedByString:@" "]);

    const char **argv = calloc(all.count + 1, sizeof(char *));
    for (NSUInteger i = 0; i < all.count; i++) argv[i] = [all[i] UTF8String];
    argv[all.count] = NULL;

    pid_t pid;
    int spawnErr = posix_spawn(&pid, tool.UTF8String, NULL, NULL,
                               (char *const *)argv, environ);
    free(argv);
    if (spawnErr != 0) {
        FPFileLog(@"tool", @"posix_spawn(%@): errno=%d (%s)",
                   tool.lastPathComponent, spawnErr, strerror(spawnErr));
        return NO;
    }

    int status = 0;
    waitpid(pid, &status, 0);
    int exitCode = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    FPFileLog(@"tool", @"%@ exited %d", tool.lastPathComponent, exitCode);
    return exitCode == 0;
}

// ── Decryptor ─────────────────────────────────────────────────────────────────

@interface Decryptor ()
@property (nonatomic, copy) NSString          *ipaPath;
@property (nonatomic, copy) FoulPlayProgress  progressHandler;
@property (nonatomic, copy, readwrite) NSString *appName;
@end

@implementation Decryptor

- (instancetype)initWithIPAPath:(NSString *)ipaPath {
    self = [super init];
    _ipaPath = ipaPath;
    return self;
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
    FPFileLog(@"Dec", @"%@", msg);
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
    // Spawned tools (unzip, zip) must be able to see these paths, so we avoid
    // the app-sandbox container and use /var/tmp/ (world-accessible).
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

    void (^cleanup)(void) = ^{
        [[NSFileManager defaultManager] removeItemAtPath:workDir error:nil];
    };

    // ── 2. Extract IPA ────────────────────────────────────────────────────────
    [self _log:@"Extracting IPA"];
    NSString *unzip = findTool(@"unzip");
    NSString *unzipErr = runToolCaptured(unzip, @[_ipaPath, @"-d", workDir]);
    if (unzipErr) {
        cleanup();
        if (outErr) *outErr = FPError(unzipErr);
        return nil;
    }

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
    if (!execName) {
        cleanup();
        if (outErr) *outErr = FPError(@"CFBundleExecutable missing from Info.plist");
        return nil;
    }
    // Prefer display name → bundle name → executable name
    self.appName = info[@"CFBundleDisplayName"] ?: info[@"CFBundleName"] ?: execName;

    // ── 5. Decrypt main binary ────────────────────────────────────────────────
    // We pass the bundle directory so decryptBinaryAtPath can set CWD there,
    // making SC_Info/<binary>.sinf visible to the FairPlay kernel extension.
    NSString *mainBin = [appBundle stringByAppendingPathComponent:execName];
    [self _log:[NSString stringWithFormat:@"Decrypting %@", execName]];

    NSString *decErr = nil;
    if (![self _decryptBinary:mainBin inBundle:appBundle error:&decErr]) {
        cleanup();
        if (outErr) *outErr = FPError(decErr ?: @"Main binary decryption failed");
        return nil;
    }

    // ── 6. Decrypt frameworks (best-effort) ───────────────────────────────────
    NSString *fwDir = [appBundle stringByAppendingPathComponent:@"Frameworks"];
    NSInteger fwIdx = 0;
    for (NSString *fw in [fm contentsOfDirectoryAtPath:fwDir error:nil]) {
        if (![fw hasSuffix:@".framework"]) continue;
        fwIdx++;
        NSString *fwPath = [fwDir stringByAppendingPathComponent:fw];
        NSString *fwBin  = [fwPath stringByAppendingPathComponent:
                            [fw stringByDeletingPathExtension]];
        if (![fm fileExistsAtPath:fwBin]) continue;

        [self _log:[NSString stringWithFormat:@"Decrypting framework %ld: %@",
                    (long)fwIdx, [fw stringByDeletingPathExtension]]];
        NSString *fwErr = nil;
        if (![self _decryptBinary:fwBin inBundle:fwPath error:&fwErr]) {
            NSLog(@"[FoulPlay] framework %@ skipped: %@", fw, fwErr ?: @"(none)");
        }
    }

    // ── 7. Repackage ──────────────────────────────────────────────────────────
    [self _log:@"Packing"];

    NSString *outDir = @"/var/tmp/FoulPlay_out";
    [fm createDirectoryAtPath:outDir withIntermediateDirectories:YES
                   attributes:nil error:nil];

    NSString *baseName = [_ipaPath.lastPathComponent stringByDeletingPathExtension];
    NSString *outName  = [baseName stringByAppendingString:@"_decrypted.ipa"];
    NSString *outPath  = [outDir stringByAppendingPathComponent:outName];
    [fm removeItemAtPath:outPath error:nil];

    char prevCWD[PATH_MAX];
    getcwd(prevCWD, sizeof(prevCWD));
    chdir(workDir.UTF8String);

    NSString *zip    = findTool(@"zip");
    BOOL      zipped = runTool(zip, @[@"-r", @"-q", outPath, @"Payload"]);
    chdir(prevCWD);

    if (!zipped) {
        cleanup();
        if (outErr) *outErr = FPError(@"zip failed — is it installed?");
        return nil;
    }

    cleanup();
    [self _log:@"Done!"];
    return outPath;
}

// ── Per-binary decryption ─────────────────────────────────────────────────────
//
// Passes the binary directly to decryptBinaryAtPath (which lives in /var/tmp/).
// decryptBinaryAtPath acquires root+CS_PLATFORM_BINARY, calls mremap_encrypted,
// and drops root — no staging to /var/containers/Bundle/Application/ needed.
//
- (BOOL)_decryptBinary:(NSString *)binaryPath
              inBundle:(NSString *)bundlePath
                 error:(NSString **)outErr {
    NSFileManager *fm = [NSFileManager defaultManager];

    // Verify the sinf exists (required by FairPlay for key lookup)
    NSString *scInfoDir = [bundlePath stringByAppendingPathComponent:@"SC_Info"];
    NSString *sinfName  = [binaryPath.lastPathComponent
                            stringByAppendingPathExtension:@"sinf"];
    NSString *sinfPath  = [scInfoDir stringByAppendingPathComponent:sinfName];

    if (![fm fileExistsAtPath:sinfPath]) {
        // Try any .sinf in SC_Info
        NSString *found = nil;
        for (NSString *item in [fm contentsOfDirectoryAtPath:scInfoDir error:nil]) {
            if ([item hasSuffix:@".sinf"]) {
                found = [scInfoDir stringByAppendingPathComponent:item];
                break;
            }
        }
        if (!found) {
            if (outErr) *outErr = [NSString stringWithFormat:
                @"No sinf in SC_Info/ for %@", binaryPath.lastPathComponent];
            return NO;
        }
        // Copy under the expected name so the kernel can locate it
        [fm copyItemAtPath:found toPath:sinfPath error:nil];
    }

    // Decrypt in-place. decryptBinaryAtPath sets CWD to bundlePath so
    // SC_Info/<name>.sinf is found relative to the binary's directory.
    NSString *decErr = nil;
    BOOL ok = decryptBinaryAtPath(binaryPath, bundlePath, &decErr);
    NSLog(@"[FoulPlay] decryptBinaryAtPath ok=%d err=%@", ok, decErr ?: @"(none)");

    if (!ok && outErr) *outErr = decErr ?: @"mremap_encrypted failed";
    return ok;
}

@end
