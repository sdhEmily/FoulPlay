#import "LogHelper.h"

NS_ASSUME_NONNULL_BEGIN

NSString *_Nullable FPLogPath(void) {
#ifdef DEBUG
    // /var/tmp, not the app container: an iPad running iOS 15.0 refused
    // container writes with EPERM while /var/tmp worked on every device.
    return @"/var/tmp/foulplay.log";
#else
    return nil;
#endif
}

void FPLogger(NSString *tag, NSString *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    NSString *msg = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);

    // NSLog rather than os_log: it needs no %{public} annotation to avoid
    // redaction, and it is what this file used before.
    //
    // Caveat, measured on iPhone 7 / 15.8.5: neither NSLog nor os_log from this
    // app appears in idevicesyslog. The same process's framework messages
    // (CoreFoundation, UIKitCore, ...) relay fine, so the app's own lines are
    // being dropped somewhere in the lockdown relay rather than never emitted.
    // Whether Console.app shows them is untested — do not assume a release
    // build is diagnosable from the system log alone until that is confirmed.
    NSLog(@"[FoulPlay][%@] %@", tag, msg);

#ifdef DEBUG
    // Decryption runs on a background queue while the UI logs from main, so the
    // append is serialised — two threads seeking to end and writing through
    // separate handles can interleave halfway through a line.
    static dispatch_queue_t fileQueue;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        fileQueue = dispatch_queue_create("gay.sdh.foulplay.log", DISPATCH_QUEUE_SERIAL);
    });
    NSString *line = [NSString stringWithFormat:@"%@  [%@] %@\n",
                      [NSDate date], tag, msg];
    // Sync, not async: this log exists to be read after a crash, and anything
    // still queued when the process dies is lost. At a few lines per run the
    // block is not worth optimising away.
    dispatch_sync(fileQueue, ^{
        NSString *logPath = FPLogPath();
        NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:logPath];
        if (!fh) {
            [@"" writeToFile:logPath atomically:NO encoding:NSUTF8StringEncoding error:nil];
            fh = [NSFileHandle fileHandleForWritingAtPath:logPath];
        }
        if (fh) {
            [fh seekToEndOfFile];
            [fh writeData:[line dataUsingEncoding:NSUTF8StringEncoding]];
            [fh closeFile];
        }
    });
#endif
}

NS_ASSUME_NONNULL_END
