#import "LogHelper.h"

#ifdef DEBUG

NSString *FPLogPath(void) {
    // Use /var/tmp — reliable for a no-sandbox jailbreak deb.
    // NSDocumentDirectory is unreliable in this context.
    return @"/var/tmp/foulplay.log";
}

void FPFileLog(NSString *tag, NSString *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    NSString *msg = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    NSLog(@"[FoulPlay][%@] %@", tag, msg);
    NSString *line = [NSString stringWithFormat:@"%@  [%@] %@\n",
                      [NSDate date], tag, msg];
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
}

#endif
