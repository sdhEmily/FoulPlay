#pragma once
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

// Always compiled in. Every build writes to the unified system log, so
// diagnostics can be captured from a release build with Console.app or
// idevicesyslog without shipping a debug package. The on-disk log is DEBUG-only
// — FPLogPath() returns nil in release builds.
void FPLogger(NSString *tag, NSString *fmt, ...) NS_FORMAT_FUNCTION(2,3);
NSString *_Nullable FPLogPath(void);

NS_ASSUME_NONNULL_END
