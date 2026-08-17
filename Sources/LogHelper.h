#pragma once
#import <Foundation/Foundation.h>

#ifdef DEBUG
void FPFileLog(NSString *tag, NSString *fmt, ...) NS_FORMAT_FUNCTION(2,3);
NSString *FPLogPath(void);
#else
// In release builds all logging compiles away to nothing.
static inline void FPFileLog(NSString *tag, NSString *fmt, ...) {}
static inline NSString *FPLogPath(void) { return @"/dev/null"; }
#endif
