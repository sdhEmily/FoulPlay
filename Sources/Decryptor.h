#import <Foundation/Foundation.h>

extern NSString *const FoulPlayErrorDomain;

typedef NS_ENUM(NSInteger, FoulPlayErrorCode) {
    FoulPlayErrorFailed    = -1,
    FoulPlayErrorCancelled = -2,
};

typedef void (^FoulPlayProgress)(NSString *message);
typedef void (^FoulPlayCompletion)(NSString *outputPath, NSError *error);

@interface Decryptor : NSObject
@property (nonatomic, copy, readonly) NSString *appName;
- (instancetype)initWithIPAPath:(NSString *)ipaPath;
- (void)decryptWithProgress:(FoulPlayProgress)progress
                 completion:(FoulPlayCompletion)completion;
/// Ask the run to stop. Cancellation is cooperative: the work unwinds at the
/// next checkpoint, so completion still fires, with FoulPlayErrorCancelled.
- (void)cancel;
@end
