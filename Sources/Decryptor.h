#import <Foundation/Foundation.h>

typedef void (^FoulPlayProgress)(NSString *message);
typedef void (^FoulPlayCompletion)(NSString *outputPath, NSError *error);

@interface Decryptor : NSObject
@property (nonatomic, copy, readonly) NSString *appName;
- (instancetype)initWithIPAPath:(NSString *)ipaPath;
- (void)decryptWithProgress:(FoulPlayProgress)progress
                 completion:(FoulPlayCompletion)completion;
@end
