#import <UIKit/UIKit.h>

@interface ViewController : UIViewController

/// Copy and decrypt the IPA at @p url. Called by the document picker and by
/// AppDelegate when another app opens an IPA in FoulPlay.
- (void)handleIncomingIPA:(NSURL *)url;

@end
