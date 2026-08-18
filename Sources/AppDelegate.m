#import "AppDelegate.h"
#import "ViewController.h"

@interface AppDelegate ()
@property (nonatomic, strong) ViewController *root;
@end

@implementation AppDelegate

- (BOOL)application:(UIApplication *)application
    didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    self.window = [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
    self.root = [[ViewController alloc] init];
    self.window.rootViewController =
        [[UINavigationController alloc] initWithRootViewController:self.root];
    [self.window makeKeyAndVisible];
    return YES;
}

// Handles "Open in FoulPlay" from Files, AirDrop, and other apps — the
// CFBundleDocumentTypes entry in Info.plist is what offers us as a target.
- (BOOL)application:(UIApplication *)app
            openURL:(NSURL *)url
            options:(NSDictionary<UIApplicationOpenURLOptionsKey, id> *)options {
    if (!url.isFileURL) return NO;
    [self.root handleIncomingIPA:url];
    return YES;
}

@end
