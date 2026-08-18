#import "ViewController.h"
#import "Decryptor.h"
#import "LogHelper.h"
#import <UniformTypeIdentifiers/UniformTypeIdentifiers.h>

#include <unistd.h>
#include <spawn.h>
#include <string.h>
#include <signal.h>
#include <sys/wait.h>

extern char **environ;

@interface ViewController () <UIDocumentPickerDelegate>
@property (nonatomic, strong) UIButton         *openButton;
@property (nonatomic, strong) UILabel          *statusLabel;
@property (nonatomic, strong) UIActivityIndicatorView *spinner;
@property (nonatomic, strong) UIButton         *shareButton;
@property (nonatomic, copy)   NSString         *outputPath;
/// Our /var/tmp copy of the picked IPA, deleted once decryption finishes.
/// Only set when we actually had to copy — see handleIncomingIPA:.
@property (nonatomic, copy)   NSString         *scratchIPAPath;
/// A file AirDropped into our own Documents/Inbox, used in place and removed
/// after a successful run so Inbox does not grow forever.
@property (nonatomic, copy)   NSString         *inboxSourcePath;
/// pid of the spawned cp, so a cancel can actually interrupt a long copy.
@property (atomic, assign)    pid_t             copyPID;
@property (nonatomic, strong) Decryptor        *decryptor;
@property (nonatomic, assign) BOOL              busy;
/// Set when Cancel is tapped, so the copy stage can unwind too — it runs
/// before there is a Decryptor to hand the request to.
@property (nonatomic, assign) BOOL              cancelRequested;
@property (nonatomic, assign) UIBackgroundTaskIdentifier bgTask;
@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    FPLogger(@"VC", @"viewDidLoad — log path: %@", FPLogPath() ?: @"(system log only)");
    _bgTask = UIBackgroundTaskInvalid;
    self.title = @"FoulPlay";
    self.view.backgroundColor = [UIColor systemBackgroundColor];

    // ── Controls ─────────────────────────────────────────────────────────────
    _openButton = [UIButton buttonWithType:UIButtonTypeSystem];
    [_openButton setTitle:@"Open IPA" forState:UIControlStateNormal];
    _openButton.titleLabel.font =
        [UIFont systemFontOfSize:22 weight:UIFontWeightSemibold];
    [_openButton addTarget:self action:@selector(openOrCancel)
          forControlEvents:UIControlEventTouchUpInside];
    // Set explicitly to match the share button — UIKit's default dimming for a
    // disabled system button is a different grey from tertiaryLabel.
    [_openButton setTitleColor:[UIColor tertiaryLabelColor]
                      forState:UIControlStateDisabled];

    _spinner = [[UIActivityIndicatorView alloc]
                initWithActivityIndicatorStyle:UIActivityIndicatorViewStyleMedium];
    // Medium is 20pt, the smallest style iOS offers — scale it down to sit at
    // the status text's 13pt line rather than towering over it.
    _spinner.transform = CGAffineTransformMakeScale(0.7, 0.7);
    // Collapsing is wanted here: it only affects the status row's horizontal
    // layout, so the text re-centres on its own when the spinner goes away.
    _spinner.hidesWhenStopped = YES;
    [_spinner setContentHuggingPriority:UILayoutPriorityRequired
                                forAxis:UILayoutConstraintAxisHorizontal];

    _shareButton = [UIButton buttonWithType:UIButtonTypeSystem];
    [_shareButton setTitle:@"Share Decrypted IPA" forState:UIControlStateNormal];
    _shareButton.titleLabel.font =
        [UIFont systemFontOfSize:17 weight:UIFontWeightMedium];
    [_shareButton addTarget:self action:@selector(shareResult)
           forControlEvents:UIControlEventTouchUpInside];
    // Always laid out — greyed out until there is something to share, so the
    // stack keeps the same height throughout.
    [_shareButton setTitleColor:[UIColor tertiaryLabelColor]
                       forState:UIControlStateDisabled];
    _shareButton.enabled = NO;
    
    _statusLabel = [[UILabel alloc] init];
    _statusLabel.textAlignment = NSTextAlignmentCenter;
    _statusLabel.numberOfLines = 0;
    _statusLabel.font = [UIFont monospacedSystemFontOfSize:13
                                                    weight:UIFontWeightRegular];
    _statusLabel.textColor = [UIColor secondaryLabelColor];
    _statusLabel.text = @"Select an IPA to decrypt";
    // Failures print several lines of diagnostics — let them be copied out.
    _statusLabel.userInteractionEnabled = YES;
    [_statusLabel addGestureRecognizer:
        [[UILongPressGestureRecognizer alloc] initWithTarget:self
                                                      action:@selector(copyStatus:)]];

    // ── Layout ───────────────────────────────────────────────────────────────
    // Spinner sits immediately left of the text. The row is sized to its
    // contents rather than stretched, so the spinner stays next to the text
    // instead of being stranded at the edge, and the pair centres as a unit.
    UIStackView *statusRow = [[UIStackView alloc] initWithArrangedSubviews:
        @[_spinner, _statusLabel]];
    statusRow.axis      = UILayoutConstraintAxisHorizontal;
    statusRow.alignment = UIStackViewAlignmentCenter;
    statusRow.spacing   = 8;
    statusRow.translatesAutoresizingMaskIntoConstraints = NO;

    // Full-width wrapper so the outer stack still has something to fill; the
    // row floats centred inside it and may narrow so long text can wrap.
    UIView *statusWrap = [[UIView alloc] init];
    [statusWrap addSubview:statusRow];
    [NSLayoutConstraint activateConstraints:@[
        [statusRow.centerXAnchor constraintEqualToAnchor:statusWrap.centerXAnchor],
        [statusRow.topAnchor     constraintEqualToAnchor:statusWrap.topAnchor],
        [statusRow.bottomAnchor  constraintEqualToAnchor:statusWrap.bottomAnchor],
        [statusRow.leadingAnchor
            constraintGreaterThanOrEqualToAnchor:statusWrap.leadingAnchor],
        [statusRow.trailingAnchor
            constraintLessThanOrEqualToAnchor:statusWrap.trailingAnchor],
    ]];

    // Everything is centred directly in the safe area. The stack is ~165pt
    // tall against ~343pt of landscape safe area on the smallest supported
    // device, so it fits without a scroll view.
    UIStackView *stack = [[UIStackView alloc] initWithArrangedSubviews:
        @[_openButton, _shareButton, statusWrap]];
    stack.axis         = UILayoutConstraintAxisVertical;
    // Fill, not Center — the status label needs a definite width to wrap.
    stack.alignment    = UIStackViewAlignmentFill;
    stack.spacing      = 15;
    stack.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:stack];

    UILabel *version = [[UILabel alloc] init];
    version.translatesAutoresizingMaskIntoConstraints = NO;
    version.textAlignment = NSTextAlignmentCenter;
    version.font = [UIFont systemFontOfSize:11 weight:UIFontWeightLight];
    version.textColor = [UIColor tertiaryLabelColor];

    NSDictionary *bundleInfo = [NSBundle mainBundle].infoDictionary;
    NSString *shortVersion = bundleInfo[@"CFBundleShortVersionString"] ?: @"?";
#ifdef DEBUG
    version.text = [NSString stringWithFormat:@"v%@ (%@)", shortVersion,
                    bundleInfo[@"CFBundleVersion"] ?: @"?"];
#else
    version.text = [NSString stringWithFormat:@"v%@", shortVersion];
#endif
    [self.view addSubview:version];

    UILayoutGuide *safe = self.view.safeAreaLayoutGuide;

    // Side margins on iPhone, capped so the buttons don't stretch across an iPad.
    NSLayoutConstraint *width =
        [stack.widthAnchor constraintEqualToAnchor:safe.widthAnchor constant:-56];
    width.priority = UILayoutPriorityDefaultHigh;

    // Vertically centred, but yields if it would ever collide with the version
    // label or the top of the safe area.
    NSLayoutConstraint *centre =
        [stack.centerYAnchor constraintEqualToAnchor:safe.centerYAnchor];
    centre.priority = UILayoutPriorityDefaultHigh;

    [NSLayoutConstraint activateConstraints:@[
        [stack.centerXAnchor constraintEqualToAnchor:safe.centerXAnchor],
        [stack.widthAnchor   constraintLessThanOrEqualToConstant:420],
        [stack.topAnchor
            constraintGreaterThanOrEqualToAnchor:safe.topAnchor constant:24],
        [stack.bottomAnchor
            constraintLessThanOrEqualToAnchor:version.topAnchor constant:-16],
        width,
        centre,

        // Reserve two lines so one-line statuses and wrapped errors don't
        // resize the stack and nudge the buttons around.
        [_statusLabel.heightAnchor constraintGreaterThanOrEqualToConstant:34],

        [version.centerXAnchor constraintEqualToAnchor:safe.centerXAnchor],
        [version.bottomAnchor  constraintEqualToAnchor:safe.bottomAnchor constant:-8],
    ]];
}

// ── Actions ───────────────────────────────────────────────────────────────────

- (void)openIPA {
    // The app's Info.plist declares com.apple.itunes.ipa and maps both .ipa and
    // .tipa onto it, so the picker can filter on that type and grey out
    // everything else. (This used to pass public.data because .ipa had no
    // registered type on iOS — that stopped being true once we shipped the
    // UTImportedTypeDeclarations entry.)
    //
    // Extensions are looked up as well as the identifier: if LaunchServices ever
    // resolves .ipa to something other than our declaration, that lookup still
    // returns the type it actually uses, so the file stays selectable.
    NSMutableArray<UTType *> *types = [NSMutableArray array];
    UTType *ipa = [UTType typeWithIdentifier:@"com.apple.itunes.ipa"];
    if (ipa) [types addObject:ipa];
    for (NSString *ext in @[@"ipa", @"tipa"]) {
        UTType *t = [UTType typeWithFilenameExtension:ext];
        if (t && ![types containsObject:t]) [types addObject:t];
    }
    // Never present a picker that can select nothing: if none of those resolved,
    // fall back to the old accept-everything behaviour. UTTypeData is the
    // compile-time constant rather than a lookup — a nil from typeWithIdentifier:
    // here would throw on insert, which is the one thing this line exists to avoid.
    if (types.count == 0) [types addObject:UTTypeData];
    FPLogger(@"UI", @"picker types: %@", [types valueForKey:@"identifier"]);

    UIDocumentPickerViewController *picker =
        [[UIDocumentPickerViewController alloc]
         initForOpeningContentTypes:types];
    picker.delegate = self;
    picker.allowsMultipleSelection = NO;
    [self presentViewController:picker animated:YES completion:nil];
}

- (void)documentPicker:(UIDocumentPickerViewController *)controller
didPickDocumentsAtURLs:(NSArray<NSURL *> *)urls {
    if (urls.firstObject) [self handleIncomingIPA:urls.firstObject];
}

- (void)openOrCancel {
    if (_busy) [self cancelRun]; else [self openIPA];
}

- (void)cancelRun {
    _cancelRequested = YES;
    [_decryptor cancel];
    // During the copy stage there is no Decryptor yet and waitpid blocks until
    // cp exits, so without this a cancel did nothing until the copy finished.
    pid_t copying = self.copyPID;
    if (copying > 0) {
        FPLogger(@"VC", @"cancel: terminating cp (pid %d)", copying);
        kill(copying, SIGTERM);
    }
    // Cancellation is cooperative, so the run keeps going until the next
    // checkpoint. Disable until it lands so this can't be tapped twice.
    _openButton.enabled = NO;
    [self setStatus:@"Cancelling" color:[UIColor secondaryLabelColor]];
}

- (void)handleIncomingIPA:(NSURL *)url {
    if (!url.isFileURL) return;

    // openURL can fire at any time — including mid-run — so a second decryption
    // is genuinely reachable from AirDrop / "Open in". Two at once would race on
    // the process-global chdir that decryptBinaryAtPath uses to locate the sinf,
    // so ignore anything that turns up while a run is in progress.
    if (_busy) {
        FPLogger(@"VC", @"busy — ignoring %@", url.lastPathComponent);
        return;
    }

    [self resetForNewRun];
    _cancelRequested = NO;
    [self setBusy:YES];
    [self beginBackgroundAssertion];

    NSString *srcPath = url.path;

    // The spawned cp below exists only because iCloud Drive blocks in-process
    // reads. A file already inside our container — an AirDrop lands in
    // Documents/Inbox — is readable directly, and Decryptor only ever reads the
    // IPA, so copying it first is a full-size copy for nothing. Deciding by
    // location rather than by trying an open also avoids holding a
    // security-scoped resource open across the whole decrypt.
    if ([srcPath hasPrefix:NSHomeDirectory()]) {
        FPLogger(@"VC", @"in-container source — decrypting in place");
        self.inboxSourcePath = srcPath;
        [self startDecryptionAt:srcPath];
        return;
    }

    [self setStatus:@"Copying" color:[UIColor secondaryLabelColor]];
    NSString *dst = [@"/var/tmp"
        stringByAppendingPathComponent:url.lastPathComponent];
    self.scratchIPAPath = dst;

    BOOL scoped = [url startAccessingSecurityScopedResource];

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSString *errorMsg = [self copyFrom:srcPath to:dst];
        if (scoped) [url stopAccessingSecurityScopedResource];

        dispatch_async(dispatch_get_main_queue(), ^{
            if (self.cancelRequested) {
                [self discardScratchIPA];
                [self showError:@"Cancelled"];
                [self finishRun];
            } else if (errorMsg) {
                // discard, not nil: a failed cp still leaves a partial file, and
                // just forgetting the path orphans it in /var/tmp forever.
                [self discardScratchIPA];
                [self showError:errorMsg];
                [self finishRun];
            } else {
                [self startDecryptionAt:dst];
            }
        });
    });
}

// In-process reads of Mobile Documents are blocked by a MAC policy on app
// processes. Spawning cp sidesteps it — the child binary runs under its own
// code signature, without the app-specific restriction.
- (NSString *)copyFrom:(NSString *)srcPath to:(NSString *)dst {
    [[NSFileManager defaultManager] removeItemAtPath:dst error:nil];

    static const char *cpPaths[] = {
        "/var/jb/usr/bin/cp", "/usr/bin/cp", "/bin/cp", NULL
    };
    const char *cpBin = NULL;
    for (int i = 0; cpPaths[i]; i++) {
        if (access(cpPaths[i], X_OK) == 0) { cpBin = cpPaths[i]; break; }
    }
    if (!cpBin) return @"cp not found";

    const char *argv[] = { cpBin, srcPath.UTF8String, dst.UTF8String, NULL };
    pid_t pid = 0;
    int spawnErr = posix_spawn(&pid, cpBin, NULL, NULL,
                               (char *const *)argv, environ);
    if (spawnErr != 0) {
        NSString *msg = [NSString stringWithFormat:@"spawn cp: %s",
                         strerror(spawnErr)];
        FPLogger(@"VC", @"%@", msg);
        return msg;
    }

    self.copyPID = pid;
    int status = 0;
    waitpid(pid, &status, 0);
    self.copyPID = 0;          // cleared promptly so cancel can't hit a reused pid
    int exitCode = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    FPLogger(@"VC", @"cp exited %d", exitCode);

    if (exitCode != 0)
        return [NSString stringWithFormat:@"cp failed (exit %d)", exitCode];
    if (![[NSFileManager defaultManager] fileExistsAtPath:dst])
        return @"cp exited 0 but file not found at /var/tmp";

    FPLogger(@"VC", @"copied → %@", dst);
    return nil;
}

- (void)startDecryptionAt:(NSString *)ipaPath {
    [self setStatus:@"Decrypting" color:[UIColor secondaryLabelColor]];
    [self setBusy:YES];

    _decryptor = [[Decryptor alloc] initWithIPAPath:ipaPath];
    __weak typeof(self) weak = self;

    [_decryptor decryptWithProgress:^(NSString *msg) {
        [weak setStatus:msg color:[UIColor secondaryLabelColor]];
    } completion:^(NSString *output, NSError *err) {
        typeof(self) strong = weak;
        if (!strong) return;

        [strong discardScratchIPA];

        if (err) {
            [strong showError:(err.code == FoulPlayErrorCancelled
                               ? @"Cancelled" : err.localizedDescription)];
        } else {
            strong.outputPath = output;
            NSString *name = strong.decryptor.appName ?: output.lastPathComponent;
            [strong setStatus:[NSString stringWithFormat:@"✓ Decrypted %@", name]
                        color:[UIColor systemGreenColor]];
            strong.shareButton.enabled = YES;
            [strong consumeInboxSource];
        }
        [strong finishRun];
    }];
}

- (void)shareResult {
    if (!_outputPath) return;

    // A real share sheet (AirDrop, Messages, Save to Files, ...). It scales app
    // icons in-process through CoreImage, which needs the GPU user-clients
    // allowlisted in entitlements.plist — without those the sandbox denies
    // AGXDeviceUserClient / IOSurfaceRootUserClient and this segfaults.
    NSURL *url = [NSURL fileURLWithPath:_outputPath];
    UIActivityViewController *avc =
        [[UIActivityViewController alloc] initWithActivityItems:@[url]
                                          applicationActivities:nil];

    // Required on iPad — presenting without an anchor throws.
    avc.popoverPresentationController.sourceView = _shareButton;
    avc.popoverPresentationController.sourceRect = _shareButton.bounds;

    [self presentViewController:avc animated:YES completion:nil];
}

// ── State ─────────────────────────────────────────────────────────────────────

static const NSTimeInterval kButtonFade = 0.5;

// UIKit's own cross-dissolve. This works here only because setBusy: sets
// enabled *before* calling it — a control-state change lands mid-animation
// otherwise and UIButton drops the transition, which is what made an earlier
// attempt hard-cut to nothing. UIKit owns the snapshot, so it also tracks the
// button if the stack re-lays out underneath it.
- (void)setOpenButtonTitle:(NSString *)title {
    [UIView transitionWithView:_openButton
                      duration:kButtonFade
                       options:UIViewAnimationOptionTransitionCrossDissolve |
                               UIViewAnimationOptionAllowUserInteraction
                    animations:^{
        [self->_openButton setTitle:title forState:UIControlStateNormal];
    }
                    completion:nil];
}

- (void)setBusy:(BOOL)busy {
    // startDecryptionAt: re-asserts YES after handleIncomingIPA: already did,
    // so without this the title cross-fades a second time from "Cancel" to
    // "Cancel" — an identical-text dissolve landing on top of the first one.
    // That is why entering a run looked worse than leaving one.
    if (_busy == busy) return;
    _busy = busy;
    // hidesWhenStopped collapses the spinner out of the status row for us.
    if (busy) [_spinner startAnimating]; else [_spinner stopAnimating];
    // Doubles as the cancel button while working, so it stays enabled — only
    // cancelRun disables it, until the run actually unwinds.
    // Set enabled first: doing it after would change control state mid-flight
    // and cancel the animation.
    _openButton.enabled = YES;
    [self setOpenButtonTitle:(busy ? @"Cancel" : @"Open IPA")];
}

/// Single exit point for a run, so busy and the background assertion can't
/// drift apart across the success and failure paths.
- (void)finishRun {
    [self setBusy:NO];
    [self endBackgroundAssertion];
}

// Decrypting a large IPA outlasts the few seconds iOS gives a backgrounded app,
// and being suspended mid-run leaves the spinner up with no completion ever
// firing. This buys the extra time; it is not unlimited, so a very large IPA
// can still be cut short if the app stays in the background.
- (void)beginBackgroundAssertion {
    if (_bgTask != UIBackgroundTaskInvalid) return;
    __weak typeof(self) weak = self;
    _bgTask = [[UIApplication sharedApplication]
        beginBackgroundTaskWithName:@"FoulPlayDecrypt"
                  expirationHandler:^{ [weak endBackgroundAssertion]; }];
}

- (void)endBackgroundAssertion {
    if (_bgTask == UIBackgroundTaskInvalid) return;
    [[UIApplication sharedApplication] endBackgroundTask:_bgTask];
    _bgTask = UIBackgroundTaskInvalid;
}

- (void)copyStatus:(UILongPressGestureRecognizer *)gesture {
    if (gesture.state != UIGestureRecognizerStateBegan) return;
    if (!_statusLabel.text.length) return;

    [UIPasteboard generalPasteboard].string = _statusLabel.text;
    [[[UINotificationFeedbackGenerator alloc] init]
        notificationOccurred:UINotificationFeedbackTypeSuccess];

    // Flash rather than swapping in "Copied" — the text being copied is the
    // error itself, and replacing it would defeat the point.
    _statusLabel.alpha = 0.2;
    [UIView animateWithDuration:0.35 animations:^{ self->_statusLabel.alpha = 1.0; }];
}

- (void)resetForNewRun {
    [self discardScratchIPA];
    _inboxSourcePath = nil;
    _outputPath = nil;
    _shareButton.enabled = NO;
}

/// Deletes an AirDropped source once we have a result from it. Guarded on the
/// Inbox path so this can never remove a file the user opened from elsewhere.
- (void)consumeInboxSource {
    NSString *path = _inboxSourcePath;
    _inboxSourcePath = nil;
    if (!path || ![path containsString:@"/Documents/Inbox/"]) return;
    [[NSFileManager defaultManager] removeItemAtPath:path error:nil];
    FPLogger(@"VC", @"removed Inbox source %@", path.lastPathComponent);
}

- (void)discardScratchIPA {
    if (!_scratchIPAPath) return;
    [[NSFileManager defaultManager] removeItemAtPath:_scratchIPAPath error:nil];
    _scratchIPAPath = nil;
}

- (void)setStatus:(NSString *)text color:(UIColor *)color {
    _statusLabel.text = text;
    _statusLabel.textColor = color;
}

- (void)showError:(NSString *)msg {
    [self setStatus:[NSString stringWithFormat:@"✗ %@", msg]
              color:[UIColor systemRedColor]];
}

@end
