#import "ViewController.h"
#import "Decryptor.h"
#import "LogHelper.h"
#import <UniformTypeIdentifiers/UniformTypeIdentifiers.h>
#include <unistd.h>
#include <spawn.h>
#include <sys/wait.h>
extern char **environ;

@interface ViewController () <UIDocumentPickerDelegate>
@property (nonatomic, strong) UIButton         *openButton;
@property (nonatomic, strong) UILabel          *statusLabel;
@property (nonatomic, strong) UIActivityIndicatorView *spinner;
@property (nonatomic, strong) UIButton         *shareButton;
@property (nonatomic, strong) NSString         *outputPath;
@property (nonatomic, strong) Decryptor        *decryptor;
@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    FPFileLog(@"VC", @"viewDidLoad — log path: %@", FPLogPath());
    self.title = @"FoulPlay";
    self.view.backgroundColor = [UIColor systemBackgroundColor];

    // ── Open button ──────────────────────────────────────────────────────────
    _openButton = [UIButton buttonWithType:UIButtonTypeSystem];
    _openButton.translatesAutoresizingMaskIntoConstraints = NO;
    [_openButton setTitle:@"Open IPA" forState:UIControlStateNormal];
    _openButton.titleLabel.font =
        [UIFont systemFontOfSize:22 weight:UIFontWeightSemibold];
    [_openButton addTarget:self action:@selector(openIPA)
          forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:_openButton];

    // ── Spinner ──────────────────────────────────────────────────────────────
    _spinner = [[UIActivityIndicatorView alloc]
                initWithActivityIndicatorStyle:UIActivityIndicatorViewStyleMedium];
    _spinner.translatesAutoresizingMaskIntoConstraints = NO;
    _spinner.hidesWhenStopped = YES;
    [self.view addSubview:_spinner];

    // ── Status label ─────────────────────────────────────────────────────────
    _statusLabel = [[UILabel alloc] init];
    _statusLabel.translatesAutoresizingMaskIntoConstraints = NO;
    _statusLabel.textAlignment = NSTextAlignmentCenter;
    _statusLabel.numberOfLines = 0;
    _statusLabel.font = [UIFont monospacedSystemFontOfSize:13
                                                    weight:UIFontWeightRegular];
    _statusLabel.textColor = [UIColor secondaryLabelColor];
    _statusLabel.text = @"Select an IPA to decrypt";
    [self.view addSubview:_statusLabel];

    // ── Share button ─────────────────────────────────────────────────────────
    _shareButton = [UIButton buttonWithType:UIButtonTypeSystem];
    _shareButton.translatesAutoresizingMaskIntoConstraints = NO;
    [_shareButton setTitle:@"Share Decrypted IPA" forState:UIControlStateNormal];
    _shareButton.titleLabel.font =
        [UIFont systemFontOfSize:17 weight:UIFontWeightMedium];
    [_shareButton addTarget:self action:@selector(shareResult)
           forControlEvents:UIControlEventTouchUpInside];
    _shareButton.hidden = YES;
    [self.view addSubview:_shareButton];

    // ── Layout ───────────────────────────────────────────────────────────────
    [NSLayoutConstraint activateConstraints:@[
        [_openButton.centerXAnchor
             constraintEqualToAnchor:self.view.centerXAnchor],
        [_openButton.centerYAnchor
             constraintEqualToAnchor:self.view.centerYAnchor constant:-80],

        [_spinner.centerXAnchor
             constraintEqualToAnchor:self.view.centerXAnchor],
        [_spinner.topAnchor
             constraintEqualToAnchor:_openButton.bottomAnchor constant:24],

        [_statusLabel.centerXAnchor
             constraintEqualToAnchor:self.view.centerXAnchor],
        [_statusLabel.topAnchor
             constraintEqualToAnchor:_spinner.bottomAnchor constant:12],
        [_statusLabel.leadingAnchor
             constraintEqualToAnchor:self.view.leadingAnchor constant:28],
        [_statusLabel.trailingAnchor
             constraintEqualToAnchor:self.view.trailingAnchor constant:-28],

        [_shareButton.centerXAnchor
             constraintEqualToAnchor:self.view.centerXAnchor],
        [_shareButton.topAnchor
             constraintEqualToAnchor:_statusLabel.bottomAnchor constant:24],
    ]];
}

// ── Actions ───────────────────────────────────────────────────────────────────

- (void)openIPA {
    // Accept all files — IPA has no registered UTType on iOS so filtering
    // by zip UTIs causes the picker to hide .ipa files entirely.
    UTType *allData = [UTType typeWithIdentifier:@"public.data"];
    UIDocumentPickerViewController *picker =
        [[UIDocumentPickerViewController alloc]
         initForOpeningContentTypes:@[allData]];
    picker.delegate = self;
    picker.allowsMultipleSelection = NO;
    [self presentViewController:picker animated:YES completion:nil];
}

- (void)_fileLog:(NSString *)msg {
    FPFileLog(@"VC", @"%@", msg);
}

- (void)documentPicker:(UIDocumentPickerViewController *)controller
didPickDocumentsAtURLs:(NSArray<NSURL *> *)urls {
    NSURL *url = urls.firstObject;
    if (!url) return;

    _outputPath = nil;
    _shareButton.hidden = YES;
    _openButton.enabled = NO;
    _statusLabel.textColor = [UIColor secondaryLabelColor];
    _statusLabel.text = @"Copying";
    [_spinner startAnimating];

    NSString *dst = [@"/var/tmp" stringByAppendingPathComponent:url.lastPathComponent];

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        [[NSFileManager defaultManager] removeItemAtPath:dst error:nil];

        // In-process reads of Mobile Documents are blocked by a MAC policy on
        // app processes. Spawning cp sidesteps it — the child binary runs under
        // its own code signature without the app-specific restriction.
        const char *cpPaths[] = { "/var/jb/usr/bin/cp", "/usr/bin/cp", "/bin/cp", NULL };
        const char *cpBin = NULL;
        for (int i = 0; cpPaths[i]; i++) {
            if (access(cpPaths[i], X_OK) == 0) { cpBin = cpPaths[i]; break; }
        }

        NSString *srcPath = url.path;
        const char *argv[] = { cpBin ?: "/bin/cp", srcPath.UTF8String, dst.UTF8String, NULL };
        pid_t pid;
        int spawnErr = cpBin
            ? posix_spawn(&pid, cpBin, NULL, NULL, (char *const *)argv, environ)
            : ENOENT;

        NSString *errorMsg = nil;
        if (spawnErr != 0) {
            errorMsg = [NSString stringWithFormat:@"spawn cp errno=%d: %s",
                        spawnErr, strerror(spawnErr)];
            [self _fileLog:errorMsg];
        } else {
            int status = 0;
            waitpid(pid, &status, 0);
            int exitCode = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
            [self _fileLog:[NSString stringWithFormat:@"cp exited %d", exitCode]];
            if (exitCode != 0) {
                errorMsg = [NSString stringWithFormat:@"cp failed (exit %d)", exitCode];
            } else if (![[NSFileManager defaultManager] fileExistsAtPath:dst]) {
                errorMsg = @"cp exited 0 but file not found at /var/tmp";
                [self _fileLog:errorMsg];
            } else {
                [self _fileLog:[NSString stringWithFormat:@"copied → %@", dst]];
            }
        }

        dispatch_async(dispatch_get_main_queue(), ^{
            if (errorMsg) {
                [self->_spinner stopAnimating];
                self->_openButton.enabled = YES;
                [self showError:errorMsg];
            } else {
                self->_statusLabel.text = @"Starting";
                [self startDecryptionAt:dst];
            }
        });
    });
}

- (void)startDecryptionAt:(NSString *)ipaPath {
    _outputPath = nil;
    _shareButton.hidden = YES;
    _openButton.enabled = NO;
    _statusLabel.textColor = [UIColor secondaryLabelColor];
    _statusLabel.text = @"Decrypting";
    [_spinner startAnimating];

    _decryptor = [[Decryptor alloc] initWithIPAPath:ipaPath];
    __weak typeof(self) weak = self;

    [_decryptor decryptWithProgress:^(NSString *msg) {
        dispatch_async(dispatch_get_main_queue(), ^{
            weak.statusLabel.text = msg;
        });
    } completion:^(NSString *output, NSError *err) {
        dispatch_async(dispatch_get_main_queue(), ^{
            [weak.spinner stopAnimating];
            weak.openButton.enabled = YES;
            if (err) {
                [weak showError:err.localizedDescription];
            } else {
                weak.outputPath = output;
                weak.statusLabel.textColor = [UIColor systemGreenColor];
                NSString *name = weak.decryptor.appName ?: output.lastPathComponent;
                weak.statusLabel.text =
                    [NSString stringWithFormat:@"✓ Decrypted %@", name];
                weak.shareButton.hidden = NO;
            }
        });
    }];
}

- (void)shareResult {
    if (!_outputPath) return;
    UIActivityViewController *avc = [[UIActivityViewController alloc]
        initWithActivityItems:@[[NSURL fileURLWithPath:_outputPath]]
        applicationActivities:nil];
    [self presentViewController:avc animated:YES completion:nil];
}

- (void)showError:(NSString *)msg {
    _statusLabel.textColor = [UIColor systemRedColor];
    _statusLabel.text = [NSString stringWithFormat:@"✗ %@", msg];
}

@end
