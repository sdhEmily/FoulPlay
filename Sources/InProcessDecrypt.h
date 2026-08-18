#pragma once
#import <Foundation/Foundation.h>

/// Decrypt the binary at @p binaryPath in-process via mremap_encrypted.
///
/// @param binaryPath   Absolute path to the binary (inside the staged app dir).
/// @param appBundleDir Directory that contains SC_Info/ (used as CWD so the
///                     kernel can locate the sinf for FairPlay key lookup).
/// @param isCancelled  Polled between chunks; return YES to abort. May be nil.
/// @param errorOut     On failure, set to a human-readable description.
/// @return YES on full success, NO if any step failed or it was cancelled.
BOOL decryptBinaryAtPath(NSString *binaryPath,
                         NSString *appBundleDir,
                         BOOL (^isCancelled)(void),
                         NSString **errorOut);

/// Pre-flight: does this binary carry a live encrypted arm64 slice?
///
/// Callers use this before staging a sinf — the sinf only matters if there is
/// something to decrypt, and checking it first reports "No sinf in SC_Info/"
/// for binaries whose real problem is that they are already decrypted or an
/// unsupported architecture.
///
/// @param displayName Name to use in messages (the app's display name), so a
///                    user sees "YouTube is already decrypted" rather than
///                    "binary is already decrypted". May be nil.
/// @param reason On NO, set to a user-facing explanation.
BOOL binaryNeedsDecryption(NSString *binaryPath, NSString *displayName,
                           NSString **reason);
