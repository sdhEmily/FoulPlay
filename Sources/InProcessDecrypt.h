#pragma once
#import <Foundation/Foundation.h>

/// Decrypt the binary at @p binaryPath in-process via mremap_encrypted.
///
/// @param binaryPath   Absolute path to the binary (inside the staged app dir).
/// @param appBundleDir Directory that contains SC_Info/ (used as CWD so the
///                     kernel can locate the sinf for FairPlay key lookup).
/// @param errorOut     On failure, set to a human-readable description.
/// @return YES on full success, NO if any step failed.
BOOL decryptBinaryAtPath(NSString *binaryPath,
                         NSString *appBundleDir,
                         NSString **errorOut);
