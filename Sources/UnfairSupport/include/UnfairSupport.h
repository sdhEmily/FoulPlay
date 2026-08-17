#ifndef UNFAIR_SUPPORT_H
#define UNFAIR_SUPPORT_H

#include <stddef.h>

// Sets CS_PLATFORM_BINARY on the calling process via jailbreakd.
// Acquires root transiently; call unfair_drop_root() when done.
int unfair_prepare_app_bundle_decryption(char *error, size_t error_size);

// Drops the root credentials acquired by unfair_prepare_app_bundle_decryption.
void unfair_drop_root(void);

#endif
