// No-op stubs — jailbreak primitives removed.
// mremap_encrypted is called directly; the kernel patch is expected to
// handle the CS_PLATFORM_BINARY requirement on a jailbroken device.
#include "UnfairSupport.h"

int unfair_prepare_app_bundle_decryption(char *error, size_t error_size) {
    (void)error; (void)error_size;
    return 0;   // nothing to do
}

void unfair_drop_root(void) {
    // nothing to do
}
