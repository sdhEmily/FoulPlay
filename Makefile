export THEOS ?= $(HOME)/theos

ARCHS = arm64
TARGET = iphone:clang:16.5:15.0
THEOS_PACKAGE_SCHEME = rootless

# Follow xcode-select rather than a hardcoded path. There is nothing useful to
# fall back to: if xcode-select is wrong, the /usr/bin tool shims Theos invokes
# resolve through it and fail regardless. An explicit DEVELOPER_DIR in the
# environment still wins, which is the normal way to build against another Xcode.
export DEVELOPER_DIR ?= $(shell xcode-select -p)

THEOS_DEVICE_IP = 127.0.0.1
THEOS_DEVICE_PORT = 2222

include $(THEOS)/makefiles/common.mk

APPLICATION_NAME = FoulPlay

FoulPlay_FILES  = Sources/main.m
FoulPlay_FILES += Sources/AppDelegate.m
FoulPlay_FILES += Sources/ViewController.m
FoulPlay_FILES += Sources/Decryptor.m
FoulPlay_FILES += Sources/InProcessDecrypt.m
FoulPlay_FILES += Sources/LogHelper.m

FoulPlay_FRAMEWORKS = UIKit Foundation UniformTypeIdentifiers CoreGraphics

FoulPlay_CFLAGS = -fobjc-arc

FoulPlay_LDFLAGS = -ldl -larchive

FoulPlay_CODESIGN_FLAGS = -Sentitlements.plist

include $(THEOS)/makefiles/application.mk

# CFBundleVersion is the on-screen build id — shown as "v1.1.0 (N)" in debug
# builds. Taken from the deb revision Theos already increments, so the label
# matches the package filename: 1.1.0-29+debug -> "v1.1.0 (29)".
#
# Note the staged path has no /var/jb prefix: rootless relocation happens later
# in packaging, so at this point the app is plainly under Applications/.
after-stage::
	@rev="$(_THEOS_INTERNAL_PACKAGE_VERSION)"; \
	case "$$rev" in *-*) rev="$${rev#*-}"; rev="$${rev%%+*}";; *) rev="";; esac; \
	if [ -n "$$rev" ]; then \
	  /usr/libexec/PlistBuddy -c "Set :CFBundleVersion $$rev" \
	    "$(THEOS_STAGING_DIR)/Applications/FoulPlay.app/Info.plist" >/dev/null && \
	  echo "==> CFBundleVersion = $$rev"; \
	fi
