export THEOS ?= $(HOME)/theos

ARCHS = arm64
TARGET = iphone:clang:16.5:15.0
THEOS_PACKAGE_SCHEME = rootless

export DEVELOPER_DIR = /Applications/Xcode-beta.app/Contents/Developer

THEOS_DEVICE_IP = 127.0.0.1
THEOS_DEVICE_PORT = 2222

include $(THEOS)/makefiles/common.mk

APPLICATION_NAME = FoulPlay

FoulPlay_FILES  = Sources/main.m
FoulPlay_FILES += Sources/AppDelegate.m
FoulPlay_FILES += Sources/ViewController.m
FoulPlay_FILES += Sources/Decryptor.m
FoulPlay_FILES += Sources/InProcessDecrypt.m
FoulPlay_FILES += Sources/UnfairSupport/UnfairSupport.c
FoulPlay_FILES += Sources/LogHelper.m

FoulPlay_FRAMEWORKS = UIKit Foundation UniformTypeIdentifiers

FoulPlay_CFLAGS  = -fobjc-arc
FoulPlay_CFLAGS += -ISources/UnfairSupport/include

FoulPlay_CCFLAGS = -fobjc-arc

FoulPlay_LDFLAGS = -ldl

FoulPlay_CODESIGN_FLAGS = -Sentitlements.plist

include $(THEOS)/makefiles/application.mk
