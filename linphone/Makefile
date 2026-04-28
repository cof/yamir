# 
# Linphone Makefile
#

# --- Configuration ---
ORIG_URL  := git://git.linphone.org/linphone-android.git
CURR_URL  := https://gitlab.linphone.org/BC/public/linphone-android.git
COMMIT_ID := 9972f63f14a27ad5cc1c331a27f9996841cec06b
BUILD_DIR := build

PATCHES := \
	$(CURDIR)/main_src.patch \
	$(CURDIR)/submod_linphone.patch \
	$(CURDIR)/submod_exposip.patch

# NDK/SDK
AND_ROOT  ?= $(HOME)/build/android
NDK_PATH  := $(AND_ROOT)/android-ndk-r7b
SDK_PATH  := $(AND_ROOT)/android-sdk-linux
NDK_BUILD := $(NDK_PATH)/ndk-build
ADB       := $(SDK_PATH)/platform-tools/adb
ANDROID   := $(SDK_PATH)/tools/android
ANT       := ant 
JAVAC     := javac

# Build target for S2/Desire (ARMv7)
ARM_ARCH := APP_ABI=armeabi-v7a

# --- Targets ---
all: build

# check env (NDK,SDK,ANT,JDK)
# ---------------------------
check-env:
	@echo "Checking build tools..."
	@test -d $(AND_ROOT) || (echo "Error: AND_ROOT $(AND_ROOT) not found"; exit 1)
	@test -x $(NDK_PATH)/ndk-build || (echo "Error: NDK not found at $(NDK_PATH)"; exit 1)
	@test -d $(SDK_PATH)/platforms/android-8 || (echo "Error: Android API 8 (Froyo) platform missing in SDK"; exit 1)
	@$(ANT) -version > /dev/null 2>&1 || (echo "Error: Apache Ant is not installed. Use 'sudo apt install ant'"; exit 1)
	@$(JAVAC) -version > /dev/null 2>&1 || (echo "Error: Java Compiler (javac) not found. JDK is required."; exit 1)
	@echo "Environment OK."

# linphone repo
# -------------
CLONE_DONE := $(BUILD_DIR)/.clone_done
$(CLONA_DONE):
	@echo "Checking out $(COMMIT_ID)"
	git clone $(ORIG_URL) $(BUILD_DIR)
	cd $(BUILD_DIR) && git checkout $(COMMIT_ID)
	cd $(BUILD_DIR) && git submodule sync --recursive
	cd $(BUILD_DIR) && git submodule update --init --recursive
	touch $(CLONE_DONE)

# linphone repo v2
# ----------------
$(CLONE_DONE):
	git clone $(CURR_URL) $(BUILD_DIR)
	cd $(BUILD_DIR) && git checkout $(COMMIT_ID)
	# main repo
	cd $(BUILD_DIR) && sed -i 's|git://git.linphone.org/|https://gitlab.linphone.org/BC/public/|g' .gitmodules
	# fix urls
	#cd $(BUILD_DIR) && sed -i 's|bcg729.git|bcg729|g' .gitmodules
	cd $(BUILD_DIR) && sed -i 's|https://gitlab.linphone.org/BC/public/linphone.git|https://gitlab.linphone.org/BC/public/liblinphone|g' .gitmodules
	cd $(BUILD_DIR) && sed -i 's|https://gitlab.linphone.org/BC/public/exosip.git|https://git.savannah.nongnu.org/git/exosip.git|g' .gitmodules
	cd $(BUILD_DIR) && sed -i 's|https://gitlab.linphone.org/BC/public/osip.git|https://github.com/aurelihein/osip.git|g' .gitmodules
	cd $(BUILD_DIR) && sed -i 's|http://git.chromium.org/webm/libvpx.git|https://gitlab.linphone.org/BC/public/external/libvpx.git|g' .gitmodules
	cd $(BUILD_DIR) && sed -i 's|https://gitlab.linphone.org/BC/public/zrtpcpp.git|https://gitlab.linphone.org/BC/public/bzrtp|g' .gitmodules
	cd $(BUILD_DIR) && sed -i 's|https://gitlab.linphone.org/BC/public/bcg729.git|https://gitlab.linphone.org/BC/public/bcg729|g' .gitmodules
	cd $(BUILD_DIR) && sed -i 's|https://gitlab.linphone.org/BC/public/gsm.git|https://gitlab.linphone.org/BC/public/external/gsm|g' .gitmodules
	cd $(BUILD_DIR) && sed -i 's|http://chromium.org|https://gitlab.linphone.org/BC/public/external/libvpx.git|g' .gitmodules
	cd $(BUILD_DIR) && sed -i 's|https://gitlab.linphone.org/BC/public/srtp.git|https://gitlab.linphone.org/BC/public/external/srtp.git|g' .gitmodules
	cd $(BUILD_DIR) && sed -i 's|https://gitlab.linphone.org/BC/public/speex|https://gitlab.linphone.org/BC/public/external/speex|g' .gitmodules
	cd $(BUILD_DIR) && sed -i 's|git://git.videolan.org/x264.git|https://gitlab.linphone.org/BC/public/external/x264.git|g' .gitmodules

	# 4. Sync and Update
	cd $(BUILD_DIR) && git submodule sync --recursive
	cd $(BUILD_DIR) && git submodule update --init --recursive -j 1
	touch $(CLONE_DONE)

PATCH_DONE := $(BUILD_DIR)/.patch_done
$(PATCH_DONE): $(CLONE_DONE)
	cd $(BUILD_DIR) && git apply $(PATCHES)
	touch $(PATCH_DONE)

PREP_DONE := $(BUILD_DIR)/.prep_done
$(PREP_DONE): $(PATCH_DONE)
	cd $(BUILD_DIR) && ./prepare_sources.sh $(NDK_PATH)
	cd $(BUILD_DIR) && $(ANDROID) update project --path . --target android-13
	touch $(PREP_DONE)

build: check-env $(PREP_DONE)
	cd $(BUILD_DIR) && $(NDK_BUILD) -j4 $(ARM_ARCH)
	cd $(BUILD_DIR) && SDK_ROOT=$(SDK_PATH) $(ANT) debug

clean:
	rm -rf $(BUILD_DIR)
