#
# Yet Another Manet IP Router (YAMIR)
# 
# yamird - user-space router
# kyamir- kernel-space module
# test_runner - test runner
#

CC = gcc
LD = gcc
CTAGS = ctags

# verbosity - aka Kbuild/HAProxy style
# -----------------------------------
V ?= 0
Q = @
ifeq ($V,1)
Q=
endif

ifeq ($(V),1)
cmd_CC  = $(CC)
cmd_LD  = $(CC)
else
cmd_CC   = $(Q)echo "  CC    $@";$(CC)
cmd_LD   = $(Q)echo "  LD    $@";$(CC)
endif

# compiler flags
# --------------
GCC_DEPS     := -MMD -MP
CPP_FLAGS    := -D_GNU_SOURCE -Iinclude -Iyamir
YAMIR_CFLAGS := -Wall \
	-Wextra -Wno-missing-field-initializers \
	-Wmissing-prototypes -Wstrict-prototypes \
	-Wno-unused-parameter \
	-Werror=sign-compare \
	-Werror=discarded-qualifiers \
	-Werror=shadow=compatible-local \
	-Werror=implicit-function-declaration \
	$(CPP_FLAGS) $(GCC_DEPS)

DEBUG_CFLAGS := -ggdb3 -fno-omit-frame-pointer -DDEBUG=1

CFLAGS  = -O2 $(YAMIR_CFLAGS)
LDFLAGS =

TOPDIR=$(shell pwd)
TARGET ?= linux

ifeq ($(TARGET), linux)
	ARCH=$(shell uname -m)
	KDIR=/lib/modules/$(shell uname -r)/build
	#OBJDIR=build-$(TARGET)
else ifeq ($(TARGET), samsungs2)
	KDIR=/home/cy/wrk/android-device/samsungs2/kernel-src
	ARCH=arm
	NDK_TOOLCHAIN=/home/cy/wrk/android9-toolchain/bin
	KERN_TOOLCHAIN=/home/cy/wrk/CodeSourcery/Sourcery_G++_Lite/bin
	PATH := $(KERN_TOOLCHAIN):$(NDK_TOOLCHAIN):$(PATH)
	#PATH := $(NDK_TOOLCHAIN):$(PATH)
	export PATH
	#iKCC=arm-linux-androideabi-gcc
	#CC=arm-none-eabi-gcc
	CC=arm-linux-androideabi-gcc
	#OBJDIR=$(ARCH)
	export CROSS_COMPILE=arm-none-eabi-
else ifeq ($(TARGET), htcdesire)
	KDIR=/home/cy/wrk/android-device/htcdesire/kernel-src
	ARCH=arm
	#iKCC=arm-linux-androideabi-gcc
	#CC=arm-none-eabi-gcc
	NDK_TOOLCHAIN=/home/cy/wrk/android9-toolchain/bin
	KERN_TOOLCHAIN=/home/cy/wrk/android-ndk-r5/toolchains/arm-eabi-4.4.0/prebuilt/linux-x86/bin
	PATH := $(KERN_TOOLCHAIN):$(NDK_TOOLCHAIN):$(PATH)
	export PATH
	CC=arm-linux-androideabi-gcc
	#OBJDIR=$(ARCH)
	export CROSS_COMPILE=arm-eabi-
else
$(error TARGET $(TARGET) unsupported)
endif


YAMIR  = yamird
KYAMIR = kyamir
BUILD_DIR = build

# default target
# --------------
.PHONY: all
all : $(YAMIR) $(KYAMIR)

# debug build
# -----------
debug: CFLAGS = -O0 $(YAMIR_CFLAGS) $(DEBUG_CFLAGS)
debug: all test_runner

# build-dir
# ---------
$(BUILD_DIR):
	@mkdir -p $@

# yamir
# -----
YAMIR_DIR  = yamir
YAMIR_SRCS = $(YAMIR_DIR)/util.c $(YAMIR_DIR)/timer.c $(YAMIR_DIR)/log.c $(YAMIR_DIR)/pbb.c $(YAMIR_DIR)/main.c
YAMIR_OBJS = $(YAMIR_SRCS:$(YAMIR_DIR)/%.c=$(BUILD_DIR)/%.o)
YAMIR_DEPS = $(YAMIR_OBJS:.o=.d)
-include $(YAMIR_DEPS)
$(YAMIR) : $(YAMIR_OBJS)
	$(cmd_LD) $(CFLAGS) $(LDFLAGS) $(YAMIR_OBJS) -o $@

# build rule for yamir files
$(BUILD_DIR)/%.o: $(YAMIR_DIR)/%.c | $(BUILD_DIR)
	$(cmd_CC) $(CFLAGS) -c $< -o $@

# kyamir
# ------
.PHONY: kyamir
$(KYAMIR):
	$(MAKE) -C $(KYAMIR) KERNELDIR=$(KDIR) KCC=$(CC)

# test-runner
# -----------
TEST_DIR  = tests
TEST_RUNNER = test_runner
TEST_SRCS = $(YAMIR_DIR)/log.c $(YAMIR_DIR)/pbb.c $(TEST_DIR)/runner.c
TEST_OBJS = $(addprefix $(BUILD_DIR)/, $(notdir $(TEST_SRCS:.c=.o)))
TEST_DEPS = $(TEST_OBJS:.o=.d)
-include $(TEST_DEPS)
$(TEST_RUNNER) : $(TEST_OBJS)
	$(cmd_LD) $(CFLAGS) $(LDFLAGS) $(TEST_OBJS) -o $@

# build rule for test files
$(BUILD_DIR)/%.o: $(TEST_DIR)/%.c | $(BUILD_DIR)
	@mkdir -p $(BUILD_DIR)
	$(cmd_CC) $(CFLAGS) -c $< -o $@

TEST_FILES = tests/rfc5444_core.txt

# test
# ----
.PHONY: test
test: $(TEST_RUNNER)
	./$(TEST_RUNNER) $(TEST_FILES)


# tags file
# ----------
.PHONY: tags
SOURCES = $(wildcard yamir/*.c yamir/*.h)
tags: $(SOURCES)
	@echo "Creating tags file"
	$(Q)$(CTAGS) $(SOURCES)

# clean
# -----
.PHONY: clean
clean: 
	rm -fr $(BUILD_DIR) $(YAMIR) $(TEST_RUNNER)
	$(MAKE) -C $(KYAMIR) KERNELDIR=$(KDIR) KCC=$(CC) clean
