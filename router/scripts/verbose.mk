#
# Verbosity - Inspired by Kbuild/HAProxy
# --------------------------------------
#

V ?= 0
Q = @
ifeq ($V,1)
Q=
endif

ifeq ($(V),1)
cmd_TAR = $(TAR)
cmd_CC  = $(CC)
cmd_LD  = $(CC)
else
cmd_TAR  = $(Q)echo "  TAR   $@";$(TAR)
cmd_CC   = $(Q)echo "  CC    $@";$(CC)
cmd_LD   = $(Q)echo "  LD    $@";$(CC)
endif
