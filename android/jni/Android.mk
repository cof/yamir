LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE    := iw
LOCAL_SRC_FILES := iwlib.c
include $(BUILD_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE    := iwconfig
LOCAL_SRC_FILES := iwconfig.c
LOCAL_STATIC_LIBRARIES:= iw
include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)
LOCAL_MODULE    := killall
LOCAL_SRC_FILES := signals.c killall.c
include $(BUILD_EXECUTABLE)
