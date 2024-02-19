# SPDX-License-Identifier: GPL-2.0
#
# Copyright (C) 2022-2024, Advanced Micro Devices, Inc.
#

KERNEL_VER ?= $(shell uname -r)
KERNEL_SRC ?= /lib/modules/$(KERNEL_VER)/build

ROOT := $(src)

ccflags-y += -I$(ROOT)/
# uAPI
ccflags-y += -I$(ROOT)/../../include/uapi
# version.h
ccflags-y += -I$(ROOT)/../../include

# All warning will report as error and debug build
ccflags-y += -g -Werror

obj-m	+= amdxdna.o
amdxdna-y := \
	solver.o \
	amdxdna_xclbin.o \
	amdxdna_ctx.o \
	amdxdna_gem.o \
	amdxdna_util.o \
	amdxdna_sysfs.o \
	npu_smu.o \
	npu_error.o \
	npu_debugfs.o \
	npu_pci.o \
	npu_message.o \
	npu1_regs.o \
	npu2_regs.o \
	amdxdna_mailbox.o \
	amdxdna_psp.o \
	amdxdna_drv.o

# Helper functions for amdxdna development, but not for upstreaming
amdxdna-y += amdxdna_devel.o

SRC_DIR ?= $(shell pwd)
BUILD_DIR ?= $(SRC_DIR)/build/amdxdna

BUILD_DIR_MAKEFILE := $(BUILD_DIR)/Makefile

# add EXTRA_CFLAGS='-save-temps' to keep intermedia files
modules: $(BUILD_DIR_MAKEFILE)
	$(MAKE) -C $(KERNEL_SRC) M=$(BUILD_DIR) src=$(SRC_DIR) CFLAGS_MODULE='-DAMDXDNA_DEVEL' modules

modules_install: $(BUILD_DIR_MAKEFILE)
	$(MAKE) -C $(KERNEL_SRC) M=$(BUILD_DIR) src=$(SRC_DIR) modules_install

$(BUILD_DIR):
	mkdir -p "$@"

$(BUILD_DIR_MAKEFILE): $(BUILD_DIR)
	touch "$@"

clean:
	rm -rf $(SRC_DIR)/build
