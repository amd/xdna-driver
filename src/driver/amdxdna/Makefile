# SPDX-License-Identifier: GPL-2.0
#
# Copyright (C) 2022-2024, Advanced Micro Devices, Inc.
#

KERNEL_VER ?= $(shell uname -r)
KERNEL_SRC ?= /lib/modules/$(KERNEL_VER)/build

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
