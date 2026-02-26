# SPDX-License-Identifier: GPL-2.0
#
# Copyright (C) 2022-2024, Advanced Micro Devices, Inc.
#

KERNEL_VER ?= $(shell uname -r)
KERNEL_SRC ?= /lib/modules/$(KERNEL_VER)/build
XDNA_BUS_TYPE := pci

ifeq ($(XDNA_BUS_TYPE), pci)
PCI = y
OF = n
else ifeq ($(XDNA_BUS_TYPE), of)
PCI = n
OF = y
else
$(error Unknown XDNA_BUS_TYPE $(XDNA_BUS_TYPE))!!
endif

mkfile_path = $(abspath $(lastword $(MAKEFILE_LIST)))
SRC_DIR = $(patsubst %/,%,$(dir $(mkfile_path)))
BUILD_ROOT_DIR := $(SRC_DIR)/build

ifeq ($(BUILD_ROOT_DIR),$(SRC_DIR))
$(error BUILD_ROOT_DIR and SRC_DIR can NOT be the same)
endif

.PHONY: all clean modules modules_install copy_ko

all: $(BUILD_ROOT_DIR)
	$(MAKE) -C $(BUILD_ROOT_DIR)/driver/$(notdir $(SRC_DIR)) modules

# add EXTRA_CFLAGS='-save-temps' to keep intermedia files
DEFINES := -DAMDXDNA_DEVEL

# Driver version
XDNA_DATE ?= $(shell date +%Y%m%d)
XDNA_HASH ?= $(shell git rev-parse HEAD)
# Detect if kernel was built with Clang - check /proc/config.gz first, then /boot/config-*
USE_LLVM ?= $(shell \
    if [ -e /proc/config.gz ]; then \
        zgrep -q "CONFIG_CC_IS_CLANG=y" /proc/config.gz 2>/dev/null && echo -n "LLVM=1"; \
    elif [ -e /boot/config-$(KERNEL_VER) ]; then \
        grep -q "CONFIG_CC_IS_CLANG=y" /boot/config-$(KERNEL_VER) 2>/dev/null && echo -n "LLVM=1"; \
    fi)

ifndef MODULE_VER_STR
MODULE_VER_STR := $(XDNA_DRIVER_VERSION)_$(XDNA_DATE),$(XDNA_HASH)
endif

DEFINES += -DMODULE_VER_STR='\"$(MODULE_VER_STR)\"'

ifeq ($(XDNA_BUS_TYPE), of)
DEFINES += -DAMDXDNA_OF
# Generate config_kernel.h when building directly (Yocto/DKMS flow)
modules: $(SRC_DIR)/config_kernel.h
	$(MAKE) -C $(KERNEL_SRC) M=$(SRC_DIR) CFLAGS_MODULE="$(DEFINES)" OFT_CONFIG_AMDXDNA_PCI=$(PCI) OFT_CONFIG_AMDXDNA_OF=$(OF) $(USE_LLVM) modules

$(SRC_DIR)/config_kernel.h:
	@echo "[INFO] Generating config_kernel.h for OF build..."
	@KERNEL_SRC=$(KERNEL_SRC) OUT="$(SRC_DIR)/config_kernel.h" bash $(SRC_DIR)/../../../../tools/configure_kernel.sh
else
# PCI builds: CMake generates config_kernel.h
modules:
	$(MAKE) -C $(KERNEL_SRC) M=$(SRC_DIR) CFLAGS_MODULE="$(DEFINES)" OFT_CONFIG_AMDXDNA_PCI=$(PCI) OFT_CONFIG_AMDXDNA_OF=$(OF) $(USE_LLVM) modules
endif

modules_install:
	$(MAKE) -C $(KERNEL_SRC) M=$(SRC_DIR) modules_install

$(BUILD_ROOT_DIR): $(SRC_DIR)
	@echo "[INFO] BUILD Directory not exist or SRC Directory is newer"
	@echo "[INFO] Re-Generate BUILD_ROOT_DIR: $(BUILD_ROOT_DIR)"
	@rm -rf $@
	@$(eval TMP_DIR := $(shell mktemp -d))
	@mkdir -p $(TMP_DIR)/driver
	@cp -rs $(SRC_DIR) $(TMP_DIR)/driver
	@cp -rs $(SRC_DIR)/../../include $(TMP_DIR)
	@mv $(TMP_DIR) $(BUILD_ROOT_DIR)

copy_ko:
	@find $(BUILD_ROOT_DIR) -mindepth 2 -name *.ko -type f -exec cp -f {} $(BUILD_ROOT_DIR) \;

clean:
	rm -rf $(BUILD_ROOT_DIR)
	rm -rf *.o *.cmd .*.cmd *.ko *.dwo *.mod* modules.order Module.symvers
