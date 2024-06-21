# SPDX-License-Identifier: GPL-2.0
#
# Copyright (C) 2022-2024, Advanced Micro Devices, Inc.
#

KERNEL_VER ?= $(shell uname -r)
KERNEL_SRC ?= /lib/modules/$(KERNEL_VER)/build

mkfile_path = $(abspath $(lastword $(MAKEFILE_LIST)))
SRC_DIR = $(patsubst %/,%,$(dir $(mkfile_path)))
BUILD_ROOT_DIR := $(SRC_DIR)/build

ifeq ($(BUILD_ROOT_DIR),$(SRC_DIR))
$(error BUILD_ROOT_DIR and SRC_DIR can NOT be the same)
endif

define enable_extra_drv
	@if [ -f extra_drv.mk ]; then \
		echo "[INFO] enable all includes in extra_drv.mk"; \
		cp extra_drv.mk extra_drv.mk.orig; \
		sed 's/-include/include/' extra_drv.mk.orig > extra_drv.mk; \
		fi
endef

define restore_extra_drv
	@if [ -f extra_drv.mk ]; then \
		cp extra_drv.mk.orig extra_drv.mk; \
		rm extra_drv.mk.orig; \
		fi
endef

.PHONY: all clean modules modules_install copy_ko

all: $(BUILD_ROOT_DIR)
	$(MAKE) -C $(BUILD_ROOT_DIR)/driver/$(notdir $(SRC_DIR)) modules

# add EXTRA_CFLAGS='-save-temps' to keep intermedia files
modules:
	$(call enable_extra_drv)
	$(MAKE) -C $(KERNEL_SRC) M=$(SRC_DIR) CFLAGS_MODULE='-DAMDXDNA_DEVEL' modules
	$(call restore_extra_drv)

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
