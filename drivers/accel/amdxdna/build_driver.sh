#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# Build script for AMDXDNA driver - supports both x86_64 PCI and ARM64 AUX builds

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Kernel tree where you run: cp .config . && make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu-
DEFAULT_KERNEL_SRC="/scratch/telluride/8jul/Vitis-AI-Telluride/versal_2ve/reference_design/vek385/rev-b/sw/yocto/build/tmp/work-shared/amd-cortexa78-mali-common/kernel-source"
VITIS_SETTINGS="/proj/xbuilds/2026.1_daily_latest/installs/lin64/2026.1/Vitis/settings64.sh"
VITIS_SETTINGS_ALT="/proj/xbuilds/2025.2_daily_latest/installs/lin64/2025.2/Vitis/settings64.sh"

print_usage() {
	echo "Usage: $0 [x86|arm64|both|clean]"
	echo ""
	echo "Options:"
	echo "  x86    - Build x86_64 PCI driver (native)"
	echo "  arm64  - Build ARM64 AUX driver against pre-built kernel-source (default)"
	echo "  both   - Build both drivers"
	echo "  clean  - Clean all build artifacts"
	echo ""
	echo "Environment (arm64, default = in-tree kernel build):"
	echo "  KERNEL_SRC  - kernel tree with .config and 'make' already done (Image built)"
	echo "  CROSS_COMPILE - default aarch64-linux-gnu- (same as manual kernel build)"
	echo ""
	echo "Optional Yocto split-tree mode:"
	echo "  KERNEL_USE_YOCTO_OUT=1  - use O=kernel-build-artifacts (old flow)"
	echo "  KERNEL_OUT              - override build dir when Yocto mode is on"
	echo ""
}

# Verify kernel was built in-tree (VE2 aux needs xilinx-aie symbols at link time).
check_kernel_ready() {
	local symvers="$KERNEL_SRC/Module.symvers"
	local aie_symvers="$KERNEL_SRC/drivers/misc/xilinx-ai-engine/Module.symvers"

	if [ ! -f "$KERNEL_SRC/.config" ]; then
		echo -e "${RED}Error: $KERNEL_SRC/.config missing${NC}"
		echo -e "${YELLOW}Copy your .config into kernel-source, run 'make ARCH=arm64', then retry.${NC}"
		return 1
	fi

	if [ ! -f "$KERNEL_SRC/include/generated/autoconf.h" ] && \
	   [ ! -f "$KERNEL_SRC/Module.symvers" ] && \
	   [ ! -f "$KERNEL_SRC/arch/arm64/boot/Image" ]; then
		echo -e "${RED}Error: kernel does not look built in $KERNEL_SRC${NC}"
		echo -e "${YELLOW}Run: ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- make -j\$(nproc)${NC}"
		return 1
	fi

	if grep -qE 'aie_partition_reserve|aie_get_device_info' "$symvers" 2>/dev/null; then
		unset KBUILD_EXTRA_SYMBOLS
		return 0
	fi

	if [ -f "$KERNEL_SRC/drivers/misc/xilinx-ai-engine/xilinx-aie.ko" ] && \
	   [ -f "$aie_symvers" ] && \
	   grep -qE 'aie_partition_reserve|aie_get_device_info' "$aie_symvers" 2>/dev/null; then
		export KBUILD_EXTRA_SYMBOLS="$aie_symvers"
		echo -e "${YELLOW}Using KBUILD_EXTRA_SYMBOLS=$KBUILD_EXTRA_SYMBOLS${NC}"
		return 0
	fi

	echo -e "${RED}Error: xilinx-aie symbols not found in $symvers${NC}"
	echo -e "${YELLOW}Enable CONFIG_XILINX_AIE in .config and rebuild the kernel (make -j).${NC}"
	return 1
}

find_yocto_cross_gcc() {
	local yocto_build kernel_ws
	kernel_ws="$(dirname "$KERNEL_SRC")"
	yocto_build="$(cd "${kernel_ws}/../../.." && pwd)"

	find "${yocto_build}/tmp/work" -path "*/linux-xlnx/*/recipe-sysroot-native/usr/bin/aarch64-amd-linux/aarch64-amd-linux-gcc" \
		2>/dev/null | head -1
}

# Optional: Yocto O=kernel-build-artifacts layout (set KERNEL_USE_YOCTO_OUT=1).
build_arm64_yocto_out() {
	export KERNEL_OUT="${KERNEL_OUT:-$(dirname "$KERNEL_SRC")/kernel-build-artifacts}"

	if [ ! -f "$KERNEL_OUT/include/generated/autoconf.h" ]; then
		echo -e "${RED}Error: prepared kernel build not found at $KERNEL_OUT${NC}"
		return 1
	fi

	YOCTO_GCC="$(find_yocto_cross_gcc)"
	if [ -z "$YOCTO_GCC" ] || [ ! -x "$YOCTO_GCC" ]; then
		echo -e "${RED}Error: aarch64-amd-linux-gcc not found${NC}"
		return 1
	fi

	export ARCH=arm64
	export CROSS_COMPILE=aarch64-amd-linux-
	export PATH="$(dirname "$YOCTO_GCC"):${PATH}"
	export XDNA_BUS_TYPE=aux

	echo -e "${YELLOW}Yocto mode: KERNEL_SRC=$KERNEL_SRC KERNEL_OUT=$KERNEL_OUT${NC}"
	make modules
}

copy_dep_modules_for_target() {
	local kdir="$KERNEL_SRC"
	for pair in \
		"drivers/misc/xilinx-ai-engine/xilinx-aie:xilinx-aie.ko"; do
		local src="${pair%%:*}"
		local dst="${pair##*:}"
		if [ -f "$kdir/$src" ]; then
			cp -f "$kdir/$src" "$SCRIPT_DIR/$dst"
			echo -e "${YELLOW}Copied $dst for target${NC}"
		fi
	done
	chmod +x "$SCRIPT_DIR/load_amdxdna_ve2.sh" 2>/dev/null || true
}

print_insmod_help() {
	echo ""
	echo -e "${YELLOW}On target: insmod does NOT load dependencies. Use either:${NC}"
	echo -e "  ${GREEN}modprobe amdxdna${NC}  (if installed under /lib/modules/\$(uname -r))"
	echo -e "  ${GREEN}./load_amdxdna_ve2.sh${NC}  (after copying xilinx-aie.ko, amdxdna.ko)"
	echo -e "  or manually:"
	echo -e "    insmod xilinx-aie.ko && insmod amdxdna.ko"
	echo -e "${YELLOW}Kernel on target must match the Image you built (CONFIG_XILINX_AIE).${NC}"
}

build_x86() {
	echo -e "${GREEN}========================================${NC}"
	echo -e "${GREEN}Building x86_64 PCI Driver${NC}"
	echo -e "${GREEN}========================================${NC}"

	make clean 2>/dev/null || true
	rm -f config_kernel.h

	if [ -f "config_kernel_x86.h" ]; then
		echo -e "${YELLOW}Using cached config_kernel_x86.h...${NC}"
		cp config_kernel_x86.h config_kernel.h
	else
		echo -e "${YELLOW}Generating config_kernel.h for x86_64...${NC}"
		OUT="config_kernel.h" bash ../tools/configure_kernel.sh
		cp config_kernel.h config_kernel_x86.h
	fi

	echo -e "${YELLOW}Building kernel module...${NC}"
	unset KERNEL_OUT
	XDNA_BUS_TYPE=pci make modules

	if [ -f "amdxdna.ko" ]; then
		echo -e "${GREEN}✓ x86_64 PCI driver built successfully!${NC}"
		ls -lh amdxdna.ko
		file amdxdna.ko
		cp amdxdna.ko amdxdna_x86_64_pci.ko
	else
		echo -e "${RED}✗ x86_64 build failed!${NC}"
		return 1
	fi
}

build_arm64() {
	echo -e "${GREEN}========================================${NC}"
	echo -e "${GREEN}Building ARM64 AUX Driver${NC}"
	echo -e "${GREEN}========================================${NC}"

	export KERNEL_SRC="${KERNEL_SRC:-$DEFAULT_KERNEL_SRC}"
	unset KERNEL_OUT

	make clean 2>/dev/null || true
	rm -f config_kernel.h

	if [ ! -d "$KERNEL_SRC" ]; then
		echo -e "${RED}Error: KERNEL_SRC not found: $KERNEL_SRC${NC}"
		return 1
	fi

	# Yocto split-tree only when explicitly requested
	if [ -n "${KERNEL_USE_YOCTO_OUT:-}" ]; then
		build_arm64_yocto_out
		[ -f "amdxdna.ko" ] && cp amdxdna.ko amdxdna_arm64_aux.ko
		return $?
	fi

	# Default: module-only build against in-tree kernel (your workflow)
	if [ -f "$VITIS_SETTINGS" ]; then
		echo -e "${YELLOW}Sourcing Vitis environment...${NC}"
		# shellcheck source=/dev/null
		source "$VITIS_SETTINGS"
	elif [ -f "$VITIS_SETTINGS_ALT" ]; then
		echo -e "${YELLOW}Sourcing Vitis environment (2025.2)...${NC}"
		# shellcheck source=/dev/null
		source "$VITIS_SETTINGS_ALT"
	else
		echo -e "${YELLOW}Warning: Vitis settings not found; using PATH for aarch64-linux-gnu-${NC}"
	fi

	export ARCH=arm64
	export CROSS_COMPILE="${CROSS_COMPILE:-aarch64-linux-gnu-}"
	export XDNA_BUS_TYPE=aux

	echo -e "${YELLOW}KERNEL_SRC: $KERNEL_SRC (in-tree, no separate KERNEL_OUT)${NC}"
	echo -e "${YELLOW}CROSS_COMPILE: $CROSS_COMPILE${NC}"
	echo -e "${YELLOW}Building amdxdna.ko only (kernel must already be built)${NC}"

	check_kernel_ready || return 1

	# Headers only (no Image rebuild) if .config exists but generated/ was removed
	if [ ! -f "$KERNEL_SRC/include/generated/autoconf.h" ] && \
	   [ -f "$KERNEL_SRC/.config" ]; then
		echo -e "${YELLOW}Running 'make prepare' in kernel tree (headers only)...${NC}"
		make -C "$KERNEL_SRC" ARCH=arm64 CROSS_COMPILE="$CROSS_COMPILE" prepare
	fi

	if [ -f "config_kernel_arm64.h" ]; then
		echo -e "${YELLOW}Using cached config_kernel_arm64.h...${NC}"
		cp config_kernel_arm64.h config_kernel.h
	else
		echo -e "${YELLOW}Generating config_kernel.h for ARM64...${NC}"
		KERNEL_SRC="$KERNEL_SRC" OUT="config_kernel.h" bash ../tools/configure_kernel.sh
		cp config_kernel.h config_kernel_arm64.h
	fi

	echo -e "${YELLOW}Cross-compiling amdxdna.ko...${NC}"
	make modules

	if [ -f "amdxdna.ko" ]; then
		echo -e "${GREEN}✓ ARM64 AUX driver built successfully!${NC}"
		ls -lh amdxdna.ko
		file amdxdna.ko
		cp amdxdna.ko amdxdna_arm64_aux.ko
		echo -e "${GREEN}Saved as: amdxdna_arm64_aux.ko${NC}"
		copy_dep_modules_for_target
		print_insmod_help
	else
		echo -e "${RED}✗ ARM64 build failed!${NC}"
		return 1
	fi
}

clean_all() {
	echo -e "${YELLOW}Cleaning all build artifacts...${NC}"
	make clean 2>/dev/null || true
	rm -f config_kernel.h
	rm -f amdxdna_x86_64_pci.ko
	rm -f amdxdna_arm64_aux.ko
	echo -e "${GREEN}✓ Clean complete${NC}"
}

case "${1:-both}" in
	x86) build_x86 ;;
	arm64) build_arm64 ;;
	both)
		build_x86
		echo ""
		build_arm64
		echo ""
		echo -e "${GREEN}========================================${NC}"
		echo -e "${GREEN}Build Summary${NC}"
		echo -e "${GREEN}========================================${NC}"
		[ -f "amdxdna_x86_64_pci.ko" ] && ls -lh amdxdna_x86_64_pci.ko
		[ -f "amdxdna_arm64_aux.ko" ] && ls -lh amdxdna_arm64_aux.ko
		;;
	clean) clean_all ;;
	-h|--help|help) print_usage ;;
	*)
		echo -e "${RED}Error: Unknown option '$1'${NC}"
		print_usage
		exit 1
		;;
esac

echo -e "${GREEN}Done!${NC}"
