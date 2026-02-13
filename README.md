# AMD XDNA™️ Driver for Linux®️
This repository is for the AMD XDNA™️ Driver (amdxdna.ko) for Linux®️ and XRT SHIM library development.

## Table of Contents
- [Introduction](#introduction)
- [System Requirements](#system-requirements)
- [Linux compilation and installation](#linux-compilation-and-installation)
- [Clone](#clone)
- [Build](#build)
- [Test](#test)
- [Q&A](#qa)
- [Contributor Guidelines](#contributor-guidelines)

## Introduction
This repository is for supporting XRT on AMD XDNA devices. From this repository, you can build a XRT plugin DEB package.
On a machine with XDNA device, with both XRT and XRT plugin packages installed, user can start using XDNA device on Linux.

## System Requirements
To run AI applications, your system needs
* Processor:
  - To run AI applications (test machine): RyzenAI processor
  - To build this repository (build machine): Any x86 processors, but recommend AMD processor :wink:
* Operating System:
  - Ubuntu >= 22.04
  - Arch Linux
* Linux Kernel: v6.10 or above. (See [Linux compilation and installation](#linux-compilation-and-installation))
  - Due to Linux API change, XDNA driver doesn't always keep supporting old version.
* Installed XRT base package (or you can install it along the
  following recipe)
  - To make sure the XRT base package works with the plug-in package, better build it from `xrt` submodule in this repo (`<root-of-source-tree>/xrt`)
  - Refer to https://github.com/Xilinx/XRT for more detailed information.

## Linux compilation and installation

### Ubuntu 25.04

Ubuntu 25.04 includes [Linux kernel 6.14](https://kernelnewbies.org/Linux_6.14) that incorporates the amdxdna driver for AMD NPUs :partying_face:. 

> The XRT SHIM library is still needed from this repository.

### Ubuntu 24.10

Ubuntu 24.10 includes Linux kernel 6.11 that meets the requirements for the xdna-driver. 

### Ubuntu 24.04

If you are using Ubuntu 24.04 you may need to update the Linux kernel. You can update to Linux 6.11 by installing the Hardware Enablement (HWE) stack:

  ```bash
  sudo apt update 
  sudo apt install --install-recommends linux-generic-hwe-24.04
  sudo reboot
  ```

### Ubuntu 22.04

Since Linux v6.10 offically supports AMD IOMMU SVA, we can work with upstream Linux kernel source.
If your system has Linux v6.10 or above installed, check if `CONFIG_AMD_IOMMU` and `CONFIG_DRM_ACCEL` are set. If not, the system is not good for XDNA driver.

If you want to manually build Linux kernel, follow below steps.
```  bash
# Assuming you have knowledge of kernel compilation,
# this is just refreshing up a few key points.

# Clone Linux source code from your favorite repository, for example
git clone --depth=1 --branch v6.10 git://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git

# Usually, when people compile kernel from source code, they use current config
cp /boot/config-`uname -r` <your_build_dir>/.config   # (Option step, if you know how to do it better)
# Open <your_build_dir>/.config and add "CONFIG_DRM_ACCEL=y" #Required by XDNA Driver
# Or run instead
scripts/config --file .config --enable DRM_ACCEL
scripts/config --file .config --enable AMD_IOMMU # Option step, if you know this is not set

# Use below command to build kernel packages. Once build is done, DEB packages are at the parent directory of <your_build_dir>
make -j `nproc` bindeb-pkg
# The exact names will depend on your configuration
sudo apt reinstall ../linux-headers-6.10.0_6.10.0-1_amd64.deb ../linux-image-6.10.0_6.10.0-1_amd64.deb ../linux-libc-dev_6.10.0-1_amd64.deb
```

## Clone

```
git clone git@github.com:amd/xdna-driver.git
cd <root-of-source-tree>
# get code for submodules
git submodule update --init --recursive
```

## Build

### Prerequisite

* If this is your first time building this module,
  follow below steps to resolve the dependencies (or at least look at
  the file content if you're not on a distro with apt-get)
``` bash
#requires root permissions to run the script
sudo su
cd <root-of-source-tree>
./tools/amdxdna_deps.sh
# exit from root
exit
```

### Steps to create release build DEB package (Ubuntu/Debian):

``` bash
cd <root-of-source-tree>/build

# If you do not have XRT installed yet:
cd xrt/build
./build.sh -npu -opt
# To adapt according to your OS & version
sudo apt reinstall ./Release/xrt_202510.2.19.0_22.04-amd64-base.deb
cd ../../build

# Start XDNA driver release build and create release DEB package
./build.sh -release

# To adapt according to your OS & version
sudo apt reinstall ./Release/xrt_plugin.2.19.0_ubuntu22.04-x86_64-amdxdna.deb
```

### Steps to create release build packages (Arch Linux):

``` bash
cd <root-of-source-tree>

# Install dependencies (requires sudo)
sudo ./tools/amdxdna_deps.sh

# Get submodules
git submodule update --init --recursive

# Build XRT
cd xrt/build
./build.sh -npu -opt

# Build and install XRT packages using pacman
# PKGBUILDs are in xrt/build/arch/
cd arch
makepkg -p PKGBUILD-xrt-base
sudo pacman -U xrt-base-*.pkg.tar.zst

makepkg -p PKGBUILD-xrt-npu
sudo pacman -U xrt-npu-*.pkg.tar.zst

# Build XDNA driver
cd ../../../build
./build.sh -release

# Build and install XDNA plugin package
cd arch
makepkg -p PKGBUILD-xrt-plugin
sudo pacman -U xrt-plugin-amdxdna-*.pkg.tar.zst

# Configure memory limits (required for NPU access)
# Using limits.d drop-in file (survives package upgrades)
sudo mkdir -p /etc/security/limits.d
sudo tee /etc/security/limits.d/99-amdxdna.conf > /dev/null << 'EOF'
* soft memlock unlimited
* hard memlock unlimited
EOF

# Log out and log back in (or reboot) for memory limit changes to take effect
```

**Note for Arch Linux users**: The build system generates `.tar.gz` packages which are repackaged into proper Arch packages (`.pkg.tar.zst`) using the provided PKGBUILDs:
- XRT packages: `xrt/build/arch/` (PKGBUILD-xrt-base, PKGBUILD-xrt-npu)
- XDNA driver: `build/arch/` directory (PKGBUILD-xrt-plugin)

This ensures proper integration with pacman for installation, upgrades, and removal.

You will find `xrt_plugin.<version>_<distro-version>-<arch>-amdxdna.deb` (Ubuntu/Debian) or `xrt_plugin.<version>_-<arch>-amdxdna.tar.gz` (Arch Linux) in the `Release/` folder. This package includes:
* The `.so` library files, which will be installed into `/opt/xilinx/xrt/lib` folder
* The XDNA driver and DKMS script, which build, install and load
  `amdxdna.ko` driver when installing the .DEB package on target machine
* The firmware binary files, which will be installed to `/usr/lib/firmware/amdnpu` folder

## Test

If you haven't read [System Requirements](#system-requirements), double check it.

``` bash
source /opt/xilinx/xrt/setup.sh
xrt-smi validate
```

## Q&A

### Q: I want to debug my application, how to build library with `-g`?

A: We have debug version of library, which is compiled with `-g` option. You can run `./build.sh -debug` or `./build.sh` which should also create debug DEB package.

### Q: I'm developing amdxdna.ko driver module. How to enable XDNA_DBG() print?

A: XDNA_DBG() relies on Linux's CONFIG_DYNAMIC_DEBUG framework, see Linux's [dynamic debug howto page](https://www.kernel.org/doc/html/v6.8/admin-guide/dynamic-debug-howto.html) for details.
TL;DR, run `sudo insmod amdxdna.ko dyndbg=+pf` to enable XDNA_DBG() globally, where +pf means enable debug printing and print the function name.

### Q: When install XRT plugin DEB package, apt-get/dpkg tool failed. What to do next?

A: Create a debug DEB package, see above question. Then install debug DEB package in your environment. This time, you will have more verbose log. Share this log with us.

### Q: Can I use NPU for accelerate ML training?

A: You can use NPU to accelerate ML inference. But NPU is not designed for ML training.

### Q: How to allocate huge size BO?

A: There is no limit for BO size from the XRT and NPU device.
An application can fail to allocate a huge BO, once it hits the Linux resource limit.
In our test, the "max locked memory" is the key. You can follow below steps to check and change configure.
``` bash
ulimit -l # The result is in kbytes

# Create a drop-in file in /etc/security/limits.d/ (survives package upgrades)
sudo mkdir -p /etc/security/limits.d
sudo tee /etc/security/limits.d/99-amdxdna.conf > /dev/null << 'EOF'
* soft memlock <max-size-in-kbytes>
* hard memlock <max-size-in-kbytes>
EOF
# Use "unlimited" instead of a numeric value if unsure

# Log out and log back in (or reboot), then check if the limit changed
ulimit -l
```

## Contributor Guidelines
1. Read [Getting Started](#getting-started)
2. Read [System Requirements](#system-requirements)
3. Run Linux checkpatch.pl before commit and create pull request, see [Checkpatch](#checkpatch)

### Checkpatch
* There is a pre-commit script to run checkpatch.pl automatically.
``` bash
# How to setup the auto pre-commit check
cd <workspace of this repo>/
cp tools/pre-commit .git/hooks/
```
`git commit` will reject the commit if error/warning is found, until you make `checkpatch.pl` happy.

* There is shell script that scan all the source code in a folder
``` bash
cd <workspace of this repo>/
./tools/codingsty_check.sh <DIR>
```

#testing CI
