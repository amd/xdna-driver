# AMD XDNA Driver for Linux
This repository is for the AMD XDNA Driver (amdxdna.ko) for Linux and XRT SHIM library development.

## Table of Contents
- [Introduction](#introduction)
- [System Requirements](#system-requirements)
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
  - To run AI applications (test machine): RyzenAI processor, example: Phoenix/Strix
  - To build this repository (build machine): Any x86 processors, but recommend AMD processor :wink:
* Operating System: Ubuntu 22.04
* Linux Kernel: v6.7 with IOMMU SVA support (see below)
* Installed XRT base package
  - To make sure the XRT base package works with the plug-in package, better build it from xrt submodule in this repo (<root-of-source-tree>/xrt)
  - Refer to https://github.com/Xilinx/XRT for more detailed information.

*Important*: IOMMU SVA in Linux kernel support is required.

You need to manually build 6.7 Linux kernel packages by following below steps.

The 6.7 Linux kernel with SVA source code can be downloaded from _iommu_sva_v4_v6.7-rc8 branch_ on https://github.com/AMDESE/linux
``` bash
# Assuming you have knowledge of kernel compile, this just refreshing up a few key points.

git clone git@github.com:AMDESE/linux.git
git checkout iommu_sva_v4_v6.7-rc8
cd linux/

# Usually, when people compile kernel from source code, they use current config.
cp /boot/config-`uname -r` <your_build_dir>/.config   # (Option step, if you know how to do it better)
# Open <your_build_dir>/.config and add "CONFIG_DRM_ACCEL=y" # Required by XDNA Driver

# Use below command to build kernel packages. Once build is done, DEB packages are at the parent directory of <your_build_dir>
make ARCH=x86 O=<your_build_dir> bindeb-pkg -j4
```

## Clone
This repository has src/xrt as a git submodule. The path to XRT is set up to clone as ssh, so you need a public key registered with your GitHub.com account.
```
% git clone git@github.com:amd/xdna-driver.git
% cd <root-of-source-tree>
# get code for submodules
% git submodule update --init --recursive
```

## Build
### Prerequisite
* If this is your first time building this module, follow below steps to resolve the dependencies.
``` bash
sudo su 	#requires root permissions to run the script
cd <root-of-source-tree>
./xrt/src/runtime_src/tools/scripts/xrtdeps.sh
exit  		#exit from root
```

### Steps to create release build DEB package:
``` bash
cd <root-of-source-tree>/build

# Start release build
./build.sh -release

# Create DEB package for existed release or debug build.
./build.sh -package
```
You will find "xrt_plugin\*-amdxdna.deb" in Release/ folder. This package includes below content:
* The .so library files, which will be install to /opt/xilinx/xrt/libs folder
* The XDNA driver and DKMS script, which build, install and load amdxdna.ko driver when install DEB package on target machine
* The firmware binary files, which will be installed to /lib/firmware/amdipu folder

## Test
If you haven't read [System Requirements](#system-requirements), double check it.

``` bash
cd <root-of-source-tree>/build

# Build the test program
./build.sh -example

# Run the test (test xclbins can be found under /lib/firwmare/amdipu/<deviceID>/validate.xclbin
./example_build/example_noop_test <path-to-xclbin>
```

## Q&A
### Q: I want to debug my application, how to build library with '-g'?

A: We have debug version of library, which is compiled with '-g' option. You can run `./build.sh -debug` or `./build.sh`.
To create a debug DEB package, run `./build.sh -package` afterward.

### Q: When build -release or -debug, can I specify linux kernel version different than currently running linux kernel?

A: Yes. For example, if you have 6.6-rc1 linux header install on your build machine. Run `./build.sh [-debug|-release] -kernel_ver 6.6-rc1`

### Q: I'm developing amdxdna.ko driver module. How to enable XDNA_DBG() print?

A: XDNA_DBG() relies on Linux's CONFIG_DYNAMIC_DEBUG framework, see Linux's [dynamic debug howto page](https://www.kernel.org/doc/html/v6.5/admin-guide/dynamic-debug-howto.html) for details.
TL;DR, run `sudo insmod amdxdna.ko dyndbg==p` to enable XDNA_DBG() globally.

### Q: When install XRT plugin DEB package, apt-get/dpkg tool failed. What to do next?

A: Create a debug DEB package, see above question. Then install debug DEB package in your environment. This time, you will have more verbose log. Share this log with us.

### Q: I see "Failed to load xclbin firmware" error in dmesg. How to fix this?

A: In amdxdna driver, it will not directly use the xclbin passed from application. Instead, it loads verified xclbin from /lib/firmware/amdipu/ directory.
The driver will check if the UUID of the xclbin from application and firmware directory matched. If this match process failed, you will see this error.

### Q: I need to test a unverified xclbin . I know what I'm doing. Can I get rid of the "Failed to load xclbin firmware" error?

A: Yes. Make sure you have root privilege of the system. Follow below steps,
``` bash
# Assume you already have xrt_plugin DEB package installed
# You need root privilege to install firmware
sudo bash

source /opt/xilinx/xrt/setup.sh

# List supported device(s)
/opt/xilinx/xrt/amdxdna/setup_xclbin_firmware.sh -list

# Assume adding an unsigned xclbin on Phoenix, run
/opt/xilinx/xrt/amdxdna/setup_xclbin_firmware.sh -dev Phoenix -xclbin <test>.xclbin

# When xrt_plugin package is removed, it will be automaticlly cleaned up.
# If setup <test>.xclbin for a device twice, the previous one will be overwritten.
```

## Contributor Guidelines
1. Read [Getting Started](#getting-started)
2. Read [System Requirements](#system-requirements)
3. Run Linux checkpatch.pl before commit and create pull request, see [Checkpatch](#checkpatch)

### Checkpatch
There is a pre-commit script for this purpose.
``` bash
cp amd-aie/tools/pre-commit <root-of-source-tree>/.git/hooks/
```
`git commit` will reject the commit if error/warning is found, until you make checkpatch.pl happy.
