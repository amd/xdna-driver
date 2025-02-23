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

### Steps to create release build DEB package:

``` bash
cd <root-of-source-tree>/build

# If you do not have XRT installed yet:
cd xrt/build
./build.sh -npu -opt
# To adapt according to your OS & version
sudo apt reinstall ./Release/xrt_202510.2.19.0_22.04-amd64-base.deb
cd ../../build

# Start XDNA driver release build
./build.sh -release

# Create DEB package for existed release or debug build.
./build.sh -package
# To adapt according to your OS & version
sudo apt reinstall ./Release/xrt_plugin.2.19.0_ubuntu22.04-x86_64-amdxdna.deb
```
You will find `xrt_plugin\*-amdxdna.deb` in Release/ folder. This package includes:
* The `.so` library files, which will be installed into `/opt/xilinx/xrt/lib` folder
* The XDNA driver and DKMS script, which build, install and load
  `amdxdna.ko` driver when installing the .DEB package on target machine
* The firmware binary files, which will be installed to `/usr/lib/firmware/amdnpu` folder

## Test

If you haven't read [System Requirements](#system-requirements), double check it.

``` bash
source /opt/xilinx/xrt/setup.sh
cd <root-of-source-tree>/build

# Build the test program
./build.sh -example

# Run the test
./example_build/example_noop_test ../tools/bins/1502_00/validate.xclbin
```

## Q&A

### Q: I want to debug my application, how to build library with `-g`?

A: We have debug version of library, which is compiled with `-g` option. You can run `./build.sh -debug` or `./build.sh`.
To create a debug DEB package, run `./build.sh -package` afterward.

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

# Open /etc/security/limits.conf, add below two lines.
# * soft  memlock <max-size-in-kbytes>
# * hard  memlock <max-size-in-kbytes>
#
# See comments of the file for the meaning of each column.

# Reboot the machine, then check if the limite is changed
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
