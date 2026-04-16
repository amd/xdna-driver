#!/bin/bash

ABS_PATH=$(pwd)
XDNA_REPO_DIR=`readlink -f ${ABS_PATH}/..`
yocto_path="$ABS_PATH/../../yocto/edf"
MACHINE="amd-cortexa78-mali-common"
RPM_ARCH_DIR="amd_cortexa78_mali_common"

YOCTO_REPO_URL="${YOCTO_REPO_URL:-https://github.com/Xilinx/yocto-manifests.git}"
YOCTO_BRANCH="${YOCTO_BRANCH:-refs/tags/amd-edf-rel-v25.11}"
MANIFEST_FILE="${MANIFEST_FILE:-default-edf.xml}"
set -e

error()
{
    echo "ERROR: $1" 1>&2
    usage_and_exit 1
}
usage()
{
    echo "Usage: $PROGRAM [options] "
    echo "  options:"
    echo "          -help                           Print this usage"
    echo "          -clean, clean                   Remove build directories, Specify architecture"
    echo ""
}

usage_and_exit()
{
    usage
    exit $1
}

install_repo()
{
    echo "Installing repo...."
    curl https://storage.googleapis.com/git-repo-downloads/repo > repo
    chmod a+x repo
    mkdir -p "$HOME/bin"
    mv repo "$HOME/bin/"
    export PATH="$HOME/bin:$PATH"
}

build_configuration()
{
    cp -rf $ABS_PATH/recipes-hip/* $yocto_path/sources/meta-xilinx/meta-xilinx-core/recipes-xrt/
    cp -rf $ABS_PATH/recipes-kernel/linux/linux-xlnx/* $yocto_path/sources/meta-xilinx/meta-xilinx-core/recipes-kernel/linux/linux-xlnx/
    cp -rf $ABS_PATH/recipes-kernel/linux/linux-xlnx_%.bbappend $yocto_path/sources/meta-xilinx/meta-xilinx-core/recipes-kernel/linux/
    if [ -d "$ABS_PATH/recipes-protobuf" ]; then
        mkdir -p "$yocto_path/sources/meta-xilinx/meta-xilinx-core/recipes-devtools/protobuf"
        cp -rf "$ABS_PATH/recipes-protobuf"/* "$yocto_path/sources/meta-xilinx/meta-xilinx-core/recipes-devtools/protobuf/"
        echo "Copied protobuf recipes to meta-xilinx-core/recipes-devtools/protobuf/"
    else
        echo "WARNING: $ABS_PATH/recipes-protobuf not found; protobuf 3.21.12 will not be added."
    fi
    {
      echo 'TOOLCHAIN_TARGET_TASK:append = " hip-dev"'
      echo 'IMAGE_INSTALL:append = " amdxdna"'
      echo 'BBFILE_PRIORITY_xilinx = "7"'
      echo 'PREFERRED_VERSION_protobuf = "3.21.12"'
      echo 'PREFERRED_VERSION_protobuf-native = "3.21.12"'
      echo 'PREFERRED_VERSION_protobuf-c = "1.4.1"'
    } >> "$yocto_path/build/conf/local.conf"
}

install_recipes()
{
    META_USER_PATH=$yocto_path/sources/meta-xilinx/meta-xilinx-core
    SAVED_OPTIONS_LOCAL=$(set +o)
    set +e
    mkdir -p ${META_USER_PATH}/recipes-xrt/xrt
    mkdir -p ${META_USER_PATH}/recipes-xrt/zocl
    mkdir -p ${META_USER_PATH}/recipes-xrt/amdxdna
    XRT_BB=${META_USER_PATH}/recipes-xrt/xrt/xrt_%.bbappend
    ZOCL_BB=${META_USER_PATH}/recipes-xrt/zocl/zocl_%.bbappend
    AMDXDNA_BB=${META_USER_PATH}/recipes-xrt/amdxdna/amdxdna_git.bb
    grep "inherit externalsrc" $XRT_BB
    if [ $? != 0 ]; then
        echo "inherit externalsrc" > $XRT_BB
        echo "EXTERNALSRC = \"$XDNA_REPO_DIR/\"" >> $XRT_BB
        echo "EXTRA_OECMAKE += \"-DXDNA_VE2=ON -DXRT_EDGE=1 -DXRT_YOCTO=1 -DXRT_ENABLE_HIP=1 -DCMAKE_INSTALL_PREFIX=/usr\"" >> $XRT_BB
        echo 'EXTERNALSRC_BUILD = "${WORKDIR}/build"' >> $XRT_BB
	echo 'OECMAKE_GENERATOR = "Unix Makefiles"' >> $XRT_BB
	echo 'DEPENDS += "virtual/kernel hip systemtap amdxdna"' >> $XRT_BB
	echo 'INSANE_SKIP:${PN} += "arch"' >> $XRT_BB
        echo 'PACKAGE_CLASSES = "package_rpm"' >> $XRT_BB
        echo 'LICENSE = "GPLv2 & Apache-2.0"' >> $XRT_BB
	echo 'LIC_FILES_CHKSUM = "file://LICENSE.amdnpu;md5=ea42c0f38f2d42aad08bd50c822460dc"' >> $XRT_BB
    fi

    grep "inherit externalsrc" $ZOCL_BB
    if [ $? != 0 ]; then
        echo "inherit externalsrc" > $ZOCL_BB
        echo "EXTERNALSRC = \"$XDNA_REPO_DIR/xrt/src/runtime_src/core/edge/drm/zocl\"" >> $ZOCL_BB
        echo "EXTERNALSRC_BUILD = \"$XDNA_REPO_DIR/xrt/src/runtime_src/core/edge/drm/zocl\"" >> $ZOCL_BB
        echo 'PACKAGE_CLASSES = "package_rpm"' >> $ZOCL_BB
        echo 'LICENSE = "GPLv2 & Apache-2.0"' >> $ZOCL_BB
        echo 'LIC_FILES_CHKSUM = "file://LICENSE;md5=7d040f51aae6ac6208de74e88a3795f8"' >> $ZOCL_BB
        if [[ ! -z $XRT_VERSION_PATCH ]]; then
            echo "EXTRA_OEMAKE += \"XRT_VERSION_PATCH=$XRT_VERSION_PATCH\"" >> $ZOCL_BB
        fi
    fi
    
    grep "inherit externalsrc" $AMDXDNA_BB
    if [ $? != 0 ]; then
        echo 'SUMMARY = "Xilinx Runtime(XRT) driver module"' >> "$AMDXDNA_BB"
        echo 'DESCRIPTION = "Xilinx Runtime driver module provides aie management and compute unit schedule"' >> "$AMDXDNA_BB"
        echo '' >> "$AMDXDNA_BB"
        echo 'LICENSE = "GPL-2.0-or-later & Apache-2.0"' >> "$AMDXDNA_BB"
        echo 'LIC_FILES_CHKSUM = "file://../../../LICENSE.amdnpu;md5=ea42c0f38f2d42aad08bd50c822460dc"' >> "$AMDXDNA_BB"
        echo '' >> "$AMDXDNA_BB"
        echo 'COMPATIBLE_MACHINE = "zynqmp|versal|versal2|versal-2ve-2vm"' >> "$AMDXDNA_BB"
        echo '' >> "$AMDXDNA_BB"
        echo 'PREFERRED_PROVIDER_virtual/opencl-icd ??= "opencl-icd-loader"' >> "$AMDXDNA_BB"
        echo 'PACKAGECONFIG ??= "${PREFERRED_PROVIDER_virtual/opencl-icd}"' >> "$AMDXDNA_BB"
        echo 'PACKAGECONFIG[ocl-icd] = ",,ocl-icd,ocl-icd"' >> "$AMDXDNA_BB"
        echo 'PACKAGECONFIG[opencl-icd-loader] = ",,opencl-icd-loader,opencl-icd-loader"' >> "$AMDXDNA_BB"
        echo '' >> "$AMDXDNA_BB"
        echo 'DEPENDS = "libdrm opencl-headers virtual/opencl-icd opencl-clhpp boost util-linux git-replacement-native protobuf-native protobuf elfutils libffi rapidjson systemtap libdfx"' >> "$AMDXDNA_BB"
        echo 'RDEPENDS:${PN} = "libdrm bash boost-system boost-filesystem systemtap kmod"' >> "$AMDXDNA_BB"
        echo 'PACKAGE_CLASSES = "package_rpm"' >> "$AMDXDNA_BB"
        echo '' >> "$AMDXDNA_BB"
        echo '# Driver version of XDNA. Update this manually when the XRT submodule is updated.' >> "$AMDXDNA_BB"
        echo 'XDNA_DRIVER_VERSION = "2.23.0"' >> "$AMDXDNA_BB"
        echo 'PV = "${XDNA_DRIVER_VERSION}"' >> "$AMDXDNA_BB"
        echo 'EXTRA_OEMAKE += "XDNA_DRIVER_VERSION=${XDNA_DRIVER_VERSION}"' >> "$AMDXDNA_BB"
        echo "TARGET_CXXFLAGS:append = \"\${@bb.utils.contains('PACKAGECONFIG', 'opencl-icd-loader', ' -DOPENCL_ICD_LOADER=on', '', d)}\"" >> "$AMDXDNA_BB"
        echo 'EXTRA_OEMAKE += "XDNA_BUS_TYPE=of"' >> "$AMDXDNA_BB"
        echo '' >> "$AMDXDNA_BB"
        echo 'inherit module externalsrc' >> "$AMDXDNA_BB"
        echo '' >> "$AMDXDNA_BB"
        echo "EXTERNALSRC = \"$XDNA_REPO_DIR/src/driver/amdxdna/\"" >> "$AMDXDNA_BB"
        echo 'EXTERNALSRC_BUILD = "${EXTERNALSRC}"' >> "$AMDXDNA_BB"
        echo 'MODULES_MODULE_SYMVERS_LOCATION = "driver/amdxdna"' >> "$AMDXDNA_BB"
        echo '' >> "$AMDXDNA_BB"
        echo 'do_install() {' >> "$AMDXDNA_BB"
        echo '    install -d ${D}${nonarch_base_libdir}/modules/${KERNEL_VERSION}/extra/' >> "$AMDXDNA_BB"
        echo '    install -m 0644 ${S}/build/driver/amdxdna/amdxdna.ko ${D}${nonarch_base_libdir}/modules/${KERNEL_VERSION}/extra/' >> "$AMDXDNA_BB"
        echo '}' >> "$AMDXDNA_BB"
        echo '' >> "$AMDXDNA_BB"
        echo 'MODULE_NAME = "amdxdna"' >> "$AMDXDNA_BB"
        echo 'KERNEL_MODULE_AUTOLOAD += "amdxdna"' >> "$AMDXDNA_BB"
        echo '' >> "$AMDXDNA_BB"
        echo 'pkg_postinst:${PN}() {' >> "$AMDXDNA_BB"
        echo '    if [ -n "$D" ]; then' >> "$AMDXDNA_BB"
        echo '        exit 0' >> "$AMDXDNA_BB"
        echo '    fi' >> "$AMDXDNA_BB"
        echo '    if command -v depmod >/dev/null 2>&1; then' >> "$AMDXDNA_BB"
        echo '        depmod -a 2>/dev/null || true' >> "$AMDXDNA_BB"
        echo '    fi' >> "$AMDXDNA_BB"
        echo '    rmmod amdxdna 2>/dev/null || true' >> "$AMDXDNA_BB"
        echo '    modprobe amdxdna 2>/dev/null || true' >> "$AMDXDNA_BB"
        echo '}' >> "$AMDXDNA_BB"

    fi
    eval "$SAVED_OPTIONS_LOCAL"
}

clean=0
while [ $# -gt 0 ]; do
    case $1 in
        -help )
            usage_and_exit 0
            ;;
        -clean | clean )
            clean=1
            ;;
        --* | -* )
            error "Unregognized option: $1"
            ;;
        * )
            error "Unregognized option: $1"
            ;;
    esac
    shift
done

if [[ $clean == 1 ]]; then
    echo "Cleaning build directory"
    echo "/bin/rm -rf $yocto_path"
    /bin/rm -rf "$yocto_path"
    exit 0
fi

#Check if repo is installed and get its version
if ! command -v repo &> /dev/null; then
    echo "Repo command not found. Installing repo..."
    install_repo
elif [[ $(repo --version 2>&1 | grep -oP 'repo launcher version \K[0-9.]+') < 2.5 ]]; then
    echo "Repo version is less than 2.5. Reinstalling repo..."
    install_repo
fi

if [ -f "$yocto_path/edf-init-build-env" ]; then
    cd $yocto_path
    source edf-init-build-env
else
    
    git submodule update --init --recursive --force
    mkdir -p $yocto_path
    cd $yocto_path
    echo "repo init -u $YOCTO_REPO_URL -b $YOCTO_BRANCH -m $MANIFEST_FILE"
    yes ""| repo init -u $YOCTO_REPO_URL -b $YOCTO_BRANCH -m $MANIFEST_FILE
    repo sync
    source edf-init-build-env

    install_recipes
    build_configuration
fi

if MACHINE=$MACHINE bitbake xrt; then
    echo "bitbake xrt succeeded."

    # Republish amdxdna RPMs into tmp/deploy/rpm (externalsrc uses SSTATE_SKIP_CREATION;
    # stamps can otherwise skip do_package_write_rpm while deploy/rpm is empty).
    MACHINE=$MACHINE bitbake amdxdna -c package_write_rpm -f

    rm -rf "$yocto_path/rpms"
    mkdir -p "$yocto_path/rpms"

    cp -rf "$yocto_path/build/tmp/deploy/rpm/cortexa72_cortexa53/xrt-"* "$yocto_path/rpms/"
    cp -rf "$yocto_path/build/tmp/deploy/rpm/$RPM_ARCH_DIR/amdxdna-"* "$yocto_path/rpms/"
    cp -rf "$yocto_path/build/tmp/deploy/rpm/$RPM_ARCH_DIR/zocl-"* "$yocto_path/rpms/"
    cp -rf "$yocto_path/build/tmp/deploy/rpm/$RPM_ARCH_DIR/kernel-"* "$yocto_path/rpms/"

    cd $yocto_path/rpms
    echo "Creating $yocto_path/rpms/install_xrt.sh"
    xrt_dbg=`ls xrt-dbg* zocl-dbg* amdxdna-dbg*`

    rpm_list=$(ls *.rpm)
    for dbg in $xrt_dbg; do
            rpm_list=$(echo "$rpm_list" | sed -e "s|$dbg||g")
    done
    # Remove any empty entries and extra spaces
    final_rpms=$(echo $rpm_list | xargs)

    echo dnf --disablerepo=\"*\" install -y $final_rpms > $yocto_path/rpms/install_xrt.sh
    echo dnf --disablerepo=\"*\" reinstall -y $final_rpms > $yocto_path/rpms/reinstall_xrt.sh

    echo "RPMs copied to $yocto_path/rpms"
    cd -
else
    echo "bitbake xrt failed"
fi
