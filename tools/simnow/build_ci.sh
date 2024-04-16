#!/bin/bash

# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2018-2022 Xilinx, Inc. All rights reserved.

IS_UBUNTU=0
IS_CENTOS=0
BUILD_SIMNOW=0
BUILD_QEMU=0
BUILD_VF=0
BUILD_CLEAN=0
BUILD_HELLO=0
BUILD_VERBOSE=0
IOMMU_MODE=1
HOST_IP="192.168.122.76"

ROOT_DIR=`pwd`
BUILD_CONF_FILE="build_ci.json"
BUILD_DIR="build_dir"
BUILD_LOG="build.log"
CURRENT_DIR=$(dirname "$0")
BASE_NAME=$(basename "$0")

BUILD_DATE=`date +%F-%T`
BUILD_DATE_FILE="$ROOT_DIR/$BUILD_DIR/build_date.txt"

record_test_start()
{
	begin_seconds=$SECONDS
}

record_test_end()
{
	SECS=$((SECONDS - begin_seconds))
	MINS=$((SECS / 60))
	HOURS=$((SECS / 3600))

	if [ $HOURS -gt 0 ];then
		echo "==== TOOK $HOURS hours and $((MINS % 60)) minutes ===="
	elif [ $MINS -gt 0 ];then
		echo "==== TOOK $MINS minutes and $((SECS % 60)) seconds ===="
	else
		echo "==== TOOK $SECS seconds ===="
	fi
}

check_result()
{
	typeset log="$1"
	typeset ret="$2"

	if [ $2 -ne 0 ];then
		dump_dmesg
		echo "=== FAIL: $1 err: $2"
		exit 1;
	else
		echo "=== PASS: $1"
	fi
}

download_http_file()
{
	echo "=== ${FUNCNAME[0]} ==="

	typeset DCMD="wget"

	which axel
	if [ $? -ne 0 ];then
		apt install axel
	fi

	which axel
	if [ $? -eq 0 ];then
		DCMD="axel -n 4"
	fi

	echo "Using $DCMD to download"
	$DCMD $1

	check_result "$DCMD" $?
}

# TODO: make dump_trace working
dump_trace()
{
	echo "=== ${FUNCNAME[0]} ==="
	echo "#!/bin/bash" > /tmp/trace.sh
	echo "cat /sys/kernel/debug/accel/0/trace_log &" >> /tmp/trace.sh
	echo "PID1=\$!" >> /tmp/trace.sh
	echo "sleep 2" >> /tmp/trace.sh
	echo "kill -s 2 \$PID1" >> /tmp/trace.sh

	scp /tmp/trace.sh root@$HOST_IP:/root
	ssh root@$HOST_IP bash -x /root/trace.sh
}

check_dmesg_warning()
{
	echo "=== ${FUNCNAME[0]} ==="
	typeset dmesg_ok=0

	ssh root@$HOST_IP dmesg | grep -e "WARNING:" -e "RIP:" -e "BUG "
	if [ $? -eq 0 ];then
		print_warn "dmesg has kernel oops warning!!! please check dmesg for details"
		dmesg_ok=1
	fi

	ssh root@$HOST_IP "dmesg -l err,crit,alert,emerg" > /tmp/fatal_error.log
	FATAL_ERROR=`cat /tmp/fatal_error.log | wc -l`
	if [ $FATAL_ERROR != "0" ];then
		print_warn "dmesg has fatal error conditions below ...\n"
		cat /tmp/fatal_error.log
		dmesg_ok=1
	fi

	if [ $dmesg_ok == 0 ];then
		echo "Congratulations! no critical error in dmesg"
	else
		exit 1
	fi
}

check_memory_leak()
{
	echo "=== ${FUNCNAME[0]} ==="

	ssh root@$HOST_IP "echo scan > /sys/kernel/debug/kmemleak"
	ssh root@$HOST_IP "cat /sys/kernel/debug/kmemleak" > /tmp/memleak.log
	MEMLEAK=`cat /tmp/memleak.log | wc -l`
	if [ $MEMLEAK != "0" ];then
		print_warn "found memory leak"
		cat /tmp/memleak.log
		exit 1
	else
		echo "Congratulations! no memory leak"
	fi
}

dump_dmesg()
{
	echo "=== check === /tmp/dmesg_${BUILD_DATE}.log"
	ssh root@$HOST_IP dmesg > /tmp/dmesg_${BUILD_DATE}.log

	check_dmesg_warning
#check_memory_leak
}

pgrep_wait()
{
	# wait until $1 is up
	while :; do
		pgrep $1
		if [ $? -ne 0 ];then
			echo "WARN: wait for running $1 ... Ctrl + C to quite"
		else
			break
		fi
		sleep 10
	done
}

print_warn()
{
	printf "\x1b[5m\x1b[31m $1 \x1b[0m!!! "
}

dir_exists()
{
	if [ -z $1 ] || [ ! -d $1 ];then
		echo "ERR: \"$1\" does not exist!!!"
		if  [ -z $BUILD_CONFIG ];then
			print_warn "NOTE"
			echo "seems mandatory --config is not provided, please see Usage:"
			usage
		fi
		exit 1
	fi
}

file_exists()
{
	if [ ! -f $1 ];then
		echo "ERR: \"$1\" does not exist!!!"
		exit 1
	fi
}

build_clean() {
	typeset start_seconds=$SECONDS

	echo "=== don't remove any files in $CONF_INSTALL_DIR, just kill simnow and qemu ==="
	pkill -9 qemu;pkill -9 simnow
	pkill -9 build_ci.sh

	echo "=== build_clean Took: $((SECONDS - start_seconds)) S"
}

grep_file()
{
	typeset name="$1"
	typeset file="$2"
	grep -w "$name" ${file} |grep -oP '".*?"'|tail -1|tr -d '"'
}

grep_yes()
{
	grep -w "yes" ${PLATFORM_FILE} |grep -oP '".*"'|cut -d ":" -f1|tr -d '"'
}

load_build_info()
{
	echo "=== ${FUNCNAME[0]} ==="

	if [ ! -z "$1" ];then
		BUILD_CONF_FILE="$1"
	fi

	if [ -f $BUILD_CONF_FILE ];then
		echo "build conf file is $BUILD_CONF_FILE"
	else
		echo "FAIL: cannot find $BUILD_CONF_FILE"
		exit 1	
	fi

	CONF_INSTALL_ART=`grep_file "CONF_INSTALL_ART" ${BUILD_CONF_FILE}`
	CONF_INSTALL_DOCKER=`grep_file "CONF_INSTALL_DOCKER" ${BUILD_CONF_FILE}`
	CONF_INSTALL_DOCKER_NAME=`grep_file "CONF_INSTALL_DOCKER_NAME" ${BUILD_CONF_FILE}`
	CONF_INSTALL_QEMU_UT22=`grep_file "CONF_INSTALL_QEMU_UT22" ${BUILD_CONF_FILE}`
	CONF_INSTALL_QEMU_UT20=`grep_file "CONF_INSTALL_QEMU_UT20" ${BUILD_CONF_FILE}`
	CONF_INSTALL_QEMU_RHEL7=`grep_file "CONF_INSTALL_QEMU_RHEL7" ${BUILD_CONF_FILE}`
	CONF_INSTALL_QCOW2=`grep_file "CONF_INSTALL_QCOW2" ${BUILD_CONF_FILE}`
	CONF_INSTALL_SIMNOW=`grep_file "CONF_INSTALL_SIMNOW" ${BUILD_CONF_FILE}`
	CONF_INSTALL_MPAIE=`grep_file "CONF_INSTALL_MPAIE" ${BUILD_CONF_FILE}`
	CONF_INSTALL_CERT=`grep_file "CONF_INSTALL_CERT" ${BUILD_CONF_FILE}`
	CONF_INSTALL_AMDAIE=`grep_file "CONF_INSTALL_AMDAIE" ${BUILD_CONF_FILE}`
	CONF_INSTALL_DIR=`grep_file "CONF_INSTALL_DIR" ${BUILD_CONF_FILE}`
	CONF_INSTALL_HOST_IP=`grep_file "CONF_INSTALL_HOST_IP" ${BUILD_CONF_FILE}`

	echo "===================================================="
	echo "ART: $CONF_INSTALL_ART"
	echo "DOCKER: $CONF_INSTALL_DOCKER"
	echo "DOCKER_NAME: $CONF_INSTALL_DOCKER_NAME"
	echo "QEMU_UT22: $CONF_INSTALL_QEMU_UT22"
	echo "QEMU_UT20: $CONF_INSTALL_QEMU_UT20"
	echo "QEMU_RHEL7: $CONF_INSTALL_QEMU_RHEL7"
	echo "QCOW2 VM: $CONF_INSTALL_QCOW2"
	echo "SIMNOW: $CONF_INSTALL_SIMNOW"
	echo "MPAIE: $CONF_INSTALL_MPAIE"
	echo "CERT: $CONF_INSTALL_CERT"
	echo "AMDAIE: $CONF_INSTALL_AMDAIE"
	echo "DIR: $CONF_INSTALL_DIR"
	echo "HOST_IP: $CONF_INSTALL_HOST_IP"
	echo "===================================================="

	if [ -z $CONF_INSTALL_HOST_IP ];then
		HOST_IP=CONF_INSTALL_HOST_IP
	fi

	dir_exists $CONF_INSTALL_ART
	dir_exists $CONF_INSTALL_DIR

	AVAIL_SPACE=`df --output=avail $CONF_INSTALL_DIR |sed 1d`
	NEED_SPACE=$(( 100 * 1024 * 1024 ))
	if [ $AVAIL_SPACE -lt $NEED_SPACE ];then
		echo "need: $NEED_SPACE, avail: $AVAIL_SPACE"
		echo "FAIL: no enough space in $CONF_INSTALL_DIR"
		exit 1
	fi
	echo "avail space: $AVAIL_SPACE"

}

start_simnow()
{
	echo "=== ${FUNCNAME[0]} ==="

	echo "We kill all simnow and qemu for cleaner setup"
	pkill -9 simnow; pkill -9 qemu

	if [ $IOMMU_MODE == 2 ];then
		echo "=== enable hugepage ==="
		echo always > /sys/kernel/mm/transparent_hugepage/enabled
		echo always > /sys/kernel/mm/transparent_hugepage/defrag

		cat /sys/kernel/mm/transparent_hugepage/enabled |grep -w '\[always\]'
		check_result "HOST hugepage should be set to [always]" $?
		cat /sys/kernel/mm/transparent_hugepage/defrag |grep -w '\[always\]'
		check_result "HOST defrag should be set to [always]" $?
	fi

	# precheck env
	if [ $IS_UBUNTU == 1 ];then
		echo "Ubuntu runs simnow inside docker"
		which docker
		if [ $? -ne 0 ];then
			echo "FAIL: no docker found, please install docker!"
			exit 1
		fi

		systemctl start docker
		if [ $? -ne 0 ];then
			echo "FAIL: please start docker daemon by \"systemctl start docker\"!"
			exit 1
		fi

		if [ -f $CONF_INSTALL_ART/$CONF_INSTALL_DOCKER ];then
			if [ ! -f $CONF_INSTALL_DIR/$CONF_INSTALL_DOCKER ];then
				echo "Copy docker into $CONF_INSTALL_DIR ... start"
				cp $CONF_INSTALL_ART/$CONF_INSTALL_DOCKER $CONF_INSTALL_DIR
				ls -lh $CONF_INSTALL_DIR/$CONF_INSTALL_DOCKER
			fi
			docker load -i $CONF_INSTALL_DIR/$CONF_INSTALL_DOCKER
		else
			echo "FAIL: no $CONF_INSTALL_ART/$CONF_INSTALL_DOCKER"
			exit 1
		fi
	else
		echo "Centos/Redhat runs simnow directly without using docker"
	fi

	# check simnow
	cd $CONF_INSTALL_DIR
	SIMNOW=`echo $CONF_INSTALL_SIMNOW |rev|cut -f1 -d "/"|rev|cut -f1 -d "."`

	if [ -f $CONF_INSTALL_DIR/$SIMNOW/simnow ];then
		echo "found existing simnow $CONF_INSTALL_DIR/$SIMNOW"
	else
		echo "get $SIMNOW from artifactory"
		download_http_file $CONF_INSTALL_SIMNOW
		unzip $SIMNOW.zip > /dev/null
	fi
	file_exists $CONF_INSTALL_DIR/$SIMNOW/simnow

	# copy files from artfactory
	# uncomment download_http_file when CERT art is fixed
	yes|rm $CONF_INSTALL_DIR/$SIMNOW/Images/app.elf
	yes|rm $CONF_INSTALL_DIR/$SIMNOW/Images/app.bin
	CERT_ART=`echo $CONF_INSTALL_CERT |rev|cut -f2- -d "/"|rev`
	if [[ $BUILD_HELLO == 1 ]];then
		print_warn "install hello version cert"
#wget $CERT_ART/app.hello.bin -O $CONF_INSTALL_DIR/$SIMNOW/Images/app.bin
		cp $CONF_INSTALL_ART/app_hello.bin $CONF_INSTALL_DIR/$SIMNOW/Images/app.bin
	elif [[ $BUILD_VERBOSE == 1 ]];then
		print_warn "install verbose version cert"
		cp $CONF_INSTALL_ART/app_console.bin $CONF_INSTALL_DIR/$SIMNOW/Images/app.bin
	else
		echo "install cert from $CONF_INSTALL_CERT"
		CERT_ART=`echo $CONF_INSTALL_CERT |rev|cut -f2- -d "/"|rev`
#wget $CERT_ART/app.release.bin -O $CONF_INSTALL_DIR/$SIMNOW/Images/app.bin
#The current CERT has bugs that data is corrupted, using a customized CERT for now
		cp $CONF_INSTALL_ART/app.bin $CONF_INSTALL_DIR/$SIMNOW/Images/app.bin
	fi
	file_exists $CONF_INSTALL_DIR/$SIMNOW/Images/app.bin

	echo "install mpaie from $CONF_INSTALL_MPAIE"
	yes|rm mpaiefw* 2>&1
	yes|rm mpaie.bin 2>&1
	download_http_file $CONF_INSTALL_MPAIE
	yes|unzip mpaiefw*.zip
	cp mpaie.bin $CONF_INSTALL_DIR/$SIMNOW/Images/
	check_result "install mpaie.bin" $?

	# copy files from amdaie
	dir_exists $CONF_INSTALL_AMDAIE
	cp $CONF_INSTALL_AMDAIE/tools/simnow/ep_test.script $CONF_INSTALL_DIR
	check_result "copy ep_test.script" $?

	if [ $IS_UBUNTU == 1 ];then
		echo "start simnow in docker"
		docker run --privileged --rm --net=host -it -v $CONF_INSTALL_DIR:/scratch --workdir /scratch/${SIMNOW}/ maxz:centos7-dev-1 ./simnow -c -e ../ep_test.script
	else
		echo "start simnow directly"
		cd $CONF_INSTALL_DIR/$SIMNOW
		./simnow -c -e ../ep_test.script
	fi
}

start_qemu()
{
	echo "=== ${FUNCNAME[0]} ==="

	cd $CONF_INSTALL_DIR
	if [ $IS_UBUNTU == 1 ];then
		if [ $OS_VERSION == 20 ];then 
			if [ -d $CONF_INSTALL_DIR/$CONF_INSTALL_QEMU_UT20 ];then
				echo "found existing qemu $CONF_INSTALL_QEMU_UT20"
			else
				echo "get qemu $CONF_INSTALL_QEMU_UT20 from artifactory ... this takes a while"
				rsync -L -aq --progress $CONF_INSTALL_ART/$CONF_INSTALL_QEMU_UT20 $CONF_INSTALL_DIR
				check_result "rsync $CONF_INSTALL_QEMU_UT20" $?
			fi
			QEMU=$CONF_INSTALL_QEMU_UT20/out
		fi

		if [ $OS_VERSION == 22 ];then 
			if [ -d $CONF_INSTALL_DIR/$CONF_INSTALL_QEMU_UT22 ];then
				echo "found existing qemu $CONF_INSTALL_QEMU_UT22"
			else
				echo "get qemu $CONF_INSTALL_QEMU_UT22 from artifactory ... this takes a while"
				rsync -L -aq --progress $CONF_INSTALL_ART/$CONF_INSTALL_QEMU_UT22 $CONF_INSTALL_DIR
				check_result "rsync $CONF_INSTALL_QEMU_UT22" $?
			fi
			QEMU=$CONF_INSTALL_QEMU_UT22/out
		fi
	else
		if [ -d $CONF_INSTALL_DIR/$CONF_INSTALL_QEMU_RHEL7 ];then
			echo "found existing qemu $CONF_INSTALL_QEMU_RHEL7"
		else
			echo "get centos7 version from airtifactory ... this takes a while"
			download_http_file http://atlartifactory.amd.com/artifactory/sw-simnowbuilds-rel-local/internal/qemu/${CONF_INSTALL_QEMU_RHEL7}.tgz
			tar xf ${CONF_INSTALL_QEMU_RHEL7}.tgz
			check_result "unzip qemu tgz" $?
		fi
		QEMU=$CONF_INSTALL_QEMU_RHEL7/bin
	fi

	#still need to copy to local, because snapshot sync is too slow in xco
	if [ -f $CONF_INSTALL_DIR/$CONF_INSTALL_QCOW2 ];then
		echo "found existing qcow2 $CONF_INSTALL_QCOW2"
	else
		echo "get qcow2 from artifactory ... this takes a while"
		rsync -L -ah --progress $CONF_INSTALL_ART/$CONF_INSTALL_QCOW2 $CONF_INSTALL_DIR
	fi

	# take qemu-img snapshot from shared artifactory
	file_exists "$CONF_INSTALL_DIR/$CONF_INSTALL_QCOW2"
	dir_exists "$QEMU"

	yes|rm $CONF_INSTALL_QCOW2.snap
	$QEMU/qemu-img create -f qcow2 -b $CONF_INSTALL_DIR/$CONF_INSTALL_QCOW2 -F qcow2 $CONF_INSTALL_QCOW2.snap
	
	# copy files from amdaie
	dir_exists $CONF_INSTALL_AMDAIE
	cp $CONF_INSTALL_AMDAIE/tools/simnow/qemu_bridge.sh $CONF_INSTALL_DIR
	check_result "copy qemu_bridge.sh" $?

	cd $CONF_INSTALL_DIR
	# replace qcow2 in qemu_bridge.sh
	sed -i "s/ubuntu22.04-dev-1.qcow2/${CONF_INSTALL_QCOW2}.snap -snapshot/" ./qemu_bridge.sh
	if [ $IS_CENTOS == 1 ];then
		# replace qemu path in qemu_bridge.sh
		sed -i "s/QemuHybrid_ubuntu_2202\/out/${CONF_INSTALL_QEMU_RHEL7}\/bin/" ./qemu_bridge.sh
		# replace qemu-bridge-helper 
		sed -i "s/qemu-bridge-helper/..\/libexec\/qemu-bridge-helper/" ./qemu_bridge.sh
		sed -i "s/sudo//" ./qemu_bridge.sh
		mkdir -p $CONF_INSTALL_DIR/$CONF_INSTALL_QEMU_RHEL7/etc/qemu/
		echo "allow virbr0" > $CONF_INSTALL_DIR/$CONF_INSTALL_QEMU_RHEL7/etc/qemu/bridge.conf
		check_result "parse qemu_bridge.sh" $?
	elif [ $OS_VERSION == 20 ];then
		# replace qemu path in qemu_bridge.sh
		sed -i "s/QemuHybrid_ubuntu_2202\/out/${CONF_INSTALL_QEMU_UT20}\/out/" ./qemu_bridge.sh

	fi
	echo "Qemu env: "
	grep -e "QemuPath" -e "qemu-bridge-helper" -e "qcow2" qemu_bridge.sh

	# wait until simnow is up
	pgrep_wait "simnow"

	# start qemu
	for count in {1..10}
	do
		#ssh root@localhost ${CONF_INSTALL_DIR}/qemu_bridge.sh
		${CONF_INSTALL_DIR}/qemu_bridge.sh
		if [ $? -ne 0 ];then
			print_warn "FAIL ($count) times: see qemu.log"
			cat $CONF_INSTALL_DIR/qemu.log
			echo "sleep 60 Seconds and retry ..."
			sleep 60
			continue
		else
			return;
		fi
	done
}

start_vf()
{
	echo "=== ${FUNCNAME[0]} ==="
	
	pgrep_wait "simnow"
	pgrep_wait "qemu"
	# wait for host starts and stable
	ping -c 2 $HOST_IP

	# check id_rsa.pub if no, ask for it
	if [ -f ~/.ssh/id_rsa.pub ];then
		ping -c 1 $HOST_IP
		if [ $? -ne 0 ];then
			echo "FAIL: qemu VM OS is not up, please run $BASE_NAME -qemu first"
			exit 1;
		fi
	else
		echo "FAIL: no publish key, please run \"ssh-keygen\" and retry"
		echo "  Please set passphrase as empty for convenience"
		echo "  script will NOT work if you set your own password!"
		exit 1;
	fi
	
	echo "NOTE: perform one time id_rsa.pub copy to VM, you won't be asked anymore"
	echo "  if asked for password, please input password as: l1admin"
	ssh-copy-id -f -i ~/.ssh/id_rsa.pub root@$HOST_IP

	dir_exists $CONF_INSTALL_AMDAIE

	# cleanup existing dmesg for clean log
	ssh root@$HOST_IP dmesg -C

	if [ $IOMMU_MODE == 2 ];then
		ssh root@$HOST_IP "echo always > /sys/kernel/mm/transparent_hugepage/enabled"
		ssh root@$HOST_IP "echo always > /sys/kernel/mm/transparent_hugepage/defrag"

		ssh root@$HOST_IP echo "cat /sys/kernel/mm/transparent_hugepage/enabled"
		ssh root@$HOST_IP cat /sys/kernel/mm/transparent_hugepage/enabled |grep -w '\[always\]'
		check_result "VM hugepage should be set to [always]" $?
		ssh root@$HOST_IP echo "cat /sys/kernel/mm/transparent_hugepage/defrag"
		ssh root@$HOST_IP cat /sys/kernel/mm/transparent_hugepage/defrag |grep -w '\[always\]'
		check_result "VM defrag should be set to [always]" $?
	fi

	WORKSPACE=`echo $CONF_INSTALL_AMDAIE |rev|cut -f1 -d "/"|rev`
	echo "cleanup existing workspace $WORKSPACE"
	ssh root@$HOST_IP rm -rf /root/$WORKSPACE
	check_result "remove /root/$WORKSPACE" $?

	echo "uploading ... $CONF_INSTALL_AMDAIE"
	rsync -L -aq -e ssh --exclude='build/Debug' --exclude='build/Release' $CONF_INSTALL_AMDAIE root@$HOST_IP:/root
	check_result "rsync $CONF_INSTALL_AMDAIE" $?
	
	ssh root@$HOST_IP /root/$WORKSPACE/build/build.sh -clean
	if [[ $BUILD_HELLO == 1 ]];then
		ssh root@$HOST_IP /root/$WORKSPACE/build/build.sh -hello_hsa
	else
		ssh root@$HOST_IP /root/$WORKSPACE/build/build.sh
	fi	
	check_result "Build $WORKSPACE driver" $?

	ssh root@$HOST_IP /root/$WORKSPACE/build/build.sh -xclbin_only npu3
	check_result "Build xclbin" $?

	ssh root@$HOST_IP ls /root/$WORKSPACE/build/Debug/bins/driver/amdxdna.ko
	check_result "amdxdna.ko" $?

 	#copy amd_maie.ko from somewhere?
        #ssh root@$HOST_IP ls /root/amd-aie/build/Debug/bins/driver/amd_maie.ko
	scp $CONF_INSTALL_ART/amd_maie.ko root@$HOST_IP:/root/$WORKSPACE/build/Debug/bins/driver
	check_result "copy amd_maie.ko" $?

	ssh root@$HOST_IP ls /root/$WORKSPACE/build/Debug/bins/vadd_oma.xclbin
	check_result "vadd_oma.xclbin" $?

	ssh root@$HOST_IP rm -f /root/$WORKSPACE/build/Debug/bins/phx_workspace
	ssh root@$HOST_IP rm -f /root/$WORKSPACE/build/Debug/bins/stx_workspace
	ssh root@$HOST_IP rm -rf /root/bins
	ssh root@$HOST_IP cp -r /root/$WORKSPACE/build/Debug/bins /root
	check_result "copy bins pkg to /root" $?

	# enable_oma_pooling:0 to enable intr
	# iommu_mode:1 to enable IOMMU dma_addr, iommu_mode:2 to enable physical addr
	# dyndbg==pf to enable verbose log (AIE_DBG)
	print_warn "IOMMU_MODE ${IOMMU_MODE} \n"
	ssh root@$HOST_IP "rmmod amdxdna; rmmod amd_maie > /dev/null 2>&1"
	ssh root@$HOST_IP "modprobe gpu_sched; modprobe drm_shmem_helper"
	ssh root@$HOST_IP "insmod /root/bins/driver/amdxdna.ko enable_oma_polling=0 iommu_mode=${IOMMU_MODE} dyndbg==pf "
	check_result "insmod amdxdna.ko" $?
	ssh root@$HOST_IP "insmod /root/bins/driver/amd_maie.ko"
	check_result "insmod amd_maie.ko" $?

	ssh root@$HOST_IP "echo 1 > /sys/bus/pci/devices/0000\:03\:00.1/sriov_numvfs"
	check_result "enable sriov" $?

	ssh root@$HOST_IP "echo 0 > /sys/kernel/debug/accel/0000\:03\:00.5/oma_test"
	check_result "Run echo test: " $?
	
	echo ">> run all shim_test <<"

	record_test_start

	if [[ $BUILD_HELLO == 1 ]];then
		print_warn "tell hello only"
		ssh root@$HOST_IP /root/bins/bin/shim_test 7
	else
		ssh root@$HOST_IP /root/bins/bin/shim_test
	fi	

	check_result "Run all shim_test" $?
	record_test_end

	dump_dmesg
}

check_file_exists()
{
	typeset FILE="$1"
	if [ -z $FILE ] || [ ! -f $FILE ];then
		echo "ERROR: $FILE doesn't exist";exit 1;
	fi
}

usage() {
    echo "Usage: $BASE_NAME [options]"
    echo "  options:"
    echo "  --config, -c             example: -c build_amd_env.json"  
    echo "  --clean, -k              kill existing simnow and qemu"
    echo "  --simnow, -s             start simnow"
    echo "  --qemu, -q               start qemu vm"
    echo "  --vf, -v                 start vf driver"
    echo "  --hello, -o              start vf driver hello test(memory test between vf and cert)"
    echo "  --iommu_mode, -m         0:PASID, 1:DMA, 2:PHYSICAL"
    echo "  --help, -h"
    echo "  Examples: "
    echo "           $BASE_NAME --simnow --config build_amd_env.json [--hello]" 
    echo "           $BASE_NAME --qemu --config build_amd_env.json" 
    echo "           $BASE_NAME --vf --config build_amd_env.json [--hello]" 
    exit $1
}

check_env()
{
	echo "=== ${FUNCNAME[0]} ==="

	#check ops
	if [[ $(( BUILD_SIMNOW + BUILD_QEMU + BUILD_VF )) -gt 1 ]];then
		echo "please only selct one from -simnow, -qemu, -vf "
		usage 1
	fi

	if [[ $BUILD_SIMNOW == 0 ]] &&
	   [[ $BUILD_QEMU == 0 ]] &&
	   [[ $BUILD_VF == 0 ]];then
		echo "please select one from -simnow, -qemu -vf"
		usage 1
	fi

	#check if os is supported

	grep ^NAME= /etc/os-release | grep -i -e "Centos" -e "Red hat"
	if [ $? -eq 0 ];then
		IS_CENTOS=1
	fi

	grep ^NAME= /etc/os-release | grep -i "Ubuntu"
	if [ $? -eq 0 ];then
		IS_UBUNTU=1
	fi

	OS_VERSION=`grep VERSION_ID /etc/os-release | cut -f1 -d. | cut -f2 -d'"'`
	if [[ $IS_CENTOS && $OS_VERSION == 7 ]] ||
	   [[ $IS_UBUNTU && $OS_VERSION == 20 ]] ||
	   [[ $IS_UBUNTU && $OS_VERSION == 22 ]];then
		lsb_release -d
		echo "PASS: Supported version."
	else
		lsb_release -a
		echo "Only support Ubuntu20.04LTS, Ubuntu22.04LTS and Centos/Redhat 7.x!"
		echo "FAIL: Unsupported version!"
		exit 1;
	fi
}

while [ $# -gt 0 ];
do
        case "$1" in
                -h | --help)
                        usage 0
                        ;;

                -c | --config)
			shift
                        BUILD_CONFIG=$1
                        ;;
		-s | --simnow)
			BUILD_SIMNOW=1
			;;
		-q | --qemu)
			BUILD_QEMU=1
			;;
		-v | --vf)
			BUILD_VF=1
			;;
		-o | --hello)
                        BUILD_HELLO=1
                        ;;
		-v | --verbose)
			BUILD_VERBOSE=1
			;;
                -k | --clean)
                        BUILD_CLEAN=1
                        ;;
                -m | --iommu_mode)
			shift
                        IOMMU_MODE=$1
                        ;;
                * | --* | -*)
                        echo "Invalid argument: $1"
                        usage 1
                        ;;
        esac
	shift
done

#####################
# build starts here #
#####################

if [[ $BUILD_CLEAN == 1 ]];then
	build_clean
	exit 0;
fi

check_env

load_build_info $BUILD_CONFIG

if [ $BUILD_SIMNOW == 1 ];then
	start_simnow
	exit 0
fi

if [ $BUILD_QEMU == 1 ];then
	start_qemu
	exit 0
fi

if [ $BUILD_VF == 1 ];then
	start_vf
	exit 0
fi
