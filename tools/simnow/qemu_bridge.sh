#!/bin/bash
 
wd=`dirname $0`
QemuPath=$wd/QemuHybrid_ubuntu_2202/out
 
#sudo $QemuPath/qemu-system-x86_64			\
#-M q35,accel=kvm,kernel-irqchip=split			\
#-m 16G							\
#-smp 2							\
#-netdev bridge,id=hn0,br=virbr0,helper=$QemuPath/qemu-bridge-helper -device virtio-net-pci,netdev=hn0,id=nic1 \
#-machine-path $wd/machine-x86				\
#-device simnow-bridge-socket,id=snb-skt			\
#-nographic						\
#-chardev stdio,id=s1,signal=off,mux=on -serial none -device isa-serial,chardev=s1 -mon chardev=s1,mode=readline \
#-hda $wd/ubuntu22.04-desktop-minimum.qcow2		\
#2>$wd/qemu.log

#-device x3130-upstream,id=x3130-us			\
#-device simnow-bridge-socket,bus=x3130-us,id=snb-skt,use_irq_queue=false,enable_iommu=true \

$QemuPath/qemu-system-x86_64				\
-M q35,accel=kvm,kernel-irqchip=split			\
-device intel-iommu,intremap=on,device-iotlb=on		\
-m 4G							\
-smp 2							\
-netdev bridge,id=hn0,br=virbr0,helper=$QemuPath/qemu-bridge-helper -device virtio-net-pci,netdev=hn0,id=nic1 \
-machine-path $wd/machine-x86				\
-device ioh3420,id=root_port1				\
-device simnow-bridge-socket,bus=root_port1,id=snb-skt,use_irq_queue=false,enable_iommu=true \
-nographic						\
-chardev stdio,id=s1,signal=off,mux=on -serial none -device isa-serial,chardev=s1 -mon chardev=s1,mode=readline \
-hda $wd/ubuntu22.04-dev-1.qcow2		\
2>$wd/qemu.log
if [ $? -ne 0 ];then
	echo "Start Qemu failed! Check $wd/qemu.log for more details."
	exit 1
fi
