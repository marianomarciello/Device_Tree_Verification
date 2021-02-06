obj-m := farside_core.o

KERNEL_PATH		:= /media/jbech/TSHB_LINUX/devel/optee_projects/qemu_v8/linux
TOOLCHAIN		:= /media/jbech/TSHB_LINUX/devel/optee_projects/reference/toolchains/aarch64/bin/aarch64-linux-gnu-
LINUX_COMMON_FLAGS	?= LOCALVERSION= CROSS_COMPILE=$(TOOLCHAIN)

all:
	make -C $(KERNEL_PATH) M=$(shell pwd) $(LINUX_COMMON_FLAGS) ARCH=arm64 modules

clean:
	make -C $(KERNEL_PATH) M=$(shell pwd) ARCH=arm64 clean

qemu_alias:
	@echo "alias s='mkdir -p /host && mount -t 9p -o trans=virtio host /host'"
	@echo "insmod /host/farside_core.ko"
	@echo "rmmod farside_core"
	@echo "cat /proc/iomem"
