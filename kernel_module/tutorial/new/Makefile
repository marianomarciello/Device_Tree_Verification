ifneq ($(KERNELRELEASE),)
obj-m:=hello.o

else
PWD :=$(shell pwd)
KDIR:=~/Kernel_Hacking/linux-next/lib
	
default:
		$(MAKE) -C '$(KDIR)' SUBDIRS=$(PWD) modules
endif

clean:
	rm -rf *.ko *.o *.mod.c *.mod.o modules.order
	rm -rf Module.symvers .*.cmd .tmp_versions
