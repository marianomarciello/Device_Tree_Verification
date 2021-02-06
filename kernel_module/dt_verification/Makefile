obj-m +=simple_module.o
KERNEL := '/home/nara/Kernel_Hacking/joakim_env/linux'

all:
	#$(MAKE) -C '/home/nara/Kernel_Hacking/linux-next' M='$(PWD)' modules
	make -C $(KERNEL) M='$(PWD)' modules

clean:
	#$(MAKE) -C '/home/nara/Kernel_Hacking/linux-next' M='$(PWD)' clean
	make -C $(KERNEL) M='$(PWD)' clean
