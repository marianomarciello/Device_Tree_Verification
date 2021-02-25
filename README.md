# Device Tree verfication module

## Intro
This module is just a *proof of concept*. With this module we try to verificate subset of the Device Tree. The verification is done with **sha1** digest.

## Installation
This is module was tested on Linux Kernel version 5.9.0, the environ is provided by **Joakim Bech** at this [link](https://github.com/jbech-linaro/build/tree/dte).

## DTB compilation
Compilation of **dts** in **dtb**.

```
$ dtc -I dts -O dtb correct.dts -o correct.dtb
$ dtc -I dts -O dtb incorrect.dts -o incorrect.dtb
```

## Transfer \*.dtb object
For transfer the new dtb obtained in the virtualized environment:

+ copy the \*.dtb file in **/srv/tftp** (copy it or create a soft-link, in **Arch linux** you **must** copy it or this will not work)
+ change permission of this files
```
chmod 777 correct.dtb
chmod 777 incorrect.dtb
```
+ change owner of this file 
```
sudo chown nobody correct.dtb
sudo chown nobody incorrect.dtb
```

## Start U-boot
Run U-boot from the specified environment with :
```
make run-netboot
```

execute the following command on **U-boot**
```
tftp ${fdt_addr} ${serverip}:correct.dtb;
```

or

```
tftp ${fdt_addr} ${serverip}:incorrect.dtb;
```

and then:

```
run nbr
```

## Load module
In the **buildroot** environment:

```
mkdir /host && mount -t 9p -o mrans=virtio host /host
```

Now we have a shared folder where we can insert the module to be loaded.
For load and unload the module just:
```
insmod dtb_verification.ko
rmmod dtb_verification.ko
```

If you want to verify a single subnode, specify the parent name with:
```
insmod dtb_verification.ko node_name="NAME_THERE"
```

