cmd_/home/nara/Kernel_Hacking/src/kernel_module/dt_verification/modules.order := {   echo /home/nara/Kernel_Hacking/src/kernel_module/dt_verification/dtb_verification.ko; :; } | awk '!x[$$0]++' - > /home/nara/Kernel_Hacking/src/kernel_module/dt_verification/modules.order
