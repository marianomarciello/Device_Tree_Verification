cmd_/home/nara/Kernel_Hacking/src/kernel_module/dt_verification/Module.symvers := sed 's/ko$$/o/' /home/nara/Kernel_Hacking/src/kernel_module/dt_verification/modules.order | scripts/mod/modpost     -o /home/nara/Kernel_Hacking/src/kernel_module/dt_verification/Module.symvers -e    -T -
