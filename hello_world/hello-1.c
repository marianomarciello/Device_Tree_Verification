/*
 * hello-1.c - The simplest kernel module.
 */
#include <linux/module.h> /* need by all module */
#include <linux/kernel.h> /* for KERN_INFO */

int init_module(void)
{
	printk(KERN_INFO "Hello world 1.\n");

	/*
	 * a non 0 value of return mean that this module can't be loaded
	 */
	
	return 0;
}

void cleanup_module(void)
{
	printk(KERN_INFO "Goodbye world 1 \n");
}
