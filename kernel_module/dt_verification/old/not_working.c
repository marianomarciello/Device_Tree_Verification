#include <linux/init.h>
#include <linux/device.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/export.h> /* for THIS_MODULE */
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/of.h> /* of_find_node_by_name */
#include <linux/slab.h> /* kmalloc */

static ssize_t device_file_read(struct file *, char *, size_t, loff_t *);

static struct file_operations simple_driver_fops = 
{
    .owner   = THIS_MODULE,
    .read    = device_file_read,
}; 

static int device_file_major_number =0;
static const char device_name[] ="Simple-driver";

int __init register_device(void)
{
	int result = 0;
	struct device_node *my_node, *my_child;
	struct property *my_property, *tmp_property;

	/* DTB node section */
	my_node = of_find_node_by_name(NULL, "cpus");

	if(!my_node) {
		printk(KERN_NOTICE "Error - of_find_node_by_name\n");
		return -1;
	} 

	/* Dump all element in the subcomponent */
	printk(KERN_NOTICE "Find node with name:%s\n", my_node->name);
	printk(KERN_NOTICE "First property name: %s\n", my_node->properties->name);	
	printk(KERN_NOTICE "First property value: %x\n", my_node->properties->value);
	
	my_property = of_find_property(my_node, "method", 0);

	my_child = my_node->child;
	if(!my_child) {
		printk(KERN_NOTICE "%s don't have child member\n", my_node->name);
	} else {
		/* adding custom property */
		tmp_property = kmalloc(sizeof(*tmp_property), GFP_KERNEL);
		if(!tmp_property) {
			printk(KERN_NOTICE "Error - kmalloc tmp_property\n");
			return -1;
		}
		tmp_property->name = "Test";
		tmp_property->value = 0x01010101;
		/* this doesn't work becouse this module is not loaded by 
		 * default, and in buildroot i can't load module
		 * cat /proc/kallsyms | grep of_add_property
		 */
		//of_add_property(my_child, tmp_property);
	}

	while(my_child) {
		printk(KERN_NOTICE "child node with name: %s\n", my_child->name);
		my_property = my_child->properties;
		while(my_property) {
			printk(KERN_NOTICE "child property name: %s\n",
				my_property->name);

			printk(KERN_NOTICE "child property value: %x\n",
				my_property->value);

			my_property = my_property->next;
		}
		my_child = my_child->child;
	}
	/* end DTB node section */

	printk(KERN_NOTICE "Simple-driver: register_device() is called\n");
	result = register_chrdev(0, device_name, &simple_driver_fops);
	if (result < 0) {
		printk(KERN_WARNING "Simple-device: can\'t register "
		"character device with error code %i\n",result);
	}
	device_file_major_number = result;
	printk(KERN_NOTICE "Simple-driver: registered character "
		"device with major number = %i and" 
		"minor numbers 0..255\n", device_file_major_number);
	return 0;
}

void __exit unregister_device(void)
{
	printk(KERN_NOTICE "Simple-driver: unregister_device() is called\n");
	if(device_file_major_number != 0)
		unregister_chrdev(device_file_major_number, device_name);
}

static const char g_s_Hello_World_string[] = "Hello world from kernel mode!\n\0";
static const ssize_t g_s_Hello_World_size = sizeof(g_s_Hello_World_string);
static ssize_t device_file_read( struct file *file_ptr, char __user *user_buffer,
				size_t count, loff_t *position)
{
	printk(KERN_NOTICE "Simple-drive: Device file is read at offset"
		" = %i, read bytes count = %i\n", (int)*position,
		(unsigned int)count);
	
	/* if position is behind the ned of a file we have nothing to read */
	if( *position >= g_s_Hello_World_size )
		return 0;
	/* if user try to read more than we have, read only as many bytes 
	 * we have 
	 */
	if(*position + count > g_s_Hello_World_size)
		count = g_s_Hello_World_size - *position;
	if(copy_to_user( user_buffer,
		g_s_Hello_World_string + *position, count) != 0)
		return -EFAULT;
	/* Move reading position */
	*position += count;
	return count;
}

module_init(register_device);
module_exit(unregister_device);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Mariano Marciello");
MODULE_VERSION("0.1");
MODULE_DESCRIPTION("A simple driver for char");
