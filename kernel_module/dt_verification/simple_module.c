#include <linux/init.h>
#include <linux/device.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/export.h> /* for THIS_MODULE */
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/of.h> /* of_find_node_by_name */
#include <linux/slab.h> /* kmalloc */
#include <crypto/hash.h>

static ssize_t device_file_read(struct file *, char *, size_t, loff_t *);

static struct file_operations simple_driver_fops = 
{
    .owner   = THIS_MODULE,
    .read    = device_file_read,
}; 

static int device_file_major_number =0;
static const char device_name[] ="Simple-driver";

struct sdesc {
	struct shash_desc shash;
	char ctx[];
};

static struct sdesc *init_sdesc(struct crypto_shash *alg)
{
	struct sdesc *sdesc;
	int size;
	size = sizeof(struct shash_desc) + crypto_shash_descsize(alg);
	sdesc = kmalloc(size, GFP_KERNEL);
	if(!sdesc) {
		return ERR_PTR(-ENOMEM);
	}

	sdesc->shash.tfm = alg;
	return sdesc;
}

static int calc_hash(struct crypto_shash *alg, const unsigned char *data,
		unsigned int datalen, unsigned char *digest)
{
	struct sdesc *sdesc;
	int ret;
	
	sdesc = init_sdesc(alg);
	if(IS_ERR(alg)) {
		printk(KERN_NOTICE "Error - init_sdesc\n");
		return PTR_ERR(sdesc);
	}

	ret = crypto_shash_digest(&sdesc->shash, data, datalen, digest);
	kfree(sdesc);
	return ret;
}

void test_hash(struct crypto_shash *alg)
{
	const u8 *data0 = "\x00\x61\x62\x63\x64";
	const u8 *data1 = "\x00";
	const u8 *data2 = "\x00\x61\x62\x63\x64";
	unsigned char *digest0;
	unsigned char *digest1;
	int ret = -1;
	digest0 = kmalloc(20, GFP_KERNEL);
	digest1 = kmalloc(20, GFP_KERNEL);
	if(!digest0 || !digest1) {
		printk(KERN_NOTICE "Error - kmalloc 20\n");
		return;
	}

	ret = calc_hash(alg, data0, sizeof(data0), digest0);
	ret = calc_hash(alg, data1, sizeof(data1), digest1);
	if( strncmp(digest0, digest1, 20) == 0 ) {
		printk(KERN_NOTICE "data0 == data1 \n");
	}
	ret = calc_hash(alg, data2, sizeof(data2), digest1);
	if( strncmp(digest0, digest1, 20) == 0 ) {
		printk(KERN_NOTICE "data0 == data2 \n");
	}

}

int print_elem(struct device_node *my_node)
{
	struct device_node *my_child;
	struct property *my_property;
	unsigned const char *pro_name = "hash";
	u64 *tmp;
	int pro_length = sizeof(pro_name);
	unsigned long tot_size = 0;

	printk(KERN_NOTICE "Find node with name:%s\n", my_node->name);
	my_property = my_node->properties;

	while(my_property) {
		tmp = (u64*)my_property->value;
		if(strncmp(my_property->name, pro_name, pro_length) == 0) {
			printk(KERN_NOTICE "pro. name: %s\n", my_property->name);
			printk(KERN_NOTICE "pro. value: %x\n", tmp);
		} else {
			printk(KERN_NOTICE "pro. name: %s\n", my_property->name);
			printk(KERN_NOTICE "pro. value: %x\n", tmp);
		}
		my_property = my_property->next;
	}
	
	my_child = my_node->child;

	
	if(!my_child) {
		printk(KERN_NOTICE "%s don't have child member\n", my_node->name);
	} 
	while(my_child != NULL) {
		printk(KERN_NOTICE "child node with name: %s\n", my_child->name);
		my_property = my_child->properties;
		while(my_property != NULL ) {
			printk(KERN_NOTICE "child property name: %s\n",
				my_property->name);

			tmp = (u64 *)my_property->value;
			printk(KERN_NOTICE "child property value: 0x%4x\n",
				tmp);
			tot_size += sizeof(tmp) + strlen(my_property->name);
			my_property = my_property->next;
		}
		my_child = my_child->child;
	}
	printk(KERN_NOTICE "Child byte: %lu\n", tot_size);
	return 0;
}

int __init register_device(void)
{
	int result = 0;
	struct device_node *my_node;
	char *hash_alg_name = "sha1";
	struct crypto_shash *alg;

	/* sha1 */
	alg = crypto_alloc_shash(hash_alg_name, CRYPTO_ALG_TYPE_SHASH, 0);
	if(IS_ERR(alg)) {
		printk(KERN_NOTICE "Error - crypto_alloc_shash\n");
		return -1;
	}

	test_hash(alg);
	crypto_free_shash(alg);
	/* END-sha1 */

	/* DTB node section */
	my_node = of_find_node_by_name(NULL, "cpus");
	if(!my_node) {
		printk(KERN_NOTICE "Error - of_find_node_by_name\n");
		return -1;
	} 

	/* Dump all element in the subcomponent */
	print_elem(my_node);
	printk(KERN_NOTICE "End dtb section \n");
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
MODULE_DESCRIPTION("A simple driver for char");
