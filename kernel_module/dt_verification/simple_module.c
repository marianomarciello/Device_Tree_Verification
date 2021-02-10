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
#include <linux/printk.h> /* hex_dump_to_buffer */

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


/* init sdesc */
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

/* calculate digest using alg function */
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

/* testing hash function */
void test_hash(struct crypto_shash *alg)
{
	/* test hash function with null byte */
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

/* print element in the node, and their child */
int print_elem(struct device_node *my_node)
{
	struct device_node *my_child;
	struct property *my_property;
	char *buffer;

	printk(KERN_NOTICE "Find node with name:%s\n", my_node->name);
	my_property = my_node->properties;

	while(my_property) {
		printk(KERN_NOTICE "pro. name: %s\n", my_property->name);
		buffer = kmalloc(my_property->length*2 + my_property->length, GFP_KERNEL);
		if (!buffer) {
			printk(KERN_NOTICE "Error - kmalloc my_property->length\n");
			return -ENOMEM;
		}
		hex_dump_to_buffer(my_property->value, my_property->length, 32, 2,
			buffer, my_property->length*2 + my_property->length, false); 
		printk(KERN_NOTICE "pro. value: %s\n", buffer);
		kfree(buffer);

		printk(KERN_NOTICE "pro. len: %d\n", my_property->length);
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

			buffer = kmalloc(my_property->length*2 + my_property->length, GFP_KERNEL);
			if (!buffer) {
				printk(KERN_NOTICE "Error - kmalloc my_property->length\n");
				return -ENOMEM;
			}
			hex_dump_to_buffer(my_property->value, my_property->length, 32, 2,
				buffer, my_property->length*2 + my_property->length, false); 

			printk(KERN_NOTICE "child property value: %s\n",
				buffer);
			kfree(buffer);
			printk(KERN_NOTICE "child property len: %d\n",
				my_property->length);
			my_property = my_property->next;
		}
		my_child = my_child->child;
	}
	return 0;
}

/* get byte in the name:value child node */
int elem_dimension(struct device_node *my_node)
{
	struct device_node *my_child;
	struct property *my_property;
	unsigned long tot_size = 0;

	my_child = my_node->child;

	
	if(!my_child) {
		printk(KERN_NOTICE "%s don't have child member\n", my_node->name);
		return -1;
	} 

	while(my_child != NULL) {
		my_property = my_child->properties;
		while(my_property != NULL ) {
			tot_size += strlen(my_property->value) 
				+ strlen(my_property->name);
			my_property = my_property->next;
		}
		my_child = my_child->child;
	}

	return tot_size;
}

/* get byte in the name:value child node (hex)*/
int hex_elem_dimension(struct device_node *my_node)
{
	struct device_node *my_child;
	struct property *my_property;
	unsigned long tot_size = 0;
	char *buffer;

	my_child = my_node->child;

	
	if(!my_child) {
		printk(KERN_NOTICE "%s don't have child member\n", my_node->name);
		return -1;
	} 

	while(my_child != NULL) {
		my_property = my_child->properties;
		while(my_property != NULL ) {
			buffer = kmalloc(my_property->length*2 + my_property->length,
					GFP_KERNEL);
			if (!buffer) {
				printk(KERN_NOTICE 
					"Error - kmalloc my_property->length\n");
				return -ENOMEM;
			}
			hex_dump_to_buffer(my_property->value, 
				my_property->length, 32, 2,
				buffer, my_property->length*2 + my_property->length,
				false); 
			tot_size += strlen(buffer) 
				+ strlen(my_property->name);
			my_property = my_property->next;
			kfree(buffer);
		}
		my_child = my_child->child;
	}

	return tot_size;
}

/* print element (only for string value) */
int print_elem_string(struct device_node *my_node, struct crypto_shash *alg,
			char *hash, int tot_size)
{
	struct device_node *my_child;
	struct property *my_property;
	int rr;
	char *ret;

	ret = kmalloc(tot_size, GFP_KERNEL); 
	if(!ret) {
		printk(KERN_INFO "Error - kmalloc(tot_size)\n");
		kfree(ret);
		return -1;
	}

	printk(KERN_NOTICE "Find node with name:%s\n", my_node->name);
	my_property = my_node->properties;

	my_child = my_node->child;
	
	if(!my_child) {
		printk(KERN_NOTICE "%s don't have child member\n", my_node->name);
		kfree(ret);
		return -1;
	} 

	while(my_child != NULL) {
		my_property = my_child->properties;
		while(my_property != NULL ) {
			memcpy(ret, my_property->name, strlen(my_property->name));
			memcpy(ret + strlen(my_property->name), my_property->value,
				strlen(my_property->value));

			ret = ret + strlen(my_property->value)
				+strlen(my_property->name);
			my_property = my_property->next;
		}
		my_child = my_child->child;
		
	}

	ret = ret - tot_size;
	printk(KERN_NOTICE "The entire string is %s\n", ret);

	if(!hash) {
		printk(KERN_NOTICE "Error - kmalloc hash \n");
		return -1;
	}
	rr = calc_hash(alg, ret, strlen(ret), hash);
	kfree(ret);
	return 0;
}
/* print element (hex value ) */
int hex_print_elem_string(struct device_node *my_node, struct crypto_shash *alg,
			char *hash, int tot_size)
{
	struct device_node *my_child;
	struct property *my_property;
	int rr;
	char *ret, *buffer;
	char *tmp;

	ret = kmalloc(tot_size, GFP_KERNEL); 
	tmp = ret;
	if(!ret) {
		printk(KERN_INFO "HEX: Error - kmalloc(tot_size)\n");
		kfree(ret);
		return -1;
	}

	printk(KERN_NOTICE "HEX: Find node with name:%s\n", my_node->name);
	my_property = my_node->properties;

	my_child = my_node->child;
	
	if(!my_child) {
		printk(KERN_NOTICE "HEX: %s don't have child member\n", my_node->name);
		kfree(ret);
		return -1;
	} 

	while(my_child != NULL) {
		my_property = my_child->properties;

		while(my_property != NULL ) {
			buffer = kmalloc(my_property->length*2 + my_property->length,
					GFP_KERNEL);
			if (!buffer) {
				printk(KERN_NOTICE 
					"HEX: Error - kmalloc my_property->length\n");
				return -ENOMEM;
			}
			hex_dump_to_buffer(my_property->value, 
				my_property->length, 32, 2,
				buffer, my_property->length*2 + my_property->length,
				false); 

			memcpy(ret, my_property->name, strlen(my_property->name));
			memcpy(ret + strlen(my_property->name), buffer,
				strlen(buffer));

			ret = ret + strlen(buffer)
				+strlen(my_property->name);

			kfree(buffer);
			my_property = my_property->next;
		}
		my_child = my_child->child;
		
	}

	printk(KERN_NOTICE "HEX: The entire string is %s\n", tmp);
	printk(KERN_NOTICE "HEX: The entire len is %d\n", strlen(tmp));

	if(!hash) {
		printk(KERN_NOTICE "Error - kmalloc hash \n");
		return -1;
	}
	rr = calc_hash(alg, tmp, strlen(tmp), hash);
	kfree(ret);
	return 0;
}

/* Register device init function, done when insmod module.ko*/
int __init register_device(void)
{
	int result = 0;
	int tot_size = 0;
	struct device_node *my_node;
	struct property *dts_property;
	char *hash_alg_name = "sha1";
	char *hash, *dts_hash;
	char *digest;
	struct crypto_shash *alg;

	/* sha1 */
	alg = crypto_alloc_shash(hash_alg_name, CRYPTO_ALG_TYPE_SHASH, 0);
	if(IS_ERR(alg)) {
		printk(KERN_NOTICE "Error - crypto_alloc_shash\n");
		return -1;
	}

	//test_hash(alg);
	/* END-sha1 */

	/* DTB node section */
	my_node = of_find_node_by_name(NULL, "test");
	dts_property = of_find_property(my_node, "hash", 0);
	if(!my_node ) {
		printk(KERN_NOTICE "Error - of_find_node_by_name of_find_property\n");
		return -1;
	} 

	dts_hash = dts_property->value;

	/* Dump all element in the subcomponent */
	//print_elem(my_node);
	tot_size = elem_dimension(my_node);
	printk(KERN_NOTICE "Size %d\n", tot_size);
	if (tot_size <= 0) {
		printk(KERN_NOTICE "Error - negative tot_size\n");
		return -1;
	}

	hash = kmalloc(tot_size, GFP_KERNEL);
	digest = kmalloc(tot_size*2 + 1 , GFP_KERNEL);

	print_elem_string(my_node, alg, hash, tot_size);

	/* output hex of digest value */
	hex_dump_to_buffer(hash, tot_size, 32, 2, digest, tot_size*2 - 1 , false);
	printk(KERN_NOTICE "End dtb section \n");
	printk(KERN_NOTICE "Hash value %s\n", digest);
	printk(KERN_NOTICE "Hash len %d\n", strlen(digest));
	printk(KERN_NOTICE "DTS hash len %d\n", strlen(dts_hash));
	printk(KERN_NOTICE "DTS hash value %s\n", dts_hash);
	if(strcmp(dts_hash, digest) == 0 ) {
		printk(KERN_NOTICE "!! Child node verified !!\n");
	} else {
		printk(KERN_NOTICE "ALERT!! child node not verified \n");
	}

	kfree(digest);
	kfree(hash);
	/* not string verification */
	my_node = of_find_node_by_name(NULL, "cpus");
	dts_property = of_find_property(my_node, "hash", 0);
	if(!my_node ) {
		printk(KERN_NOTICE "Error - of_find_node_by_name of_find_property\n");
		return -1;
	} 

	dts_hash = dts_property->value;

	tot_size = hex_elem_dimension(my_node);
	printk(KERN_NOTICE "Hex Size %d\n", tot_size);
	if (tot_size <= 0) {
		printk(KERN_NOTICE "Error - hex negative tot_size\n");
		return -1;
	}

	hash = kmalloc(tot_size, GFP_KERNEL);
	digest = kmalloc(tot_size , GFP_KERNEL);
	hex_print_elem_string(my_node, alg, hash, tot_size);
	
	hex_dump_to_buffer(hash, tot_size, 32, 2, digest, tot_size , false);
	printk(KERN_NOTICE "Hash value %s\n", digest);
	printk(KERN_NOTICE "Hash len %d\n", strlen(digest));
	printk(KERN_NOTICE "DTS hash len %d\n", strlen(dts_hash));
	printk(KERN_NOTICE "DTS hash value %s\n", dts_hash);
	if(strcmp(dts_hash, digest) == 0 ) {
		printk(KERN_NOTICE "!! Child node verified !!\n");
	} else {
		printk(KERN_NOTICE "ALERT!! child node not verified \n");
	}

	crypto_free_shash(alg);
	kfree(digest);
	kfree(hash);
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
		" minor numbers 0..255\n", device_file_major_number);
	
	return 0;
}

/* last function when rmmod module.ko */
void __exit unregister_device(void)
{
	printk(KERN_NOTICE "Simple-driver: unregister_device() is called\n");
	if(device_file_major_number != 0)
		unregister_chrdev(device_file_major_number, device_name);
}

/* Char device function */
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
