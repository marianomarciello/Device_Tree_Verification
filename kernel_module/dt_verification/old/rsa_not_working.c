#include <linux/init.h>
#include <linux/device.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/export.h> /* for THIS_MODULE */
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/of.h> /* of_find_node_by_name */
#include <linux/slab.h> /* kmalloc */
#include <crypto/akcipher.h>

static ssize_t device_file_read(struct file *, char *, size_t, loff_t *);

static struct file_operations simple_driver_fops = 
{
    .owner   = THIS_MODULE,
    .read    = device_file_read,
}; 

static int device_file_major_number =0;
static const char device_name[] ="Simple-driver";



/* init rsa */
static struct crypto_akcipher * my_rsa(void)
{
	struct crypto_akcipher *tfm;
	int err = 0;

	/* using rsa */
	tfm = crypto_alloc_akcipher("rsa", 0, 0);

	if(IS_ERR(tfm)) {
		printk(KERN_NOTICE "Error %ld- crypto_alloc_akcipher\n",
			PTR_ERR(tfm));
		return PTR_ERR(tfm);
	}

	printk(KERN_NOTICE "Rsa-init done\n");
	return tfm;
}

static int my_rsa_encrypt(struct crypto_akcipher *tfm )
{
	struct akcipher_request *req;
	int err = -ENOMEM;
	u8 *pub ;
	const unsigned char *pub_key = 
	"\x30\x82\x02\x1F" /* sequence of 543 bytes */
	"\x02\x01\x01" /* version - integer of 1 byte */
	"\x02\x82\x01\x00" /* modulus - integer of 256 bytes */
	"\xDB\x10\x1A\xC2\xA3\xF1\xDC\xFF\x13\x6B\xED\x44\xDF\xF0\x02\x6D"
	"\x13\xC7\x88\xDA\x70\x6B\x54\xF1\xE8\x27\xDC\xC3\x0F\x99\x6A\xFA"
	"\xC6\x67\xFF\x1D\x1E\x3C\x1D\xC1\xB5\x5F\x6C\xC0\xB2\x07\x3A\x6D"
	"\x41\xE4\x25\x99\xAC\xFC\xD2\x0F\x02\xD3\xD1\x54\x06\x1A\x51\x77"
	"\xBD\xB6\xBF\xEA\xA7\x5C\x06\xA9\x5D\x69\x84\x45\xD7\xF5\x05\xBA"
	"\x47\xF0\x1B\xD7\x2B\x24\xEC\xCB\x9B\x1B\x10\x8D\x81\xA0\xBE\xB1"
	"\x8C\x33\xE4\x36\xB8\x43\xEB\x19\x2A\x81\x8D\xDE\x81\x0A\x99\x48"
	"\xB6\xF6\xBC\xCD\x49\x34\x3A\x8F\x26\x94\xE3\x28\x82\x1A\x7C\x8F"
	"\x59\x9F\x45\xE8\x5D\x1A\x45\x76\x04\x56\x05\xA1\xD0\x1B\x8C\x77"
	"\x6D\xAF\x53\xFA\x71\xE2\x67\xE0\x9A\xFE\x03\xA9\x85\xD2\xC9\xAA"
	"\xBA\x2A\xBC\xF4\xA0\x08\xF5\x13\x98\x13\x5D\xF0\xD9\x33\x34\x2A"
	"\x61\xC3\x89\x55\xF0\xAE\x1A\x9C\x22\xEE\x19\x05\x8D\x32\xFE\xEC"
	"\x9C\x84\xBA\xB7\xF9\x6C\x3A\x4F\x07\xFC\x45\xEB\x12\xE5\x7B\xFD"
	"\x55\xE6\x29\x69\xD1\xC2\xE8\xB9\x78\x59\xF6\x79\x10\xC6\x4E\xEB"
	"\x6A\x5E\xB9\x9A\xC7\xC4\x5B\x63\xDA\xA3\x3F\x5E\x92\x7A\x81\x5E"
	"\xD6\xB0\xE2\x62\x8F\x74\x26\xC2\x0C\xD3\x9A\x17\x47\xE6\x8E\xAB"
	"\x02\x03\x01\x00\x01" /* public key - integer of 3 bytes */
	"\x02\x82\x01\x00" /* private key - integer of 256 bytes */
	"\x52\x41\xF4\xDA\x7B\xB7\x59\x55\xCA\xD4\x2F\x0F\x3A\xCB\xA4\x0D"
	"\x93\x6C\xCC\x9D\xC1\xB2\xFB\xFD\xAE\x40\x31\xAC\x69\x52\x21\x92"
	"\xB3\x27\xDF\xEA\xEE\x2C\x82\xBB\xF7\x40\x32\xD5\x14\xC4\x94\x12"
	"\xEC\xB8\x1F\xCA\x59\xE3\xC1\x78\xF3\x85\xD8\x47\xA5\xD7\x02\x1A"
	"\x65\x79\x97\x0D\x24\xF4\xF0\x67\x6E\x75\x2D\xBF\x10\x3D\xA8\x7D"
	"\xEF\x7F\x60\xE4\xE6\x05\x82\x89\x5D\xDF\xC6\xD2\x6C\x07\x91\x33"
	"\x98\x42\xF0\x02\x00\x25\x38\xC5\x85\x69\x8A\x7D\x2F\x95\x6C\x43"
	"\x9A\xB8\x81\xE2\xD0\x07\x35\xAA\x05\x41\xC9\x1E\xAF\xE4\x04\x3B"
	"\x19\xB8\x73\xA2\xAC\x4B\x1E\x66\x48\xD8\x72\x1F\xAC\xF6\xCB\xBC"
	"\x90\x09\xCA\xEC\x0C\xDC\xF9\x2C\xD7\xEB\xAE\xA3\xA4\x47\xD7\x33"
	"\x2F\x8A\xCA\xBC\x5E\xF0\x77\xE4\x97\x98\x97\xC7\x10\x91\x7D\x2A"
	"\xA6\xFF\x46\x83\x97\xDE\xE9\xE2\x17\x03\x06\x14\xE2\xD7\xB1\x1D"
	"\x77\xAF\x51\x27\x5B\x5E\x69\xB8\x81\xE6\x11\xC5\x43\x23\x81\x04"
	"\x62\xFF\xE9\x46\xB8\xD8\x44\xDB\xA5\xCC\x31\x54\x34\xCE\x3E\x82"
	"\xD6\xBF\x7A\x0B\x64\x21\x6D\x88\x7E\x5B\x45\x12\x1E\x63\x8D\x49"
	"\xA7\x1D\xD9\x1E\x06\xCD\xE8\xBA\x2C\x8C\x69\x32\xEA\xBE\x60\x71"
	"\x02\x01\x00" /* prime1 - integer of 1 byte */
	"\x02\x01\x00" /* prime2 - integer of 1 byte */
	"\x02\x01\x00" /* exponent1 - integer of 1 byte */
	"\x02\x01\x00" /* exponent2 - integer of 1 byte */
	"\x02\x01\x00"; /* coefficient - integer of 1 byte */
	int key_len = 547;
	pub = kmalloc(key_len + sizeof(u32) * 2, GFP_KERNEL);  
	memcpy(pub, pub_key, key_len);

	if(!pub) {
		printk(KERN_NOTICE "Error - kmallock(key_len ...\n");
		goto exit;
	}
	unsigned char *priv="\x65\x66\x67\x68\x65\x66\x67\x68\x65\x66\x67\x68";

	req = akcipher_request_alloc(tfm, GFP_KERNEL);
	if(!req) {
		printk(KERN_NOTICE "Error - akcipher_request_alloc\n");
		goto exit;
	}
	
	/* return 0 on success */
	err = crypto_akcipher_set_pub_key(tfm, pub, key_len);	
	if(err) { 
		printk(KERN_NOTICE "Error %d - crypto_akcipher_set_pub_key\n",
			err);
		goto exit; 
	}
	err = crypto_akcipher_set_priv_key(tfm, priv, key_len);	

	if(err) { 
		printk(KERN_NOTICE "Error %d - crypto_akcipher_set_priv_key\n",
			err);
		goto exit; 
	}
	
	printk(KERN_NOTICE "my_rsa_encrypt - all fine\n");

exit:
	if(pub)
		kfree(pub);
	return err;
}

static int destroy_rsa(struct crypto_akcipher *tfm)
{
	crypto_free_akcipher(tfm);
	printk(KERN_NOTICE "Rsa-free done\n");
	return 0;
}

int __init register_device(void)
{
	int result = 0;
	struct device_node *my_node, *my_child;
	struct property *my_property;
	struct crypto_akcipher *rsa;

	/* DTB node section */
	my_node = of_find_node_by_name(NULL, "cpus");

	/* RSA */
	rsa = my_rsa();
	if(!rsa)
		return -1;

	my_rsa_encrypt(rsa);
	destroy_rsa(rsa);
	/* END-RSA */

	if(!my_node) {
		printk(KERN_NOTICE "Error - of_find_node_by_name\n");
		return -1;
	} 

	/* Dump all element in the subcomponent */
	printk(KERN_NOTICE "Find node with name:%s\n", my_node->name);

	my_property = my_node->properties;

	while(my_property) {
		printk(KERN_NOTICE "property name %s\n", my_property->name);
		printk(KERN_NOTICE "property value %x\n", my_property->value);
		my_property = my_property->next;
	}
	
	my_child = my_node->child;

	if(!my_child) {
		printk(KERN_NOTICE "%s don't have child member\n", my_node->name);
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
