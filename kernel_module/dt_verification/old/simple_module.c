#include <linux/init.h>
#include <linux/module.h>
#include <linux/export.h> /* for THIS_MODULE */
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/of.h> /* of_find_node_by_name */
#include <linux/slab.h> /* kmalloc */
#include <crypto/hash.h>
#include <linux/printk.h> /* hex_dump_to_buffer */

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


/* get byte len in the name:value child node (hex)*/
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

/* print element (hex value ) */
int hex_print_elem_string(struct device_node *my_node, struct crypto_shash *alg,
			char *hash, int tot_size)
{
	struct device_node *my_child;
	struct property *my_property;
	int rr;
	char *ret, *buffer;

	ret = kmalloc(tot_size*2, GFP_KERNEL); 
	if(!ret) {
		printk(KERN_INFO "HEX: Error - kmalloc(tot_size)\n");
		return -ENOMEM;
	}

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
				strlen(buffer)+1);

			ret = ret + strlen(buffer) + strlen(my_property->name);

			kfree(buffer);
			my_property = my_property->next;
		}
		my_child = my_child->child;
		
	}
	
	ret = ret - tot_size;
	printk(KERN_NOTICE "HEX: The entire string is [%s]\n", ret);
	printk(KERN_NOTICE "HEX: The entire len is %ld\n", strlen(ret));

	rr = calc_hash(alg, ret, strlen(ret), hash);

	kfree(ret);
	return 0;
}

/* Register device init function, done when insmod module.ko */
int __init start_module(void)
{
	int tot_size = 0;
	struct device_node *my_node;
	struct property *dts_property;
	char *hash_alg_name = "sha1";
	char *hash, *dts_hash;
	char *digest;
	struct crypto_shash *alg;
	int ret = 0;

	/* sha1 */
	alg = crypto_alloc_shash(hash_alg_name, CRYPTO_ALG_TYPE_SHASH, 0);
	if(IS_ERR(alg)) {
		printk(KERN_NOTICE "Error - crypto_alloc_shash\n");
		return -1;
	}
	/* END-sha1 */

	/* DTB node section */
	my_node = of_find_node_by_name(NULL, "cpus");
	dts_property = of_find_property(my_node, "hash", 0);
	if(!my_node || !dts_property) {
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
	if(!hash) {
		printk(KERN_NOTICE "Error - malloc hash\n");
		return -ENOMEM;
	}
	digest = kmalloc(tot_size , GFP_KERNEL);
	if(!digest) {
		printk(KERN_NOTICE "Error - malloc digest\n");
		return -ENOMEM;
	}

	if(hex_print_elem_string(my_node, alg, hash, tot_size)) {
		printk(KERN_NOTICE "Error - hex_print_elem \n");
		return -1;
	}
	
	ret = hex_dump_to_buffer(hash, tot_size, 32, 2, digest, tot_size , false);
	if( ret != strlen(digest)) {
		printk(KERN_NOTICE "Error - hex_dump_to_buffer\n");
		return -1;
	}
	printk(KERN_NOTICE "Hash value %s\n", digest);
	printk(KERN_NOTICE "Hash len %ld\n", strlen(digest));
	printk(KERN_NOTICE "DTS hash len %ld\n", strlen(dts_hash));
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

	return 0;
}

/* last function when rmmod module.ko */
void __exit end_module(void)
{
	printk(KERN_NOTICE "Removing module\n");
}

module_init(start_module);
module_exit(end_module);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Mariano Marciello");
MODULE_DESCRIPTION("A simple proof of concept for dtb verification");
