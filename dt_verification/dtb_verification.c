// SPDX-License-Identifier: GPL-2.0-only

#include <linux/init.h>
#include <linux/module.h>
#include <linux/export.h> /* for THIS_MODULE */
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/of.h> /* of_find_node_by_name */
#include <linux/slab.h> /* kmalloc */
#include <crypto/hash.h>
#include <crypto/sha.h> /* SHA1_DIGEST_SIZE */
#include <linux/printk.h> /* hex_dump_to_buffer */

/**
 * Command line option
 */
static char *node_name = "";
module_param(node_name, charp, 0000);
MODULE_PARM_DESC(node_name, "Node's name");

/**
 * Hash function descriptor
 */
struct sdesc {
	struct shash_desc shash;
};

/**
 * ini_sdesc() - Init the sdesc structure
 * @crypto_shash: cipher handle
 * Return: sdesc initializated
 */
static struct sdesc *init_sdesc(struct crypto_shash *alg)
{
	struct sdesc *sdesc;
	int size;

	size = sizeof(struct shash_desc) + crypto_shash_descsize(alg);
	sdesc = kmalloc(size, GFP_KERNEL);
	if (!sdesc)
		return ERR_PTR(-ENOMEM);

	sdesc->shash.tfm = alg;
	return sdesc;
}

/**
 * calc_hash - calculate the hash for the data and save it in the digest buffer
 * @alg: cipher handle
 * @data: char array data to hash
 * @datalen: len of the data buffer
 * @digest: buffer for store the digest
 * Return: 0 if the digest creation was successful, < 0 if an error occurred
 */
static int calc_hash(struct crypto_shash *alg, const unsigned char *data,
		unsigned int datalen, unsigned char *digest)
{
	struct sdesc *sdesc;
	int ret;

	sdesc = init_sdesc(alg);
	if (IS_ERR(alg)) {
		pr_notice("Error - init_sdesc\n")
		return PTR_ERR(sdesc);
	}

	ret = crypto_shash_digest(&sdesc->shash, data, datalen, digest);
	kfree(sdesc);
	return ret;
}

/**
 * hex_elem_dimension - count number of byte in the node as namevalue char
 * array.
 * @my_node: device tree node element
 * Return: number of byte counted on success, <0 if an error occurred.
 */
int hex_elem_dimension(struct device_node *my_node)
{
	struct device_node *my_child;
	struct property *my_property;
	unsigned long tot_size = 0;
	char *buffer;

	my_child = my_node->child;

	if (!my_child) {
		pr_notice("%s don't have child member\n", my_node->name);
		return -1;
	}

	while (my_child != NULL) {
		my_property = my_child->properties;
		while (my_property != NULL) {
			if (my_property->length > 0) {
				buffer = kmalloc(my_property->length*2
					+ my_property->length,
						GFP_KERNEL);
				if (!buffer) {
					pr_notice("Error - kmalloc\n");
					return -ENOMEM;
				}
				/* property with value */
				hex_dump_to_buffer(my_property->value,
					my_property->length, 32, 2,
					buffer, my_property->length*2
					+ my_property->length,
					false);
				tot_size += strlen(buffer)
					+ strlen(my_property->name);
				kfree(buffer);
			} else {
				tot_size += strlen(my_property->name);
			}
			my_property = my_property->next;
		}
		my_child = my_child->child;
	}

	return tot_size;
}

/**
 * hex_print_elem_string - iterate over the subnode of my_node, concatenate all
 * value as namevalue and then calculate the hash of this string.
 * @my_node: parent node with hash property
 * @alg: cipher handle
 * @hash: buffer for the digest
 * @tot_size: total number of byte in the subnode property
 * Return: 0 on success; < 0 if an error occurred
 */
int hex_print_elem_string(struct device_node *my_node, struct crypto_shash *alg,
			char *hash, int tot_size)
{
	struct device_node *my_child;
	struct property *my_property;
	int rr;
	char *ret, *buffer;

	ret = kmalloc(tot_size, GFP_KERNEL);
	if (!ret)
		return -ENOMEM;

	my_property = my_node->properties;
	my_child = my_node->child;
	if (!my_child) {
		pr_notice("HEX: %s no child member\n", my_node->name);
		kfree(ret);
		return -ENODATA;
	}

	while (my_child != NULL) {
		my_property = my_child->properties;

		while (my_property != NULL) {
			if (my_property->length > 0) {
				buffer = kmalloc(my_property->length*2 +
					my_property->length,
						GFP_KERNEL);
				if (!buffer)
					return -ENOMEM;

				hex_dump_to_buffer(my_property->value,
					my_property->length, 32, 2,
					buffer, my_property->length*2 +
						my_property->length,
					false);

				memcpy(ret, my_property->name,
					strlen(my_property->name));
				memcpy(ret + strlen(my_property->name),
					buffer,
					strlen(buffer));

				ret = ret + strlen(buffer) +
					strlen(my_property->name);
				kfree(buffer);
			} else {
				memcpy(ret, my_property->name,
					strlen(my_property->name));
				ret = ret + strlen(my_property->name);
			}

			my_property = my_property->next;
		}
		my_child = my_child->child;
	}

	strcpy(ret, "\0");
	ret = ret - tot_size;
	rr = calc_hash(alg, ret, strlen(ret), hash);
	kfree(ret);
	return rr;
}

/**
 * verify() - verification of node my_node
 * @my_node: node to be verified
 * @alg: cipher handler
 * Return: 1 no property hash found, 0 on success, < 0 if an error occurred
 */
int verify(struct device_node *my_node, struct crypto_shash *alg)
{
	int tot_size = 0;
	struct property *dts_property;
	char *hash, *dts_hash;
	char *digest;
	int ret = 0;

	dts_property = of_find_property(my_node, "hash", 0);
	if (!dts_property) {
		pr_notice("Error - node [%s] no property hash\n",
				my_node->name);
		return 1;
	}

	dts_hash = dts_property->value;
	tot_size = hex_elem_dimension(my_node);

	if (tot_size <= 0) {
		pr_notice("Error - node [%s] hex negative tot_size\n",
				my_node->name);
		return -ENODATA;
	}

	hash = kmalloc(SHA1_DIGEST_SIZE, GFP_KERNEL);
	if (!hash)
		return -ENOMEM;

	memset(hash, 0, tot_size);

	digest = kmalloc(tot_size, GFP_KERNEL);
	if (!digest) {
		kfree(hash);
		return -ENOMEM;
	}

	ret = hex_print_elem_string(my_node, alg, hash, tot_size);
	if (ret) {
		pr_notice("Error - node [%s] hex_print_elem\n", my_node->name);
		kfree(digest);
		kfree(hash);
		return ret;
	}

	ret = hex_dump_to_buffer(hash, SHA1_DIGEST_SIZE, 32, 2, digest,
		tot_size, false);

	if (ret != strlen(digest)) {
		pr_notice("Error - hex_dump_to_buffer\n");
		kfree(digest);
		kfree(hash);
		return -ENODATA;
	}

	pr_notice("Node [%s] Hash value %s\n", my_node->name, digest);
	pr_notice("Node [%s] Hash len %ld\n", my_node->name, strlen(digest));
	pr_notice("Node [%s] DTS hash len %ld\n", my_node->name,
			strlen(dts_hash));
	pr_notice("Node [%s] DTS hash value %s\n", my_node->name, dts_hash);

	if (strcmp(dts_hash, digest) == 0) {
		pr_notice("!! Child node of [%s] verified !!\n", my_node->name);
	} else {
		pr_notice("ALERT!! child of [%s] node not verified\n",
				my_node->name);
	}

	kfree(digest);
	kfree(hash);
	return 0;
}

/**
 * start_module() - this function called when the module is loaded with
 * insmod module.ko
 * Return: 0 on success; < 0 if an error occurred
 */
int __init start_module(void)
{
	struct device_node *my_node;
	char *hash_alg_name = "sha1";
	struct crypto_shash *alg;
	int ret = 0;

	/* sha1 */
	alg = crypto_alloc_shash(hash_alg_name, CRYPTO_ALG_TYPE_SHASH, 0);
	if (IS_ERR(alg)) {
		pr_notice("Error - crypto_alloc_shash\n");
		return PTR_ERR(alg);
	}
	/* END-sha1 */

	/* DTB node section */
	if (strcmp(node_name, "") == 0) {
		/* take the root node */
		my_node = of_root->child;
		while (my_node != NULL) {
			ret = verify(my_node, alg);
			if (ret < 0) {
				crypto_free_shash(alg);
				return ret;
			}
			my_node = my_node->sibling;
		}
	} else {
		my_node = of_find_node_by_name(NULL, node_name);
		ret = verify(my_node, alg);
		if (ret < 0) {
			crypto_free_shash(alg);
			return ret;
		}
	}

	/* end DTB node section */
	crypto_free_shash(alg);
	return 0;
}

/**
 * end_module() - this function is called when the module is removed with
 * rmmod module.ko
 */
void __exit end_module(void)
{
	pr_notice("Removing module\n");
}

module_init(start_module);
module_exit(end_module);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Mariano Marciello");
MODULE_DESCRIPTION("A simple proof of concept for dtb verification");
