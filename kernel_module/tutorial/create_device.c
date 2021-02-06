/*
 * This code will create 2 character device with names
 * /dev/mychardev0 and /dev/muchardev1
 */
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>

/*
 * max Minor device
 */
#define MAX_DEV 2

static int mychardev_open(struct inode *inode, struct file *file)
{
	printk("MYCHARDEV: Device open\n");
	return 0;
}

static int mychardev_release(struct inode *inode, struct file *file)
{
	printk("MYCHARDEV: Device close\n");
	return 0;
}

static long mychardev_ioctl(struct file *file, unsigned int cmd, 
	unsigned long arg)
{
	printk("MYCHARDEV: Device ioctl\n");
	return 0;
}

static ssize_t mychardev_read(struct file *file, char __user *buf,
	size_t count, loff_t *offset)
{
	printk("MYCHARDEV: Device read\n");
	return 0;
}

static ssize_t mychardev_write(struct file *file, const char __user *buf,
	size_t count, loff_t *offset)
{
	printk("MYCHARDEV: Device write\n");
	return 0;
}

/*
 * Initialize file_operation
 */
static const struct file_operations mychardev_fops = {	
	.owner           = THIS_MODULE,
	.open            = mychardev_open,
	.release         = mychardev_release,
	.unlocked_ioctl  = mychardev_ioctl,
	.read            = mychardev_read,
	.write           = mychardev_write,
};

/*
 * Device data holder, this structure may be extended to hold addition data
 */
struct mychar_device_data {
	struct cdev cdev;
};

/*
 * Global storage dor device Major number
 */
static int dev_major = 0;

/*
 * sysfs clas structure
 */
static struct class *mychardev_class = NULL;

/*
 * array of mychar_device_data for
 */
static struct mychar_device_data mychardev_data[MAX_DEV];


void mychardev_init(void)
{
	int err, i;
	dev_t dev;
	printk("MYCHARDEV: Init device\n");

	/*
	 * allocate chardev region and assign Major number
	 */
	err = alloc_chrdev_region(&dev, 0, MAX_DEV, "mychardev");

	/*
	 * generate the Major number
	 */
	dev_major = MAJOR(dev);

	/*
	 * create sysfs class
	 * and setting up the correct permission
	 */
	mychardev_class = class_create(THIS_MODULE, "mychardev");

	/*
	 * create the necessary number of device
	 */
	for(i = 0; i < MAX_DEV; i++) {
		/*
		 * init new device
		 */
		cdev_init(&mychardev_data[i].cdev, &mychardev_fops);
		mychardev_data[i].cdev.owner = THIS_MODULE;
		
		/*
		 * add device to the system where "i" is a Minor number 
		 * of the new device
		 */
		cdev_add(&mychardev_data[i].cdev, MKDEV(dev_major, i), 1);

		/*
		 * create device node /dev/mychardev-x where "x" is "i",
		 * equal to the Minor number
		 */
		device_create(mychardev_class, NULL, MKDEV(dev_major, i),
			NULL, "mychardev-%d", i);
	}

}

void mychardev_destroy(void)
{
	int i;
	printk("MYCHARDEV: Destroy device\n");

	for(i = 0; i < MAX_DEV; i++) {
		device_destroy(mychardev_class, MKDEV(dev_major, i));
	}

	class_unregister(mychardev_class);
	class_destroy(mychardev_class);

	unregister_chrdev_region(MKDEV(dev_major, 0), MINORMASK);
}

MODULE_LICENSE("GPL");
