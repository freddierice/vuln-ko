// linux
#include <linux/init.h>
#include <linux/module.h> 
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/cdev.h>
#include <linux/slab.h>
#include <linux/device.h>

// common
#include "vuln.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Frederick Rice");

// globals
#define VULN_DEV	"vuln"
dev_t VULN_NUMBER;
struct class *vuln_dev_class;
struct cdev vuln_dev;

// functions
int vuln_open (struct inode *, struct file *);
int vuln_release (struct inode *, struct file *);
ssize_t vuln_read(struct file *, char __user *, size_t, loff_t *);
ssize_t vuln_write(struct file *, const char __user *,size_t, loff_t *);
long vuln_ioctl(struct file *, unsigned int, unsigned long);
char *vuln_devnode(struct device *dev, umode_t *mode);
void give_root(void);

static struct file_operations vuln_fops = 
{
   .owner   		= THIS_MODULE,
   .open			= vuln_open,
   .release 		= vuln_release,
   .read    		= vuln_read,
   .write			= vuln_write,
   .compat_ioctl	= vuln_ioctl,
   .unlocked_ioctl  = vuln_ioctl,
};

// vuln struct
typedef struct vuln_struct {
	void (*v_func)(void*, void*, void*, void*);
	void *v_arg1;
	void *v_arg2;
	void *v_arg3;
	void *v_arg4;
	void *v_data;
} vuln_t;

// register the vuln device
static int vuln_init(void) {

	printk(KERN_INFO "vuln: initializing\n");

	cdev_init(&vuln_dev, &vuln_fops);
	if (alloc_chrdev_region(&VULN_NUMBER, 0, 1, VULN_DEV) < 0)
		goto err_dev;
	if ((vuln_dev_class = class_create(THIS_MODULE, VULN_DEV)) == NULL)
		goto err_class;
	vuln_dev_class->devnode = vuln_devnode;
	if (device_create(vuln_dev_class, NULL, VULN_NUMBER, NULL, VULN_DEV) < 0)
		goto err_create;
	if (cdev_add(&vuln_dev, VULN_NUMBER, 1) == -1)
		goto err_add;

	printk(KERN_INFO "vuln: registered device (%u,%u)\n", MAJOR(VULN_NUMBER), MINOR(VULN_NUMBER));
	return 0;

err_add:
	device_destroy(vuln_dev_class, VULN_NUMBER);
err_create:
	class_destroy(vuln_dev_class);
err_class:
	unregister_chrdev_region(VULN_NUMBER, 1);
err_dev:
	printk(KERN_ERR "vuln: can't register device\n");
	return 1;
}

// unregister the vuln device
static void vuln_exit(void) {
	printk(KERN_INFO "vuln: exiting\n");
	
	device_destroy(vuln_dev_class, VULN_NUMBER);
	class_destroy(vuln_dev_class);
	unregister_chrdev_region(VULN_NUMBER, 1);
}

// vuln_open 
int vuln_open(struct inode *inode, struct file *fptr) {
	printk(KERN_INFO "vuln: opening\n");
	return !(fptr->private_data = (void *)kzalloc(sizeof(vuln_t), GFP_KERNEL));
}

// vuln_release - clean up the file's private_data
int vuln_release(struct inode *inode, struct file *fptr) {
	vuln_t *v;

	printk(KERN_INFO "vuln: closing\n");
	v = (vuln_t *)fptr->private_data;
	if (fptr->private_data)
		kfree(fptr->private_data);

	fptr->private_data = NULL;
	return 0;
}

// vuln_ioctl - where most of the logic happens
long vuln_ioctl(struct file *fptr, unsigned int ioctl_num, unsigned long ioctl_param) {
	vuln_t *v;
	void *give_root_ptr, *data_ptr;
   
	v = (vuln_t *)fptr->private_data;
	data_ptr = (void *)v->v_data;
	give_root_ptr = (void *)give_root;

	printk(KERN_INFO "vuln: ioctl_call %d\n", ioctl_num);
	switch (ioctl_num) {
		case VULN_SET_FUNC:
			printk(KERN_INFO "vuln: in VULN_SET_FUNC\n");
			v->v_func = (void (*)(void*,void*,void*,void*))ioctl_param;
			return 0;
		case VULN_SET_ARG1:
			printk(KERN_INFO "vuln: in VULN_SET_ARG1\n");
			v->v_arg1 = (void *)ioctl_param;
			return 0;
		case VULN_SET_ARG2:
			printk(KERN_INFO "vuln: in VULN_SET_ARG2\n");
			v->v_arg2 = (void *)ioctl_param;
			return 0;
		case VULN_SET_ARG3:
			printk(KERN_INFO "vuln: in VULN_SET_ARG3\n");
			v->v_arg3 = (void *)ioctl_param;
			return 0;
		case VULN_SET_ARG4:
			printk(KERN_INFO "vuln: in VULN_SET_ARG4\n");
			v->v_arg4 = (void *)ioctl_param;
			return 0;
		case VULN_GET_DATA:
			printk(KERN_INFO "vuln: in VULN_GET_DATA\n");
			if (copy_to_user((void *)ioctl_param, (const void *)&data_ptr, sizeof(void *)))
				return -1;
			return 0;
		case VULN_GET_ROOT:
			printk(KERN_INFO "vuln: in VULN_GET_ROOT\n");
			if (copy_to_user((void *)ioctl_param, (const void *)&give_root_ptr, sizeof(void *)))
				return -1;
			return 0;
		case VULN_SET_DATA:
			printk(KERN_INFO "vuln: in VULN_SET_DATA");
			if (copy_from_user(v->v_data, (const void *)ioctl_param, PAGE_SIZE))
				return -1;
			return 0;
		case VULN_TRIGGER:
			printk(KERN_INFO "vuln: executing %p on %p, %p, %p, %p\n", v->v_func, 
				v->v_arg1, v->v_arg2, v->v_arg3, v->v_arg4);
			v->v_func(v->v_arg1, v->v_arg2, v->v_arg3, v->v_arg4);
			return 0;
		default:
			printk(KERN_INFO "vuln: invalid ioctl code\n");
			return -1;
	}

	return 0;
}

char *vuln_devnode(struct device *dev, umode_t *mode) {
	if (mode) *mode = 0666;
	return NULL;
}

// vuln_read - a nop
ssize_t vuln_read(struct file *fptr, char __user *user_buffer, size_t count, 
		loff_t *pos) {
	printk(KERN_INFO "vuln: read\n");
	return 0;
}

// vuln_write - a nop
ssize_t vuln_write(struct file *fptr, const char __user *user_buffer,
		size_t count, loff_t *position) {
	printk(KERN_INFO "vuln: write\n");
	return 0;
}

// give_root - for simple tests to copy init's kernel credentials
void give_root(void) {
	commit_creds(prepare_kernel_cred(NULL));
}

module_init(vuln_init);
module_exit(vuln_exit);
