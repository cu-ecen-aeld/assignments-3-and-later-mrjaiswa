/**
 * @file aesdchar.c
 * @brief Functions and data related to the AESD char driver implementation
 *
 * Based on the implementation of the "scull" device driver, found in
 * Linux Device Drivers example code.
 *
 * @author Dan Walkes
 * @author __Refactor --> Mrinal Jaiswal
 * @date 2024-2-18
 * @copyright Copyright (c) 2024, 2019
 *
 */


#include "aesdchar.h"

#include <linux/module.h>
#include <linux/init.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/cdev.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/fs.h> // file_operations

int aesd_major =   0; // use dynamic major
int aesd_minor =   0;

MODULE_AUTHOR("Mrinal Jaiswal");
MODULE_LICENSE("Dual BSD/GPL");

struct aesd_dev aesd_device;

int aesd_open(struct inode *inode, struct file *filp)
{
    PDEBUG("open");

    return 0;
}

int aesd_release(struct inode *inode, struct file *filp)
{
    PDEBUG("release");

    return 0;
}

ssize_t aesd_read(struct file *filp, char __user *buf, size_t count,
                loff_t *f_pos)
{
    ssize_t retval = 0;
    size_t offset_in_entry;
    struct aesd_buffer_entry *entry;
    int left_in_entry;

    PDEBUG("%s(): read %zu bytes with offset %lld",__func__, count,*f_pos);

    mutex_lock(&aesd_device.aesd_mutex);
    entry = aesd_circular_buffer_find_entry_offset_for_fpos(&aesd_device.buffer, *f_pos, &offset_in_entry);
    
    if (!entry) {
        printk("!entry");
        mutex_unlock(&aesd_device.aesd_mutex);
    	return 0;
    }
    mutex_unlock(&aesd_device.aesd_mutex);

    PDEBUG("%s(): offset_in_entry=%lu, entry->buffptr=%s, entry->size=%lu\n", __func__, offset_in_entry, entry->buffptr, entry->size);
    
    left_in_entry = entry->size - offset_in_entry;

    retval = left_in_entry > count ? count : left_in_entry;

    PDEBUG("%s(): retval=%lu\n", __func__, retval);

    copy_to_user(buf, entry->buffptr + offset_in_entry, retval);
    *f_pos += retval;

    PDEBUG("=================");

    return retval;
}

ssize_t aesd_write(struct file *filp, const char __user *buf, size_t count,
                loff_t *f_pos)
{
    ssize_t retval = -ENOMEM;
    struct aesd_buffer_entry entry;
    char* temp;
    size_t total;

    PDEBUG("write %zu bytes with offset %lld",count,*f_pos);

    total = count + aesd_device.temp_buf_size;
    
    temp = (char *)kmalloc(total, GFP_KERNEL);
    if (!temp) {
    	printk("Error: No memory allocated\n");
	return retval;
    }

    if (aesd_device.temp_buf != NULL) {
    	memcpy(temp, aesd_device.temp_buf, aesd_device.temp_buf_size);
    }

    if (copy_from_user(temp + aesd_device.temp_buf_size, buf, count) != 0) {
        printk("copy_from_user failed");
        return 0;	
    }

    if (temp[total - 1] == '\n') {
    	
	entry.buffptr = temp;
    
        entry.size = total;

	mutex_lock(&aesd_device.aesd_mutex);
        aesd_circular_buffer_add_entry(&aesd_device.buffer, &entry);


        *f_pos += total;

        retval = count;

        if (aesd_device.temp_buf != NULL) {
            kfree(aesd_device.temp_buf);
	    aesd_device.temp_buf = NULL;
	    aesd_device.temp_buf_size = 0;
	}

	mutex_unlock(&aesd_device.aesd_mutex);
    
    } else {

        if (aesd_device.temp_buf)
		kfree(aesd_device.temp_buf);

	mutex_lock(&aesd_device.aesd_mutex);
	aesd_device.temp_buf = temp;
	aesd_device.temp_buf_size += count;

	mutex_unlock(&aesd_device.aesd_mutex);
	retval = count;
    }


    return retval;
}



struct file_operations aesd_fops = {
    .owner =    THIS_MODULE,
    .read =     aesd_read,
    .write =    aesd_write,
    .open =     aesd_open,
    .release =  aesd_release,
};

static int aesd_setup_cdev(struct aesd_dev *dev)
{
    int err, devno = MKDEV(aesd_major, aesd_minor);

    cdev_init(&dev->cdev, &aesd_fops);
    dev->cdev.owner = THIS_MODULE;
    dev->cdev.ops = &aesd_fops;

    err = cdev_add(&dev->cdev, devno, 1);
    if (err) {
        printk(KERN_ERR "Error %d adding aesd cdev", err);
    }

    return err;
}

int aesd_init_module(void)
{
    dev_t dev = 0;
    int result;
    result = alloc_chrdev_region(&dev, aesd_minor, 1,
            "aesdchar");
    aesd_major = MAJOR(dev);
    if (result < 0) {
        printk(KERN_WARNING "Can't get major %d\n", aesd_major);
        return result;
    }
    memset(&aesd_device,0,sizeof(struct aesd_dev));

    /**
     * TODO: initialize the AESD specific portion of the device
     */

    PDEBUG("%s(): << \n", __func__);
    
    aesd_device.buffer.full = false;
    aesd_device.temp_buf = NULL;
    aesd_device.temp_buf_size = 0;
    mutex_init(&aesd_device.aesd_mutex);

    result = aesd_setup_cdev(&aesd_device);

    if( result ) {
        unregister_chrdev_region(dev, 1);
    }
    return result;

}

void aesd_cleanup_module(void)
{
    dev_t devno = MKDEV(aesd_major, aesd_minor);
    struct aesd_buffer_entry *entry;
    int index = 0;

    cdev_del(&aesd_device.cdev);

    /**
     * TODO: cleanup AESD specific poritions here as necessary
     */

    mutex_destroy(&aesd_device.aesd_mutex);

    AESD_CIRCULAR_BUFFER_FOREACH(entry, &aesd_device.buffer, index) {
        kfree(entry->buffptr);
    }

    unregister_chrdev_region(devno, 1);
}



module_init(aesd_init_module);
module_exit(aesd_cleanup_module);
