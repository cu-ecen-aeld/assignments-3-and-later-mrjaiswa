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

#include "aesd_ioctl.h"

int aesd_major = 0; // use dynamic major
int aesd_minor = 0;

MODULE_AUTHOR("Mrinal");
MODULE_LICENSE("Dual BSD/GPL");

static struct aesd_dev aesd_device;

static int aesd_open(struct inode *inode, struct file *filp)
{
	PDEBUG("open");

	return 0;
}

static int aesd_release(struct inode *inode, struct file *filp)
{
	PDEBUG("release");

	return 0;
}

static size_t aesd_size(void)
{
	uint8_t index;
	struct aesd_buffer_entry *entry;
	size_t size = 0;

	// Unused entries are expected to have zero size
	AESD_CIRCULAR_BUFFER_FOREACH(entry, &aesd_device.buffer, index)
	{
		size += entry->size;
	}

	return size;
}

static loff_t aesd_llseek(struct file *file, loff_t offset, int whence)
{
	loff_t ret;
	loff_t size;

	PDEBUG("llseek with offset %lld and whence %d", offset, whence);

	mutex_lock(&aesd_device.lock);

	size = aesd_size();

	switch (whence) {
	case SEEK_SET:
	case SEEK_CUR:
	case SEEK_END:
		ret = fixed_size_llseek(file, offset, whence, size);
		break;
	default:
		ret = -EINVAL;
	}

	mutex_unlock(&aesd_device.lock);

	return ret;
}

static ssize_t aesd_read(struct file *filp, char __user *buff, size_t count,
			 loff_t *offp)
{
	struct aesd_buffer_entry *entry;
	size_t entry_offset;
	size_t buff_index;
	size_t min_length;
	unsigned long not_copied;
	ssize_t retval = 0;

	PDEBUG("read %zu bytes with offset %lld", count, *offp);

	mutex_lock(&aesd_device.lock);

	buff_index = 0;
	while (buff_index < count) {
		entry = aesd_circular_buffer_find_entry_offset_for_fpos(
			&aesd_device.buffer, *offp, &entry_offset);
		if (entry == NULL) {
			break;
		}

		min_length =
			min(count - buff_index, entry->size - entry_offset);
		not_copied = copy_to_user(&buff[buff_index],
					  &entry->buffptr[entry_offset],
					  min_length);
		if (not_copied != 0) {
			retval = -EFAULT;
			goto read_unlock;
		}

		buff_index += min_length;
		*offp += min_length;
	}

	retval = buff_index;

read_unlock:
	mutex_unlock(&aesd_device.lock);

	if (retval < 0) {
		PDEBUG("read error %ld", retval);
	} else {
		PDEBUG("read %ld bytes", retval);
	}

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

static long aesd_unlocked_ioctl(struct file *file, unsigned int cmd,
				unsigned long arg)
{
	unsigned long not_copied;
	struct aesd_seekto seekto;
	uint32_t count;
	uint8_t index;
	size_t offset;

	switch (cmd) {
	case AESDCHAR_IOCSEEKTO:
		not_copied = copy_from_user(&seekto, (const void __user *)arg,
					sizeof(seekto));
		if (not_copied != 0) {
			return -EFAULT;
		}
		break;
	default:
		return -ENOTTY;
	}

	// Empty buffer
	if (!aesd_device.buffer.full && aesd_device.buffer.out_offs == aesd_device.buffer.in_offs) {
		return -EINVAL;
	}

	offset = 0;
	count = 0;
	index = aesd_device.buffer.out_offs;
	do {
		if (count == seekto.write_cmd) {
			break;
		}
		offset += aesd_device.buffer.entry[index].size;
		count++;
		index = (index + 1) % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
	} while (index != aesd_device.buffer.in_offs);

	if (count != seekto.write_cmd) {
		return -EINVAL;
	}

	if (seekto.write_cmd_offset >= aesd_device.buffer.entry[index].size) {
		return -EINVAL;
	}

	file->f_pos = offset + seekto.write_cmd_offset;

	return 0;
}

struct file_operations aesd_fops = {
	.owner = THIS_MODULE,
	.llseek = aesd_llseek,
	.read = aesd_read,
	.write = aesd_write,
	.unlocked_ioctl = aesd_unlocked_ioctl,
	.open = aesd_open,
	.release = aesd_release,
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

static int aesd_init_module(void)
{
	dev_t dev = 0;
	int result;

	result = alloc_chrdev_region(&dev, aesd_minor, 1, "aesdchar");
	aesd_major = MAJOR(dev);
	if (result < 0) {
		printk(KERN_WARNING "Can't get major %d\n", aesd_major);
		return result;
	}

	memset(&aesd_device, 0, sizeof(struct aesd_dev));

	mutex_init(&aesd_device.lock);

	aesd_circular_buffer_init(&aesd_device.buffer);

	result = aesd_setup_cdev(&aesd_device);
	if (result) {
		unregister_chrdev_region(dev, 1);
	}

	return result;
}

static void aesd_cleanup_module(void)
{
	uint8_t index;
	struct aesd_buffer_entry *entry;

	dev_t devno = MKDEV(aesd_major, aesd_minor);

	cdev_del(&aesd_device.cdev);

	kfree(aesd_device.buffptr);

	AESD_CIRCULAR_BUFFER_FOREACH(entry, &aesd_device.buffer, index)
	{
		kfree(entry->buffptr);
	}

	unregister_chrdev_region(devno, 1);
}

module_init(aesd_init_module);
module_exit(aesd_cleanup_module);
