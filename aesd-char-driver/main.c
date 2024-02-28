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

static ssize_t aesd_read(struct file *filp, char __user *buff, size_t count, loff_t *offp)
{
    struct aesd_buffer_entry *entry;
    size_t entry_offset;
    size_t index_buffer;
    size_t minimum_length;
    unsigned long bytes_rem;
    ssize_t retval = 0;
    bool need_unlock = false;

    // Print debug information about the read operation
    pr_debug("AESD Driver: Reading %zu bytes with offset %lld\n", count, *offp);

    mutex_lock(&aesd_device.mutx_lock);
    need_unlock = true; // Set the flag to indicate that mutex_lock has been called

    for (index_buffer = 0; index_buffer < count; ) {
        // Find the buffer entry for the given file position
        entry = aesd_circular_buffer_find_entry_offset_for_fpos(&aesd_device.buffer, *offp, &entry_offset);
        if (entry == NULL) {
            // If no entry found, exit the loop
            pr_debug("AESD Driver: No buffer entry found for offset %lld\n", *offp);
            break;
        }

        // Determine the minimum length to copy
        minimum_length = min(count - index_buffer, entry->size - entry_offset);

        // Copy data from kernel buffer to user buffer
        bytes_rem = copy_to_user(&buff[index_buffer], &entry->buffptr[entry_offset], minimum_length);
        if (bytes_rem != 0) {
            retval = -EFAULT;
            pr_err("AESD Driver: Error copying data to user space\n");
            goto out; // Exit the loop and release the lock
        }

        index_buffer += minimum_length;
        *offp += minimum_length;
    }

    retval = index_buffer;

out:
    if (need_unlock) {
        mutex_unlock(&aesd_device.mutx_lock);
    }

    // Print debug information about the read completion
    if (retval < 0) {
        pr_debug("AESD Driver: Read operation completed with error: %ld\n", retval);
    } else {
        pr_debug("AESD Driver: Successfully read %ld bytes\n", retval);
    }

    return retval;
}

static ssize_t aesd_write(struct file *filp, const char __user *buf, size_t count, loff_t *f_pos)
{
    ssize_t retval = 0;
    size_t index;
    char *new_buffptr;
    const char *del_buffptr;
    unsigned long not_copied;
    struct aesd_buffer_entry entry;

    pr_debug("write %zu bytes with offset %lld\n", count, *f_pos);

    mutex_lock(&aesd_device.mutx_lock);

    if (aesd_device.capacity - aesd_device.offset < count) {
        new_buffptr = krealloc(aesd_device.buffptr, aesd_device.capacity + count, GFP_KERNEL);
        if (new_buffptr == NULL) {
            pr_debug("failed to allocate memory\n");
            retval = -ENOMEM;
            goto write_unlock;
        }
        aesd_device.buffptr = new_buffptr;
        aesd_device.capacity += count;
    }

    not_copied = copy_from_user(&aesd_device.buffptr[aesd_device.offset], buf, count);
    retval = count - not_copied;
    aesd_device.offset += retval;

    for (index = 0; index < aesd_device.offset; index++) {
        if (aesd_device.buffptr[index] == '\n') {
            entry.buffptr = aesd_device.buffptr;
            entry.size = index + 1;
            del_buffptr = aesd_circular_buffer_add_entry(&aesd_device.buffer, &entry);
            kfree(del_buffptr);
            aesd_device.buffptr = NULL;
            aesd_device.capacity = 0;
            aesd_device.offset = 0;
            pr_debug("found newline character, command complete\n");
            break;
        }
    }

write_unlock:
    mutex_unlock(&aesd_device.mutx_lock);

    if (retval < 0) {
        pr_debug("write error %ld\n", retval);
    } else {
        pr_debug("wrote %ld bytes\n", retval);
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

    result = alloc_chrdev_region(&dev, aesd_minor, 1, "aesdchar");
    aesd_major = MAJOR(dev);
    if (result < 0) {
        printk(KERN_WARNING "Can't get major %d\n", aesd_major);
        return result;
    }

    memset(&aesd_device, 0, sizeof(struct aesd_dev));

    mutex_init(&aesd_device.mutx_lock);

    aesd_circular_buffer_init(&aesd_device.buffer);

    result = aesd_setup_cdev(&aesd_device);
    if (result) {
        unregister_chrdev_region(dev, 1);
    }

    return result;
}

void aesd_cleanup_module(void)
{
    uint8_t index;
    struct aesd_buffer_entry *entry;

    dev_t devno = MKDEV(aesd_major, aesd_minor);

    cdev_del(&aesd_device.cdev);

    kfree(aesd_device.buffptr);

    AESD_CIRCULAR_BUFFER_FOREACH(entry, &aesd_device.buffer, index){
        kfree(entry->buffptr);
    }

    unregister_chrdev_region(devno, 1);
}

module_init(aesd_init_module);
module_exit(aesd_cleanup_module);
