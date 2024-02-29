/*
 * aesdchar.h
 *
 *  Created on: Oct 23, 2019
 *      Author: Dan Walkes
 */

#ifndef AESD_CHAR_DRIVER_AESDCHAR_H_
#define AESD_CHAR_DRIVER_AESDCHAR_H_

#include "aesd-circular-buffer.h"

#define AESD_DEBUG 1  //Remove comment on this line to enable debug

#undef PDEBUG             /* undef it, just in case */
#ifdef AESD_DEBUG
#  ifdef __KERNEL__
     /* This one if debugging is on, and kernel space */
#    define PDEBUG(fmt, args...) printk( KERN_DEBUG "aesdchar: " fmt, ## args)
#  else
     /* This one for user space */
#    define PDEBUG(fmt, args...) fprintf(stderr, fmt, ## args)
#  endif
#else
#  define PDEBUG(fmt, args...) /* not debugging: nothing */
#endif


/**
 * @brief AESD Character Device Structure
 * 
 * Designed to be add character devices into the linux kernel
*/
struct aesd_dev
{
    /**
     * TODO: Add structure(s) and locks needed to complete assignment requirements
     */

    struct mutex lock; /* Locking primitive for the driver */
    struct aesd_circular_buffer buffer;  /*Circular buffer struct*/
    struct cdev cdev;     /* Char device structure      */
    char *write_buffer; /*Pointer to dynamically allocated buffer for each device*/
    size_t write_buffer_size; /* Amount of data currently stored in buffer*/
    size_t buff_size; //Total size of buff
};

#endif /* AESD_CHAR_DRIVER_AESDCHAR_H_ */
