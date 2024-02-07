/**
 * @file aesd-circular-buffer.c
 * @brief Functions and data related to a circular buffer imlementation
 *
 * @author Dan Walkes
 * @date 2020-03-01
 * @copyright Copyright (c) 2020
 *
 */
#ifdef __KERNEL__
#include <linux/string.h>
#else
#include <string.h>
#endif
#include <stdio.h>
#include "aesd-circular-buffer.h"

/**
 * @param buffer the buffer to search for corresponding offset.  Any necessary locking must be performed by caller.
 * @param char_offset the position to search for in the buffer list, describing the zero referenced
 *      character index if all buffer strings were concatenated end to end
 * @param entry_offset_byte_rtn is a pointer specifying a location to store the byte of the returned aesd_buffer_entry
 *      buffptr member corresponding to char_offset.  This value is only set when a matching char_offset is found
 *      in aesd_buffer.
 * @return the struct aesd_buffer_entry structure representing the position described by char_offset, or
 * NULL if this position is not available in the buffer (not enough data is written).
 */



int buffer_empty_flag;
struct aesd_buffer_entry *aesd_circular_buffer_find_entry_offset_for_fpos(struct aesd_circular_buffer *buffer,
        size_t char_offset, size_t *entry_offset_byte_rtn)
{
    printf("Entering aesd_circular_buffer_find_entry_offset_for_fpos\n"); // Print a message indicating entry into the function
    int i = 0 ;
    size_t cum_offset = 0;
    int offset_calc;
    if (!entry_offset_byte_rtn || !buffer) {
        printf("Invalid input parameters\n");
        return NULL;
    }

    if (!buffer->full && buffer->out_offs >= buffer->in_offs) {
        printf("Circular buffer not full and out_offs >= in_offs\n");
        return NULL;
    }

    if (buffer->full && buffer->out_offs < buffer->in_offs) {
        printf("Circular buffer full and out_offs < in_offs\n");
        return NULL;
    }
    if (buffer_empty_flag == 1){
        printf("Circular buffer flag is set \n");
        return NULL;
    }
    for (i = 0; i < AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED; i++) {

        offset_calc = (buffer->out_offs + i) % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
        cum_offset = cum_offset + buffer->entry[offset_calc].size;

        if (char_offset < cum_offset) {
            *entry_offset_byte_rtn = char_offset - (cum_offset - buffer->entry[offset_calc].size);
            printf("Found entry at index %d\n", i);
            return &buffer->entry[offset_calc];
        }
    }


    printf("Entry not found\n");
    return NULL;
}

/**
* Adds entry @param add_entry to @param buffer in the location specified in buffer->in_offs.
* If the buffer was already full, overwrites the oldest entry and advances buffer->out_offs to the
* new start location.
* Any necessary locking must be handled by the caller
* Any memory referenced in @param add_entry must be allocated by and/or must have a lifetime managed by the caller.
*/

void aesd_circular_buffer_add_entry(struct aesd_circular_buffer *buffer, const struct aesd_buffer_entry *add_entry)
{
    printf("Entering aesd_circular_buffer_add_entry\n"); // Print a message indicating entry into the function
    if (buffer->full == true)
    {
        buffer->out_offs = buffer->out_offs + 1;
        buffer->out_offs = buffer->out_offs % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED; // ensure pointer wraps around
    }
    buffer->entry[buffer->in_offs].buffptr = add_entry->buffptr ;
    buffer->entry[buffer->in_offs].size = add_entry->size;
    buffer->in_offs = buffer->in_offs + 1;
    buffer->in_offs = buffer->in_offs % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
    if (buffer->in_offs == 0){
        buffer->full = true;
    }
    buffer_empty_flag = 0;
    }


/**
* Initializes the circular buffer described by @param buffer to an empty struct
*/

void aesd_circular_buffer_init(struct aesd_circular_buffer *buffer)
{
    printf("Initializing circular buffer\n"); // Print a message indicating initialization
    memset(buffer, 0, sizeof(struct aesd_circular_buffer));
    printf("Buffer contents:\n");
    for (int i = 0; i < AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED; ++i) {
        printf("Entry %d: size = %zu", i, buffer->entry[i].size);
    }
}
