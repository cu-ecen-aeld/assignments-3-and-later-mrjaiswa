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
#include <errno.h>
#endif
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

struct aesd_buffer_entry *aesd_circular_buffer_find_entry_offset_for_fpos(struct aesd_circular_buffer *buffer,
            size_t char_offset, size_t *entry_offset_byte_rtn )
{
    /**
    * TODO: implement per description
    */
    
	int count = 0;
    	int position = buffer->out_offs;
	char_offset = char_offset+1;
	
	while(count<AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED)
	{
		if(buffer->entry[position].size >= char_offset)
		{
			*entry_offset_byte_rtn = char_offset-1;
			
			return &buffer->entry[position];
		}
		
		else
		{
			char_offset -= buffer->entry[position].size;
		}
		
		count++;
		position++;
		position %= AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
	}
	
	return NULL;

}

/**
* Adds entry @param add_entry to @param buffer in the location specified in buffer->in_offs.
* If the buffer was already full, overwrites the oldest entry and advances buffer->out_offs to the
* new start location.
* Any necessary locking must be handled by the caller
* Any memory referenced in @param add_entry must be allocated by and/or must have a lifetime managed by the caller.
*/
char *aesd_circular_buffer_add_entry(struct aesd_circular_buffer *buffer, const struct aesd_buffer_entry *add_entry)
{
    /**
    * TODO: implement per description
    */
    
    char *returnchar_ptr = NULL;
    
    if(true == buffer->full)
    {
    	returnchar_ptr = (char *)buffer->entry[buffer->in_offs].buffptr;

    	buffer->total_buff_size -= buffer->entry[buffer->in_offs].size;	
    	buffer->entry[buffer->in_offs] = *add_entry;
    	buffer->total_buff_size += add_entry->size;
    	buffer->in_offs++;
    	buffer->in_offs %= AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
    	buffer->out_offs++;
    	buffer->out_offs %= AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
    }
    else
    {
    	buffer->entry[buffer->in_offs] = *add_entry;
    	buffer->total_buff_size += add_entry->size;
    	buffer->in_offs++;
    	buffer->in_offs %= AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;    	
    
    }
    
    
    if(buffer->in_offs == buffer->out_offs)
    {
    	buffer->full = true;
    }
    else 
    {
    	buffer->full = false;
    }
    
    return returnchar_ptr;
}
