#include "threading.h"
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

// Optional: use these functions to add debug or error prints to your application
#define DEBUG_LOG(msg,...)
//#define DEBUG_LOG(msg,...) printf("threading: " msg "\n" , ##__VA_ARGS__)
#define ERROR_LOG(msg,...) printf("threading ERROR: " msg "\n" , ##__VA_ARGS__)

void* threadfunc(void* thread_param)
{
    struct thread_data* thread_func_args = (struct thread_data *) thread_param;
    int ret_val;								                         

    ret_val = usleep((thread_func_args->wait_to_obtain_ms)*1000);           //wait for required msec to obtain the mutex
    
    if(ret_val==0)
    {
        thread_func_args->thread_status_success = true;                  //check conditions if usleep succeeded
    }		 
    else
    {
        thread_func_args->thread_status_success = false;
        perror("Sleep failed");

    }


    ret_val = pthread_mutex_lock(thread_func_args->mutex);				    //lock the mutex
    if(ret_val==0)
    {
        thread_func_args->thread_status_success = true;                   //if pthread_mutex_lock succeeded
    }                
    else
    {
        thread_func_args->thread_status_success = false;
        perror("Mutex lock error ");

    }
    
    ret_val = usleep((thread_func_args->wait_to_release_ms)*1000);		 	//wait for required msec to release the mutex
    if(ret_val==0)
    {
        thread_func_args->thread_status_success = true;                   //check conditions if usleep succeeded
    }                
    else
    {
        thread_func_args->thread_status_success = false;
	perror("Sleep failed");

    }


    ret_val = pthread_mutex_unlock(thread_func_args->mutex);			    //unlock the mutex
    if(ret_val==0)
    {
        thread_func_args->thread_status_success = true;
    }                
    else
    {
        thread_func_args->thread_status_success = false;
        perror("Mutex unlock error ");

    }
    return thread_param;
}


bool start_thread_obtaining_mutex(pthread_t *thread, pthread_mutex_t *mutex,int wait_to_obtain_ms, int wait_to_release_ms)
{
     struct thread_data *thread_data_instance= malloc(sizeof(struct thread_data*)); 				//allocate memory 
     if(thread_data_instance == NULL)
     {
        ERROR_LOG("Heap Error\n");
        return false;
     }		

     thread_data_instance->mutex = mutex;									//assign mutex to the structure
     thread_data_instance->wait_to_obtain_ms = wait_to_obtain_ms;						//assign the obtain wait time to the structure
     thread_data_instance->wait_to_release_ms = wait_to_release_ms;						//assign teh release wait time to the structure

     int rc = pthread_create(thread, NULL, threadfunc, (void *)thread_data_instance);				//create the thread and check the return value
     if(rc==0)
     {
        return true;
     }											//if thread created successfully return true
     else
     {
        return false;
     }											//else return false

    return false;
}

