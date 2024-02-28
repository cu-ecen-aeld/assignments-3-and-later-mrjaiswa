#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <errno.h>
#include <stdbool.h>
#include <fcntl.h>
#include <signal.h>
#include <netdb.h>
#include <syslog.h>
#include <pthread.h>
#include <time.h>
#include "aesd_ioctl.h"

#define PORT ("9000")
#define TEMP_BUFFER_SIZE (3)
#define USE_AESD_CHAR_DEVICE

#ifdef USE_AESD_CHAR_DEVICE
#define AESDSOCKET_FILEPATH ("/dev/aesdchar")
#else
#define AESDSOCKET_FILEPATH ("/var/tmp/aesdsocketdata")
bool elapsed_10sec = false;
pthread_mutex_t mutex;
timer_t timer;
#endif
int server_socket_fd, client_socket_fd;
bool closed_flag = false;

const char* ioctl_string = "AESDCHAR_IOCSEEKTO:";

typedef struct 
{
    pthread_t threadid;
    int client_str_fd;
    struct sockaddr_in client_str_address;
    bool thread_status;
} THREAD_DATA;

typedef struct ll_node
{
    THREAD_DATA tdata;
    struct ll_node *next;
} NODE;

#ifndef USE_AESD_CHAR_DEVICE
int init_timer(void){

    int status= timer_create(CLOCK_REALTIME, NULL, &timer);
    
    if(-1 == status){
    	return status;
    }
    
    struct itimerspec d_10;

    d_10.it_value.tv_sec = 10;
    d_10.it_value.tv_nsec = 0;
    d_10.it_interval.tv_sec = 10;
    d_10.it_interval.tv_nsec = 0;

    status = timer_settime(timer, 0, &d_10, NULL);
    
    if(-1 == status){
    	return status;
    }
    
    return 0;
}


void timer_10_sec(void)
{
    time_t timestamp;
    char buffer[50];

    struct tm* tmp;

    time(&timestamp);
    tmp = localtime(&timestamp);

    strftime(buffer, sizeof(buffer), "timestamp: %a, %d %b %Y %T %z\n", tmp);

    lseek(aesdsocketdata_fd, 0, SEEK_END);

    pthread_mutex_lock(&mutex);
    
    write(aesdsocketdata_fd, buffer, strlen(buffer));
    
    pthread_mutex_unlock(&mutex);

}
#endif

int node_insert( NODE **head, NODE *new_thread)
{
    if( new_thread == NULL )
    {
        return -1;
    }
    new_thread->next = *head;
    *head =  new_thread;
    return 0;
}

void signal_handler(int signum)
{
    	if (SIGINT == signum || SIGTERM == signum) {
    		syslog(LOG_DEBUG, "SIGINT or SIGTERM signal received\n");
		printf("SIGINT or SIGTERM occured\n");
		closed_flag = true;
    	}
    	#ifndef USE_AESD_CHAR_DEVICE
    	else if(signum == SIGALRM)
    	{
        	syslog(LOG_DEBUG, "SIGALRM signal recevied\n");
        	elapsed_10sec = true;
    	}
    	#endif

}

void cleanup()
{
    close(server_socket_fd);
    unlink(AESDSOCKET_FILEPATH);
    #ifndef USE_AESD_CHAR_DEVICE
    pthread_mutex_destroy(&mutex);
    timer_delete(timer);
    #endif
    closelog();
    exit(0);
}

void *new_thread_fn( void *t_parameters )
{
    THREAD_DATA *t_data = (THREAD_DATA *) t_parameters;
    char address_string[20];
    const char *client_ip;
    struct sockaddr_in *p = (struct sockaddr_in *)&t_data->client_str_address;  
    char temp_buffer[TEMP_BUFFER_SIZE];
    int packet_size;
    bool packet_received  = false;
    int count = 0;
    int recv_buff_len = 0;
    int prev_len = TEMP_BUFFER_SIZE;
    char *recieved_packets;
    
    client_ip = inet_ntop(AF_INET, &p->sin_addr, address_string, sizeof(address_string));
    syslog(LOG_DEBUG, "Connected with %s\n\r",client_ip ); 
     
    memset(temp_buffer, '\0', TEMP_BUFFER_SIZE);
    
    while( false == packet_received )
    {
    	int i=0;
        packet_size = 0;

        if( -1 == recv(t_data->client_str_fd, &temp_buffer, TEMP_BUFFER_SIZE, 0))
        {
            syslog(LOG_ERR, "recv ");
        }
        
        while(i< TEMP_BUFFER_SIZE)
        {
	       packet_size++;
        	 if( '\n' == temp_buffer[i] )
        	 {
           		     packet_received = true;
             		     break;
        	 }
         i++;
        }

        if(count != 0)
        {
            char *ptr = realloc(recieved_packets, prev_len+packet_size);
            if(ptr != NULL)
            {
                recieved_packets = ptr;
                prev_len  += packet_size;
                
            }
            else
            {
                syslog(LOG_ERR, "realloc failed");
                
            }
            recv_buff_len  = prev_len ;
        }
        else
        {
            recieved_packets = (char *)malloc(packet_size);
            if(recieved_packets == NULL)
            {
                syslog(LOG_ERR, "malloc failed");
            }

            memset(recieved_packets, '\0', packet_size);
            recv_buff_len  = packet_size;
            
        }
        memcpy((count * TEMP_BUFFER_SIZE) + recieved_packets, temp_buffer, packet_size);
        count++;
    }

//    lseek(aesdsocketdata_fd, 0, SEEK_END);

#ifndef USE_AESD_CHAR_DEVICE
    int status = pthread_mutex_lock(&mutex);
    if( status != 0 )
    {
        perror("mutex lock");
    }
#endif
	//open the socket data file
	int aesdsocketdata_fd= open(AESDSOCKET_FILEPATH,O_RDWR | O_CREAT | O_APPEND,0666);

	if( -1 == aesdsocketdata_fd ){
	
		syslog(LOG_ERR, "not able to open file %s",AESDSOCKET_FILEPATH);
		
	}
	
    if(0 == strncmp(recieved_packets, ioctl_string, strlen(ioctl_string)))
    {
        struct aesd_seekto seek_info; 
        
        sscanf(recieved_packets, "AESDCHAR_IOCSEEKTO:%d,%d", &seek_info.write_cmd, &seek_info.write_cmd_offset);
        
        if( ioctl(aesdsocketdata_fd, AESDCHAR_IOCSEEKTO, &seek_info))
        {
            syslog(LOG_ERR, "Ioctl %d", errno);
        }
    }
    else
    {
        if(-1 == write(aesdsocketdata_fd, recieved_packets, recv_buff_len))
        {
            syslog(LOG_ERR, "write");
        }
    }
    
    memset(temp_buffer, '\0', TEMP_BUFFER_SIZE);
    
    #ifndef USE_AESD_CHAR_DEVICE
    lseek(aesdsocketdata_fd, 0, SEEK_SET);
    #endif
    
    int read_bytes;
    char *recv_buffer = (char *)malloc(TEMP_BUFFER_SIZE);

    if (NULL == recv_buffer) {
        syslog(LOG_ERR, "not able to allocate memory");
        printf("not able to allocate memory\n");
    }
    
    while( (read_bytes = read(aesdsocketdata_fd, recv_buffer, TEMP_BUFFER_SIZE))>0)
    {

        int bytes_sent = send(t_data->client_str_fd, recv_buffer, read_bytes, 0);

        if (bytes_sent == -1) 
        {
            syslog(LOG_ERR, "send");
            break;
        }
    }
    close(aesdsocketdata_fd);
    #ifndef USE_AESD_CHAR_DEVICE
    status = pthread_mutex_unlock(&mutex);
    if( status!=0 )
    {
        syslog(LOG_ERR, "mutex unlock failed");
    }
    #endif
    
    if(read_bytes == -1)
    {
        syslog(LOG_ERR, "read failed");
        printf("read failed\n");
    }
    
    free(recv_buffer);
    free(recieved_packets);
    close(t_data->client_str_fd);
    t_data->thread_status = true;
    syslog(LOG_DEBUG, "Closed with %s\n\r",client_ip ); 
    return 0;
}


int main(int argc, char *argv[]){

	bool daemon_process=false;
	struct sockaddr_in Client_addr;
	socklen_t addr_size;
	struct addrinfo hints;
    	struct addrinfo *server_info;
    	int status;	
    	int enable = 1;	
        
	//open syslog
	openlog(NULL, 0, LOG_USER);
	
	//check if deamon process
	if ((argc > 1) && (!strcmp("-d", (char*) argv[1]))){
		daemon_process=true;
		syslog(LOG_DEBUG, "aesdsocket as Daemon");
	}
	else{
		syslog(LOG_ERR, "Daemon failed");
		printf("Daemon failed");
	}



	//signal handlers
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);
#ifdef USE_AESD_CHAR_DEVICE
#else
signal(SIGALRM, signal_handler);
#endif
	
	//hints
    	memset(&hints, 0, sizeof(hints));    
    	hints.ai_family = AF_INET;        
    	hints.ai_socktype = SOCK_STREAM;    
    	hints.ai_flags = AI_PASSIVE;        	
	
	//getaddrinfo
	status = getaddrinfo(NULL, PORT , &hints, &server_info);
	if (status != 0){
		syslog(LOG_ERR, "Client connection failed");
		closelog();
		return -1;
	}
	
	//create socket
	server_socket_fd = socket(server_info->ai_family,server_info->ai_socktype, server_info->ai_protocol );
	
    	if ( -1 == server_socket_fd ){
    		syslog(LOG_ERR, "Client connection failed");
    		closelog(); 
    	        return -1;
    	}

	// Reference : Linux System Programming Book
    	if (setsockopt(server_socket_fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0)
    	{
    		printf("Error : setsockopt\n");
    	}
    	
    	int flags = fcntl(server_socket_fd, F_GETFL);
    	fcntl(server_socket_fd, F_SETFL, flags | O_NONBLOCK);
    
    	
	//binding
	status= bind(server_socket_fd,server_info->ai_addr,server_info->ai_addrlen);
	if ( status != 0){
		syslog(LOG_ERR, "Client connection failed due to binding");
		closelog();
		return -1;
	}
	
	if(daemon_process){
		status = daemon(0, 0);
		if (status == -1){
			syslog(LOG_ERR, "Daemon process failed!!!");
		}
	}
	
	status = listen(server_socket_fd, 10);
    	if( status != 0 )
    	{
        	syslog(LOG_ERR, "Client connection failed");
        	closelog();
        	return -1;
    	}
    		
	freeaddrinfo(server_info);
	addr_size = sizeof Client_addr;
	
	#ifndef USE_AESD_CHAR_DEVICE
 	status= init_timer();
    	if(status == -1)
    	{
    	    perror("timer init failed");
    	}
    	
    	pthread_mutex_init(&mutex, NULL);
	#endif
	
	
    	NODE *head =NULL;
    	NODE *prev,*current;
    
	while(!closed_flag)
	{
	#ifndef USE_AESD_CHAR_DEVICE
		if(elapsed_10sec)
        	{
            		elapsed_10sec = false;
            		timer_10_sec();
        	}
        #endif
        	
		status=0;
		
		//accept
		client_socket_fd= accept(server_socket_fd, (struct sockaddr *)&Client_addr, &addr_size);
	 	if(client_socket_fd == -1 )
	 	{
	 	            if(errno == EWOULDBLOCK)
           		     {
                		continue;
            		     }
            		syslog(LOG_ERR, "Client connection failed");
            		continue;
        	}
        	NODE *new_thread = (NODE *)malloc(sizeof(NODE));
        	new_thread->tdata.thread_status = false;
        	new_thread->tdata.client_str_fd= client_socket_fd;
        	new_thread->tdata.client_str_address = Client_addr;        

		pthread_create( &(new_thread->tdata.threadid), NULL, &new_thread_fn, &(new_thread->tdata));

        	node_insert(&head, new_thread);
    	}
    	
    	current =  head;
    	prev = head;		
	    	
    	while(current)
    	{
    		if(current->tdata.thread_status == true){
        		if(current != head)
        		{
            			prev->next = current->next;
            			current->next = NULL;
            			pthread_join(current->tdata.threadid, NULL);
            			free(current);
            			current = prev->next;
	
        		}
        		else if (current == head)
        		{ 
            			head = current->next;
            			pthread_join(current->tdata.threadid, NULL);
            			free(current);
            			current = head;	

        		}
        	}
        	else 
        	{
        		prev = current;
        		current = current->next;
        	}
    	}
        cleanup();	
		 
}
