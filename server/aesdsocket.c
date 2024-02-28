#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdbool.h>
#include <pthread.h>
#include <signal.h>
#include <sys/queue.h>

#include <time.h>
#include "aesd_ioctl.h"

#define PORT_NUMBER ("9000")
#define TEMP_BUFFER_SIZE (3)
#define USE_AESD_CHAR_DEVICE

// Define struct thread_data before struct list_data
struct thread_data {
    pthread_t thread_id;
    int client_fd;
    struct sockaddr_in client_address;
    bool thread_status; // Added thread_status field
};

// Define struct list_data
struct list_data {
    struct thread_data info;
    SLIST_ENTRY(list_data) entries;
};

#ifdef USE_AESD_CHAR_DEVICE
#define AESD_DATA_FILEPATH ("/dev/aesdchar")
#else
#define AESD_DATA_FILEPATH ("/var/tmp/aesdsocketdata")
bool elapsed_10_seconds = false;
pthread_mutex_t mutex;
timer_t timer;
#endif
SLIST_HEAD(slisthead, list_data) head;
pthread_mutex_t list_mutex = PTHREAD_MUTEX_INITIALIZER;
int server_socket_fd, client_socket_fd;
bool closed_flag = false;


// Function prototypes
void sig_handler(int signal);
void add_to_list(struct thread_data *data);
void process_list();
#ifndef USE_AESD_CHAR_DEVICE
void* timestamp_thread(void* arg);
#endif
void cleanup();
void *thread_function(void *parameters);

const char *ioctl_string = "AESDCHAR_IOCSEEKTO:";

void sig_handler(int signal) {
    printf("Caught signal %d\n", signal);
    if ((signal == SIGINT) || (signal == SIGTERM)) {
        closed_flag = true;

        syslog(LOG_INFO, "Closing file descriptors...\n");
        close(server_socket_fd);
        close(client_socket_fd);
        syslog(LOG_INFO, "Destroying list mutex...\n");
        pthread_mutex_destroy(&list_mutex);
        exit(0);
    }
}
#ifndef USE_AESD_CHAR_DEVICE
void* timestamp_thread(void* arg) {
    while (!terminate_program) {
        time_t current_time;
        time(&current_time);
        char timestamp[50];
        strftime(timestamp, sizeof(timestamp), "timestamp:%a, %d %b %Y %H:%M:%S %z", localtime(&current_time));
        syslog(LOG_INFO, "Timestamp: %s\n", timestamp);
        pthread_mutex_lock(&file_mutex);
        lseek(file_fd, 0, SEEK_END);  // Move to the end of the file
        write(file_fd, timestamp, strlen(timestamp));
        write(file_fd, "\n", 1);  // Add a newline character
        pthread_mutex_unlock(&file_mutex);

        sleep(10);
    }

    return NULL;
}
#endif
void add_to_list(struct thread_data *data) {
    struct list_data *new_entry = malloc(sizeof(struct list_data));
    if (new_entry == NULL) {
        perror("malloc failure");
        exit(EXIT_FAILURE);
    }

    new_entry->info = *data;

    pthread_mutex_lock(&list_mutex);
    SLIST_INSERT_HEAD(&head, new_entry, entries);
    pthread_mutex_unlock(&list_mutex);
}

void process_list() {
    struct list_data *entry;

    pthread_mutex_lock(&list_mutex);
    SLIST_FOREACH(entry, &head, entries) {
        syslog(LOG_INFO, "Thread ID: %lu\n", entry->info.thread_id);
    }
    pthread_mutex_unlock(&list_mutex);
}
/**
void* thread_function(void* parameters) {
    struct thread_data *thread_data = (struct thread_data *)parameters;
    char address_string[20];
    const char *client_ip;
    struct sockaddr_in *addr = &thread_data->client_address;
    char temp_buffer[TEMP_BUFFER_SIZE];
    int packet_size;
    bool packet_received = false;
    int count = 0;
    char *received_packets = NULL;

    client_ip = inet_ntop(AF_INET, &addr->sin_addr, address_string, sizeof(address_string));
    syslog(LOG_DEBUG, "Connected with %s\n", client_ip);

    while (!packet_received) {
        packet_size = recv(thread_data->client_fd, temp_buffer, TEMP_BUFFER_SIZE, 0);
        if (packet_size == -1) {
            syslog(LOG_ERR, "recv error: %s\n", strerror(errno));
            break;
        }
        for (int i = 0; i < packet_size; i++) {
            if (temp_buffer[i] == '\n') {
                packet_received = true;
                break;
            }
        }

        received_packets = realloc(received_packets, count * TEMP_BUFFER_SIZE + packet_size);
        if (received_packets == NULL) {
            syslog(LOG_ERR, "realloc failed");
            break;
        }
        memcpy(received_packets + count * TEMP_BUFFER_SIZE, temp_buffer, packet_size);
        count++;
    }

    int aesd_data_fd = open(AESD_DATA_FILEPATH, O_RDWR | O_CREAT | O_APPEND, 0666);
    if (aesd_data_fd == -1) {
        syslog(LOG_ERR, "Failed to open file %s: %s", AESD_DATA_FILEPATH, strerror(errno));
        return NULL;
    }

    if (strncmp(received_packets, ioctl_string, strlen(ioctl_string)) == 0) {
        struct aesd_seekto seek_info;
        sscanf(received_packets, "AESDCHAR_IOCSEEKTO:%d,%d", &seek_info.write_cmd, &seek_info.write_cmd_offset);
        if (ioctl(aesd_data_fd, AESDCHAR_IOCSEEKTO, &seek_info)) {
            syslog(LOG_ERR, "Ioctl failed: %s", strerror(errno));
        }
    } else {
        if (write(aesd_data_fd, received_packets, count * TEMP_BUFFER_SIZE) == -1) {
            syslog(LOG_ERR, "Write failed: %s", strerror(errno));
        }
    }

    lseek(aesd_data_fd, 0, SEEK_SET);

    int read_bytes;
    char recv_buffer[TEMP_BUFFER_SIZE];
    while ((read_bytes = read(aesd_data_fd, recv_buffer, TEMP_BUFFER_SIZE)) > 0) {
        int bytes_sent = send(thread_data->client_fd, recv_buffer, read_bytes, 0);
        if (bytes_sent == -1) {
            syslog(LOG_ERR, "send error: %s", strerror(errno));
            break;
        }
    }

    if (read_bytes == -1) {
        syslog(LOG_ERR, "read failed: %s", strerror(errno));
    }

    free(received_packets);
    close(aesd_data_fd);
    close(thread_data->client_fd);
    thread_data->thread_status = true;
    syslog(LOG_DEBUG, "Closed with %s\n", client_ip);
    return NULL;
}
*/

void* thread_function(void* parameters) {
    struct thread_data *thread_data = (struct thread_data *)parameters;
    char address_string[20];
    const char *client_ip;
    struct sockaddr_in *addr = &thread_data->client_address;
    char temp_buffer[TEMP_BUFFER_SIZE];
    int packet_size;
    bool packet_received = false;
    int count = 0;
    char *received_packets = NULL;

    client_ip = inet_ntop(AF_INET, &addr->sin_addr, address_string, sizeof(address_string));
    syslog(LOG_DEBUG, "Connected with %s\n", client_ip);

    while (!packet_received) {
        packet_size = recv(thread_data->client_fd, temp_buffer, TEMP_BUFFER_SIZE, 0);
        if (packet_size == -1) {
            syslog(LOG_ERR, "recv error: %s\n", strerror(errno));
            break;
        }
        for (int i = 0; i < packet_size; i++) {
            if (temp_buffer[i] == '\n') {
                packet_received = true;
                break;
            }
        }

        received_packets = realloc(received_packets, count * TEMP_BUFFER_SIZE + packet_size);
        if (received_packets == NULL) {
            syslog(LOG_ERR, "realloc failed");
            break;
        }
        memcpy(received_packets + count * TEMP_BUFFER_SIZE, temp_buffer, packet_size);
        count++;
    }

    int aesd_data_fd = open(AESD_DATA_FILEPATH, O_RDWR | O_CREAT | O_APPEND, 0666);
    if (aesd_data_fd == -1) {
        syslog(LOG_ERR, "Failed to open file %s: %s", AESD_DATA_FILEPATH, strerror(errno));
        return NULL;
    }
/**
    if (strncmp(received_packets, ioctl_string, strlen(ioctl_string)) == 0) {
        struct aesd_seekto seek_info;
        sscanf(received_packets, "AESDCHAR_IOCSEEKTO:%d,%d", &seek_info.write_cmd, &seek_info.write_cmd_offset);
        if (ioctl(aesd_data_fd, AESDCHAR_IOCSEEKTO, &seek_info)) {
            syslog(LOG_ERR, "Ioctl failed: %s", strerror(errno));
        }
    } else {
        int bytes_written = write(aesd_data_fd, received_packets, count * TEMP_BUFFER_SIZE);
        if (bytes_written == -1) {
            syslog(LOG_ERR, "Write failed: %s", strerror(errno));
        } else {
            syslog(LOG_INFO, "Bytes written: %d", bytes_written);
        }
    }
*/
    int bytes_written = write(aesd_data_fd, received_packets, count * TEMP_BUFFER_SIZE);
    if (bytes_written == -1) {
            syslog(LOG_ERR, "Write failed: %s", strerror(errno));
    } else {
          syslog(LOG_INFO, "Bytes written: %d", bytes_written);
    }
    lseek(aesd_data_fd, 0, SEEK_SET);

    int read_bytes;
    char recv_buffer[TEMP_BUFFER_SIZE];
    while ((read_bytes = read(aesd_data_fd, recv_buffer, TEMP_BUFFER_SIZE)) > 0) {
        int bytes_sent = send(thread_data->client_fd, recv_buffer, read_bytes, 0);
        if (bytes_sent == -1) {
            syslog(LOG_ERR, "send error: %s", strerror(errno));
            break;
        }
    }

    if (read_bytes == -1) {
        syslog(LOG_ERR, "read failed: %s", strerror(errno));
    }

    free(received_packets);
    close(aesd_data_fd);
    close(thread_data->client_fd);
    thread_data->thread_status = true;
    syslog(LOG_DEBUG, "Closed with %s\n", client_ip);
    return NULL;
}


void cleanup() {
    close(server_socket_fd);
    #ifndef USE_AESD_CHAR_DEVICE
    pthread_mutex_destroy(&mutex);
    #endif
    closelog();
    exit(0);
}

int main(int argc, char *argv[]) {
    bool is_daemon = false;
    struct sockaddr_in client_address;
    socklen_t addr_size;
    struct addrinfo hints;
    struct addrinfo *server_info;
    int status;
    int enable = 1;
    openlog(NULL, 0, LOG_USER);

    // Check if daemon flag is provided
    if (argc > 1 && !strcmp(argv[1], "-d")) {
        pid_t pid = fork();
        if (pid == -1) {
            syslog(LOG_ERR, "error on : fork");
            return -1;
        } else if (pid != 0) {
            printf("Parent Process Terminating \n");
            exit(EXIT_SUCCESS);
        }

        if (setsid() == -1) {
            printf("Set Sid Failed\n");
            return -1;
        }

        if (chdir("/") == -1) {
            printf("Changing Working Directory Failed\n");
            return -1;
        }
        open("/dev/null", O_RDWR);
        dup(0);
        dup(0);
        printf("Daemon Started\n");
    } else {
        is_daemon = true;
        syslog(LOG_DEBUG, "aesdsocket as Daemon");
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
#ifndef USE_AESD_CHAR_DEVICE
    signal(SIGALRM, sig_handler);
#endif

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    status = getaddrinfo(NULL, PORT_NUMBER, &hints, &server_info);
    if (status != 0) {
        syslog(LOG_ERR, "Failed to get server address info");
        closelog();
        return -1;
    }

    server_socket_fd = socket(server_info->ai_family, server_info->ai_socktype, server_info->ai_protocol);
    if (server_socket_fd == -1 ) {
        syslog(LOG_ERR, "Failed to create server socket");
        closelog();
        return -1;
    }

    if (setsockopt(server_socket_fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0) {
        syslog(LOG_ERR, "Error: setsockopt");
        closelog();
        return -1;
    }

    int flags = fcntl(server_socket_fd, F_GETFL);
    fcntl(server_socket_fd, F_SETFL, flags | O_NONBLOCK);

    status = bind(server_socket_fd, server_info->ai_addr, server_info->ai_addrlen);
    if (status != 0) {
        syslog(LOG_ERR, "Failed to bind server socket");
        closelog();
        return -1;
    }

    if (is_daemon) {
        status = daemon(0, 0);
        if (status == -1){
            syslog(LOG_ERR, "Daemon process failed");
        }
    }

    status = listen(server_socket_fd, 10);
    if (status != 0) {
        syslog(LOG_ERR, "Server socket listen failed");
        closelog();
        return -1;
    }
 #ifndef USE_AESD_CHAR_DEVICE
    pthread_t tstamp_tid;
    if (pthread_create(&tstamp_tid,NULL,timestamp_thread,NULL) !=0)
    {
        fprintf(stderr, "Failed to create timestamp thread\n");
        pthread_mutex_destroy(&file_mutex);
        return -1;
    }
#endif
    freeaddrinfo(server_info);
    addr_size = sizeof(client_address);

    SLIST_INIT(&head);

    while (!closed_flag) {

        status = 0;

        client_socket_fd = accept(server_socket_fd, (struct sockaddr *)&client_address, &addr_size);
        if (client_socket_fd == -1 ) {
            if (errno == EWOULDBLOCK) {
                continue;
            }
            syslog(LOG_ERR, "Failed to accept client connection");
            continue;
        }

        struct thread_data *new_thread_data = malloc(sizeof(struct thread_data));
        if (new_thread_data == NULL) {
            perror("malloc failure");
            continue;
        }
        new_thread_data->thread_status = false;
        new_thread_data->client_fd = client_socket_fd;
        new_thread_data->client_address = client_address;

        pthread_create(&(new_thread_data->thread_id), NULL, &thread_function, (void *)new_thread_data);

        add_to_list(new_thread_data);
    }
#ifndef USE_AESD_CHAR_DEVICE
    pthread_cancel(tstamp_tid);
    // Join timestamp thread
    if (pthread_join(tstamp_tid, NULL) != 0) {
        fprintf(stderr, "Failed to join timestamp thread\n");
    }
#endif
    process_list();

    cleanup();
    return 0;
}
