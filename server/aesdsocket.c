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

#define PORT 9000
#define FILE "/var/tmp/aesdsocketdata"
#define MAX_BUFFER 1024
#define BUFFER_SIZE 256
#define CONCURRENT_CONN 10
#define SEND_FLAGS 0
#define RECV_FLAGS 0

int file_fd, sock_fd;
SLIST_HEAD(slisthead, list_data) head;
pthread_mutex_t file_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t list_mutex = PTHREAD_MUTEX_INITIALIZER;
pid_t pid;
bool initial_sleep_done = false;
bool terminate_program = false; // Flag to indicate termination signal received

struct thread_data {
    pthread_t thread_id;
};

struct list_data {
    struct thread_data info;
    SLIST_ENTRY(list_data) entries;
};

void sig_handler(int signal) {
    printf("Caught signal %d\n", signal);
    if ((signal == SIGINT) || (signal == SIGTERM)) {
        terminate_program = true;


        syslog(LOG_INFO, "Closing file descriptor...\n");
        close(file_fd);
        close(sock_fd);
        syslog(LOG_INFO, "Removing file %s...\n", FILE);
        remove(FILE);
        syslog(LOG_INFO, "Destroying file mutex...\n");
        pthread_mutex_destroy(&file_mutex);
        exit(0);
    
    }
}

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

void *handle_connection(void *arg) {
    int acceptfd = *((int *)arg);
    int recv_bytes, saved_bytes;
    char *w_packet;

    char server_buffer[MAX_BUFFER];
    memset(server_buffer, '\0', MAX_BUFFER);
    struct thread_data thread_info;
    thread_info.thread_id = pthread_self();

    w_packet = malloc(sizeof(char) * MAX_BUFFER);
    if (w_packet == NULL) {
        perror("malloc failure");
        close(acceptfd);
        return NULL;
    }

    syslog(LOG_INFO, "Allocated memory for w_packet");
    bool packet_rx = false;
    saved_bytes = 0;

    while (!packet_rx) {
        recv_bytes = recv(acceptfd, server_buffer, MAX_BUFFER, RECV_FLAGS);

        if (recv_bytes == 0 || (strchr(server_buffer, '\n') != NULL)) {
            packet_rx = true;
        }

        server_buffer[recv_bytes] = '\0';  // Ensure null-terminated string
        syslog(LOG_INFO, "Received %d bytes: %s\n", recv_bytes, server_buffer);
        size_t new_size = saved_bytes + recv_bytes;
        syslog(LOG_INFO, "New size: %zu\n", new_size);

        w_packet = realloc(w_packet, sizeof(char) * new_size);
        if (w_packet == NULL) {
            perror("realloc failure");
            close(acceptfd);
            return NULL;
        }
        syslog(LOG_INFO, "Reallocated size: %zu bytes\n", new_size);
        memcpy(w_packet + saved_bytes, server_buffer, recv_bytes);
        saved_bytes += recv_bytes;
    }

    if (w_packet == NULL) {
        syslog(LOG_ERR, "w_packet is NULL after realloc");
        close(acceptfd);
        return NULL;
    }

    pthread_mutex_lock(&file_mutex);
    lseek(file_fd, 0, SEEK_END);
    write(file_fd, w_packet, saved_bytes);
    pthread_mutex_unlock(&file_mutex);

    off_t file_size_read = lseek(file_fd, 0, SEEK_END);
    if (file_size_read == -1) {
        perror("Error seeking file");
        close(file_fd);
        free(w_packet);
        close(acceptfd);
        return NULL;
    }

    if (lseek(file_fd, 0, SEEK_SET) == -1) {
        perror("Error seeking file");
        close(file_fd);
        free(w_packet);
        close(acceptfd);
        return NULL;
    }

    long send_buffer_size = file_size_read;

    char *send_buffer = malloc(send_buffer_size * sizeof(char));
    if (send_buffer == NULL) {
        perror("malloc failure");
        close(file_fd);
        free(w_packet);
        close(acceptfd);
        return NULL;
    }

    ssize_t read_bytes = read(file_fd, send_buffer, send_buffer_size);
    if (read_bytes == -1 || read_bytes != send_buffer_size) {
        perror("read");
        free(send_buffer);
        close(file_fd);
        free(w_packet);
        close(acceptfd);
        return NULL;
    }

    pthread_mutex_unlock(&file_mutex);

    int status = send(acceptfd, send_buffer, read_bytes, SEND_FLAGS);
    if (status == -1) {
        perror("Error in send");
    } else {
        syslog(LOG_DEBUG, "send success\n");
    }
    add_to_list(&thread_info);
    free(w_packet);
    free(send_buffer);
    close(acceptfd);

    return NULL;
}

int main(int argc, char **argv) {
    struct sockaddr_in server_so, client_so;
    int status, acceptfd;
    socklen_t addr_size;
    SLIST_INIT(&head);
    sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd == -1) {
        syslog(LOG_ERR, "socket error = %d\n", errno);
        exit(EXIT_FAILURE);
    }

    int optval = 1;
    if (setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(int)) == -1) {
        perror("setsockopt");
        close(sock_fd);
        return -1;
    }

    server_so.sin_addr.s_addr = INADDR_ANY;
    server_so.sin_family = AF_INET;
    server_so.sin_port = htons(PORT);

    status = bind(sock_fd, (struct sockaddr *)&server_so, sizeof(struct sockaddr_in));
    if (status == -1) {
        syslog(LOG_ERR, "bind error ");
        fprintf(stderr, "bind error ");
        exit(EXIT_FAILURE);
    }

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
    }

    status = listen(sock_fd, CONCURRENT_CONN);
    if (status == -1) {
        syslog(LOG_ERR, "Error in Listening");
    }

    file_fd = open(FILE, O_RDWR | O_CREAT | O_TRUNC, S_IRWXU | S_IRWXG | S_IRWXO);
    if (file_fd == -1) {
        syslog(LOG_ERR, "Error opening file: %s", FILE);
        exit(EXIT_FAILURE);
    }

    // Setup signal handler
    signal(SIGTERM, sig_handler);
    signal(SIGINT, sig_handler);
    pthread_t tstamp_tid;

    if (pthread_create(&tstamp_tid,NULL,timestamp_thread,NULL) !=0)
    {
        fprintf(stderr, "Failed to create timestamp thread\n");
        pthread_mutex_destroy(&file_mutex);
        return -1;
    }

    while (!terminate_program) {
        addr_size = sizeof(client_so);
        acceptfd = accept(sock_fd, (struct sockaddr *)&client_so, &addr_size);
        if (acceptfd == -1) {
            syslog(LOG_ERR, "There has been an accept error ");
            exit(-1);
        } else {
            syslog(LOG_DEBUG, "Accepted connection from : %s\n", inet_ntoa(client_so.sin_addr));
        }

        pthread_t tid;
        process_list();
        int *arg = malloc(sizeof(*arg));
        *arg = acceptfd;

        if (pthread_create(&tid, NULL, handle_connection, arg) != 0) {
            fprintf(stderr, "Failed to create thread\n");
            close(acceptfd);
            free(arg);
        }
    }
    pthread_cancel(tstamp_tid);
    // Join timestamp thread
    if (pthread_join(tstamp_tid, NULL) != 0) {
        fprintf(stderr, "Failed to join timestamp thread\n");
    }

    // Cleanup
    pthread_mutex_destroy(&file_mutex);
    close(sock_fd);
    close(file_fd);
    remove(FILE);

    return 0;
}

