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
#include <sys/wait.h>
#include <signal.h>
#include <syslog.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdbool.h>

#define PORT 9000
#define FILE "/var/tmp/aesdsocketdata"
#define MAX_BUFFER 1000
#define BUFFER_SIZE 256
#define CONCURRENT_CONN 10
#define SEND_FLAGS 0
#define RECV_FLAGS 0

int file_fd, sock_fd;
pid_t pid;

void sig_handler(int signal) {

  printf("Caught signal %d", signal);
  if ((signal == SIGINT) || (signal == SIGTERM)) {
      close(file_fd);
      close(sock_fd);
      remove(FILE);
      exit(0);
  }

}


int main(int argc, char **argv)
{
    char *w_packet, *read_packet, server_buffer[MAX_BUFFER];
    struct sockaddr_in server_so, client_so;
    int status, recv_bytes, acceptfd, max_buf_size, saved_bytes, send_bytes = 0, read_bytes = 0;
    socklen_t addr_size;



    sock_fd = socket(AF_INET , SOCK_STREAM, 0);
    if(sock_fd == -1)
        {
                syslog(LOG_ERR, "socket error = %d\n",errno);

                exit(-1);
        }
        else
        {
                syslog(LOG_DEBUG, "socket success\n");
        }


    server_so.sin_addr.s_addr = INADDR_ANY;
    server_so.sin_family = AF_INET;
    server_so.sin_port = htons(PORT);

        status = bind(sock_fd , (struct sockaddr_in *)&server_so , sizeof(struct sockaddr_in));

        if(status == -1)
        {
                syslog(LOG_ERR, "bind error ");
                fprintf(stderr, "bind error ");
                exit(-1);
        }
        else
        {
                syslog(LOG_DEBUG, "bind success\n");
        }



    if(argc > 1 && !strcmp(argv[1], "-d")){
                pid_t pid = fork();
                if(pid == -1) {
                        syslog(LOG_ERR, "error on : fork");
                        return -1;
                }

        else if (pid != 0)
        {
            printf("Parent Process Terminating \n");
            exit(EXIT_SUCCESS);
        }

        if (setsid() == -1)
        {
            printf("Set Sid Failed\n");
            return -1;
        }

        if (chdir("/") == -1)                 /* set the working directory to the root directory */
        {
            printf("Changing Working Directory Failed\n");
            return -1;
        }
                        open("/dev/null", O_RDWR);
                        dup(0);
                        dup(0);
            printf("Daemon Started\n");
                }


        status = listen(sock_fd, CONCURRENT_CONN);
        if(status == -1)
        {
                syslog(LOG_ERR, "Error in Listening");

                //exit(-1);
        }
        else
        {
                syslog(LOG_DEBUG, "Successfully started Listening\n");
        }



    file_fd = open(FILE, O_RDWR | O_CREAT | O_TRUNC, S_IRWXU | S_IRWXG | S_IRWXO);

    while(1)
    {
        addr_size = sizeof(client_so);
        acceptfd = accept(sock_fd, (struct sockaddr_in *) &client_so, &addr_size);
        if(acceptfd == -1)
        {
                syslog(LOG_ERR, "There has been an accept error ");

                exit(-1);
        }
        else
        {

                syslog(LOG_DEBUG, "Accepted connection from : %s\n", inet_ntoa(client_so.sin_addr));
        }

    max_buf_size = MAX_BUFFER;
    saved_bytes = 0;


    w_packet = malloc(sizeof(char) * MAX_BUFFER);

    bool packet_rx = false;
    while(!packet_rx)
    {
        recv_bytes = recv(acceptfd, server_buffer, MAX_BUFFER, RECV_FLAGS);

        if (recv_bytes == 0 || (strchr(server_buffer, '\n') != NULL))
        {
            packet_rx = true;
            printf("Packet Completed\n");
        }

        if ((max_buf_size - saved_bytes) < recv_bytes)
        {
            max_buf_size += recv_bytes;
            w_packet = (char *) realloc(w_packet, sizeof(char) * max_buf_size);
        }

        memcpy(w_packet + saved_bytes, server_buffer, recv_bytes);
        saved_bytes += recv_bytes;
    }

    write(file_fd, w_packet, saved_bytes);
    lseek(file_fd, 0, SEEK_SET);


    send_bytes += saved_bytes;

    read_packet = (char*)malloc(sizeof(char) * send_bytes);
    if(read_packet == NULL)
        {
                syslog(LOG_ERR, "There has been an error in reading packet = %d\n",errno);
                exit(-1);
        }

    read_bytes = read(file_fd, read_packet, send_bytes);

    status = send(acceptfd, read_packet, read_bytes , SEND_FLAGS);
    if(status == -1)
        {
                syslog(LOG_ERR, "send error = %d\n",errno);
                fprintf(stderr, "send error: %d\n", errno);
                exit(-1);
        }
    else
        {
                syslog(LOG_DEBUG, "send success\n");
        }
    syslog(LOG_DEBUG, "Closed connection from : %s\n", inet_ntoa(client_so.sin_addr));
    free(read_packet);
    free(w_packet);
    }


    return 0;
}

