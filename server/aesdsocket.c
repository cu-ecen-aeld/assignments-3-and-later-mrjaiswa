#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <netdb.h>
#include <unistd.h>
#include <string.h>
#include <netdb.h>
#include <signal.h>
#include <fcntl.h>
#include <stdbool.h>
#include <syslog.h>
#include <net/if.h>

#define DOMAIN AF_INET
#define TYPE SOCK_STREAM
#define LIST_PORT 9000
#define FILE "/var/tmp/aesdsocketdata"
#define BUFF_SIZE 200
#define CONCURRENT_CONN 10

int file_fd;
int sockfd;

void sig_handler(int signal) {

  printf("Caught signal %d", signal);
  if ((signal == SIGINT) || (signal == SIGTERM)) {
      close(file_fd);
      close(sockfd);
      remove(FILE);
      exit(0);
  }

}
int main(int argc, char **argv)
{
  signal(SIGINT,sig_handler);
  signal(SIGTERM, sig_handler);
  struct sockaddr_in serveraddress;
  struct sockaddr_in clientaddress;
  int recvClient;
  char *readFile;
  socklen_t addr_size;
  int clientSocket;
  int serverSocket;
  char *writer;
  //int seekValue = 0;
  //int bytesToBeRead;
  int fd = 0;
  int totalBuffer = BUFF_SIZE;
  int currentSize = 0;

  char rxClient[BUFF_SIZE];


  //int bytesToBeWritten = 0;
  //int readBufferSize = 0;
  int readBuffer = 0;
  serverSocket = socket(AF_INET , SOCK_STREAM, 0);

  if(serverSocket < 0)
  {
    perror("[-] Error in creating Socket \n");
    exit(-1);
    }
  printf("[+] Server Listening Socket is Created\n");
  memset(&serveraddress , '\0' , sizeof(struct sockaddr_in));
  serveraddress.sin_family = AF_INET;
  serveraddress.sin_addr.s_addr = INADDR_ANY;
  serveraddress.sin_port = htons(LIST_PORT);

  int bindSocket = bind(serverSocket , (struct sockaddr*)&serveraddress , sizeof(struct sockaddr));

  if (bindSocket < 0)
  {
      perror("[-] Bind Failed\n");
      close(serverSocket);
      exit(-1);
  }
  printf("[+] Bind Socket Completed\n");

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
  printf("Listening\n");
  if (listen(serverSocket, CONCURRENT_CONN) == -1) {
      syslog(LOG_ERR, "error on syscall: listen");
      return -1;
   }
  fd = open(FILE, O_CREAT | O_RDWR | O_TRUNC, 0644);

  while(1)
  {

    addr_size = sizeof(clientaddress);
    clientSocket = accept(serverSocket, (struct sockaddr*)&clientaddress, &addr_size);

    printf("Client Socket = %d\n", clientSocket);

    totalBuffer = BUFF_SIZE;
    currentSize = 0;


    writer = malloc(sizeof(char) * BUFF_SIZE);




    if(clientSocket < 0)
    {
        perror("[-] Accept Failed\n");
        exit(-1);
    }


    printf("Client Address : %s\n", inet_ntoa(clientaddress.sin_addr));

    while(true)
    {
        recvClient = recv(clientSocket,rxClient, BUFF_SIZE, 0);
        if ((totalBuffer - currentSize) < recvClient)
        {
            totalBuffer += recvClient;
            writer = (char *) realloc(writer, sizeof(char) * totalBuffer);
        }

        if (recvClient == 0 || (strchr(rxClient, '\n') != NULL))
        {
            printf("Packet Completed\n");
            break;
        }



        memcpy(writer + currentSize, rxClient, recvClient);
        currentSize += recvClient;
    }
    int write_bytes = write(file_fd, writer, currentSize);
    if (write_bytes == -1)
    {
        perror("error writing to file");
        return -1;
    }
    lseek(fd, 0, SEEK_SET);
    readBuffer += currentSize;

    readFile = (char *) malloc(sizeof(char) * readBuffer);


    ssize_t read_bytes = read(fd,readFile, readBuffer);
    if (read_bytes == -1)
    {
        perror("error reading from file");
        return -1;
    }
    syslog(LOG_INFO, "Bytes To be Read = %ld\n", read_bytes);
    int send_bytes = send(clientSocket, readFile, read_bytes, 0);
    syslog(LOG_INFO, "Client Send Return Value = %d\n",send_bytes);

    if (send_bytes < 0)
    {
        perror("[-] Error Sending to Client\n");
    }

    free(readFile);
    free(writer);


    syslog(LOG_INFO, "Closed connection from : %s\n", inet_ntoa(clientaddress.sin_addr));
}

return 0;
}

