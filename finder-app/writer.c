#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

char writefile[100];
char writestring[100];


int main (int argc, char *argv[]){
    ssize_t writer; 
    if(argc == 3){
	    char* filepath=argv[1];
	    char* string=argv[2];
	    syslog(LOG_USER, "Writing %s to %s", string, filepath);
    
	    int fd = open(filepath, O_WRONLY | O_CREAT | O_TRUNC ,0700);
	    if (fd == -1){
	    	printf("File was not opened properly");
		syslog (LOG_ERR,"File was not opened properly");
	    	perror ("open");
           	exit(1);
	    }
	    writer = write(fd, string, strlen(string));
	    if (writer == -1){
		syslog(LOG_ERR, "Writing Failed");    
	        printf("Writing Failed");
        	exit(-1);
	    }
	   //fclose(fd);

    } 
   else
   {
   	    syslog(LOG_ERR, "Expecting 2 args not %d args", argc-1);
            return 1;
   }
   return 0;
 }

