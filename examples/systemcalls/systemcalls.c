#include "systemcalls.h"
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h> 
#include <sys/wait.h> 
#include <fcntl.h> 

bool do_system(const char *cmd)
{

    if(system(cmd) == -1)
        return false;

    return true;
}

bool do_exec(int count, ...)
{
    va_list args;
    va_start(args, count);
    char * command[count+1];
    int i;
    int status;
    pid_t pid;
    for(i=0; i<count; i++)
    {
        command[i] = va_arg(args, char *);
    }
    command[count] = NULL;
    pid = fork();


    if(pid < 0)
        return false;

    if(pid == 0)
    {
     	printf("=============PID of  Child Process = %d=============\n", getpid());

	execv(command[0],(command));
        exit(-1);
    }

    if(waitpid(pid,&status, 0) == -1) //waitpid will wait for the pid .
        return false;
    else if(WIFEXITED(status))
    {
    	if(WEXITSTATUS(status) == 0)
    		return true;
    	else
    		return false;
    }

    va_end(args);

    return true;
}

bool do_exec_redirect(const char *outputfile, int count, ...)
{
    va_list args;
    va_start(args, count);
    char * command[count+1];
    int i;
    pid_t pid;
    int status;
    for(i=0; i<count; i++)
    {
        command[i] = va_arg(args, char *);
    }
    command[count] = NULL;

    command[count] = command[count];

    int file = open(outputfile, O_WRONLY | O_CREAT , 0777);
    if (file < 0)
    {

        return false;
    }
    pid = fork();
    if(pid == 0)
    {

        int file2 = dup2(file , STDOUT_FILENO);

        if(file2 == -1)
        {
            exit(-1);
        }


        close(file);

        execv(command[0], command);
        exit(-1);
    }
    if(waitpid(pid,&status, 0) == -1)
       return false;
    else if(WIFEXITED(status))
    {
       if(WEXITSTATUS(status) == 0)
           return true;
       else
           return false;
    }
    va_end(args);

    return true;
}

