/* 
 The execve() call will make sure the (or at least an) LD_PRELOAD variable 
 survives through to the process' children. That particular piece of code 
 is probably riddled with bugs.
 The execve(): 
   - probably leaks memory, although it's unclear if that makes any difference
     here, as we're replacing the memory image with something else when 
     calling execve anyway - not sure.
   - The code does not allow multiple LD_PRELOAD libraries to be passed 
     down the  execution stack... It will overwrite the value with its 
     hard coded LD_PRELOAD setting.
*/

#define _GNU_SOURCE
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <errno.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define EXTRA_PRELOAD_STR "LD_PRELOAD=/my/full/path/libusurp.so.1.0"


int execve(const char *filename, char *const argv[], char *const envp[])
{
    printf("Calling execve: %s\n", filename);

    int (*org_execve)(const char *filename, char *const argv[], char *const envp[]);
    org_execve = dlsym(RTLD_NEXT, "execve"); 


    /* Make sure that we preserve the LD_PRELOAD environment var */
    char **new_envp;


    /* figure out how many environment variables are defined */
    int env_count = 0;
    if (envp && *envp) {
        char **cur_p = (char **)envp;
        while (*cur_p) {
            cur_p++;
            env_count ++;
        }
    }


    /* copy the current env to a new env, and append LD_PRELOAD if required */
    new_envp = malloc(sizeof(char**) * env_count + 10);
    {

        char **new_envp_p = new_envp;
        char **old_envp = (char **)envp;

        while (old_envp && *old_envp) {
            *new_envp_p = (char *)malloc(strlen(*old_envp));
            strcpy((char*)new_envp_p, (char*)old_envp);

            old_envp ++;
            new_envp_p ++;
        }

        /* Add the LD_PRELOAD bit we want */
        char *cur_ld_preload = getenv("LD_PRELOAD");
        char *extra_string = NULL;

        if (cur_ld_preload) {
            char *prefix = "LD_PRELOAD=";
            extra_string = malloc(strlen(cur_ld_preload) + strlen(prefix) + 10);
            snprintf(extra_string, strlen(cur_ld_preload) + strlen(prefix) + 1, "%s%s", prefix, cur_ld_preload);
        }
        else {
            /* Add the LD_PRELOAD=xxx in */
            char *ld_preload_string = EXTRA_PRELOAD_STR;
            extra_string = malloc(strlen(ld_preload_string) + 1);
            strcpy(extra_string, ld_preload_string);
        }

        *new_envp_p = (char *)malloc(strlen(extra_string));
        strcpy((char*)*new_envp_p, extra_string);


        /* Add the NULL at the end of the list */
        new_envp_p ++;
        *new_envp_p = 0;
    }


    /* Dump environment to stdout */
    {
        char **cur_p = new_envp;
        while (*cur_p) {
            printf("env: %s\n", *cur_p);
            cur_p++;
        }
    }
   
    return (*org_execve)(filename, argv, new_envp);
}

