
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


/* Intercept stat() */
int stat(const char *path, struct stat *buf)
{
    printf("INTERCEPT stat()\n");
    int (*org_stat)(const char *, struct stat *);
    org_stat = dlsym(RTLD_NEXT, "stat"); 
    return (*org_stat)(path, buf);
}


int fstat(int fd, struct stat *buf) 
{
    printf("Calling fstat\n");
    
    int (*org_fstat)(int, struct stat *);
    org_fstat = dlsym(RTLD_NEXT, "fstat"); 
    return (*org_fstat)(fd, buf);
}


int lstat(const char *path, struct stat *buf)
{
    printf("Calling lstat\n");
    
    int (*org_lstat)(const char *path, struct stat *buf);
    org_lstat = dlsym(RTLD_NEXT, "lstat"); 
    return (*org_lstat)(path, buf);
}
