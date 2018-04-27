
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


/* Load in list of files that do not exist */
int open(const char *pathname, int flags)
{
    int (*org_open)(const char *, int);
    org_open = dlsym(RTLD_NEXT, "open"); 

    printf("Called open: p = %s!\n", pathname);

    return (*org_open)(pathname, flags);
}
