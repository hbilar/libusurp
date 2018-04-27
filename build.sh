#!/bin/bash

set -e 
set -x

# build library
gcc -fPIC -c connect.c 
gcc -fPIC -c execve.c 
gcc -fPIC -c stats.c 
gcc -shared -Wl,-soname,libusurp.so.1 -ldl -o libusurp.so.1.0 connect.o execve.o stats.o


# build test program
gcc -o test-connect test-connect.c


# build tcp server
gcc -o tcpserver tcpserver.c
