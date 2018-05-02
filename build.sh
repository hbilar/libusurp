#!/bin/bash

set -e 
set -x

# build library

FILES="connect execve stats open"
O_STR=
for i in $FILES; do
	gcc -fPIC -c $i.c
	O_STR="$O_STR $i.o"
done

gcc -shared -Wl,-soname,libusurp.so.1 -ldl -o libusurp.so.1.0 $O_STR


# build test program
gcc -o test-connect test-connect.c


# build tcp server
gcc -o tcpserver tcpserver.c
