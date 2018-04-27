
## libusurp

This is a little proof of concept work to 'usurp' system calls for shared library linked binaries using `LD_PRELOAD`.

E.g. the `connect()` library call can be controlled and either allowed/denied through a configuration file (IPV4 TCP only, at present). This might be useful in e.g. a test/dev environment setting, where you don't want to risk accidentally connecting to e.g. a production database.

Usurping the `connect()` library call like this will implement something of a basic application level firewall.


Also note that no root permissions are required for this, i.e. it's perfectly plausible to use this in e.g. Jenkins builds.


## Caveats

The `LD_PRELOAD` method only works for non-statically linked binaries.


## Building

Simply run the `build.sh` script. This will produce `libusurp.so.1.0`, which you then use with your / other binaries:


```
(infra)sandbox@sandbox:~/libusurp$ ./build.sh 
+ gcc -fPIC -c connect.c
+ gcc -fPIC -c execve.c
+ gcc -fPIC -c stats.c
+ gcc -shared -Wl,-soname,libusurp.so.1 -ldl -o libusurp.so.1.0 connect.o execve.o stats.o
+ gcc -o test-connect test-connect.c
+ gcc -o tcpserver tcpserver.c
(infra)sandbox@sandbox:~/libusurp$ 
```


## Examples

Example config file:
```
(infra)sandbox@sandbox:~/libusurp$ cat usurp-fw.conf 

# allow connections to port 22 on 10.0.8.76
rule=allow 10.0.8.76 32 22 22

# allow connection to 10.0.8.76:12345
rule=allow 10.0.8.76 32 12345 12345

default_policy=deny
```

Example invocation to an allowed address:

```
(infra)sandbox@sandbox:~/libusurp$ LD_PRELOAD=`pwd`/libusurp.so.1.0  nc 10.0.8.76 22
SSH-2.0-OpenSSH_6.6.1
^C
(infra)sandbox@sandbox:~/libusurp$ 
```


Example invocation to a disallowed address:

```
(infra)sandbox@sandbox:~/libusurp$ LD_PRELOAD=`pwd`/libusurp.so.1.0  nc 10.0.8.77 22
Ncat: Permission denied.
(infra)sandbox@sandbox:~/libusurp$ 
```



## Utility programs

### tcpserver.c

Listens on a port and sends a random ASCII drink to a connectee.

### test-connect.c

Noddy little program that connects to an IP:port and prints whatever comes back over that socket to stdout.

