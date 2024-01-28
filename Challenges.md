## Behind the Scenes

This was the first challenge I did from Hack The Box. I started it because there was a newcomer at the club, and wanted to do some Reversing together. Me, as a newbie myself, picked something easy, the one with the most solves.

I started by `strings` as in every challenge, regardless of the category.
We can see something interesting by piping the strings to grep `strings behindhtescenes | grep -n HTB -B 2 -A 2`,

```
19-[]A\A]A^A_
20-./challenge <password>
21:> HTB{%s}
22-:*3$"
23-GCC: (Ubuntu 9.3.0-17ubuntu1~20.04) 9.3.0
```

From Line *20* and *21*, I assumed that the program takes as input a *password*. 

I run `strace` with a dummy password as argument:

```
strace ./behindthescenes babisgkantantougkas
```

Interesting... We can see clearly a [*SIGILL*](https://support.sas.com/documentation/onlinedoc/ccompiler/doc700/html/lr1/z2005346.htm) situation going around here.

Enough with the assumptions, let's jump into Ghidra and do some disassembling.
After the initial analysis is done, we navigate to the defined strings of the program and search for the *interesting* ones we found via `strings`.

Under the defined string `./challenge <password>` there is the following sequence of characters in plain sight.

```
Itz_0nLy_UD2
```

Spoiler alert, this is probably the flag! Anyways, it says something about **UD2**. Let's dive more into that.

*"Generates an invalid opcode. This instruction is provided for software testing to explicitly generate an invalid opcode. The opcode for this instruction is reserved for this purpose.
Other than raising the invalid opcode exception, this instruction is the same as the NOP instruction."*

A useful shortcut to search in Ghidra is <kbd>Ctrl</kbd> + <kbd>Shift</kbd> + <kbd>e</kbd>  (see [[Tools#Ghidra]]). We search for **UD2** enabling *Instruction Mnemonics* and jump to the first hit. We disassemble the code below **UD2**.  There are 2 more hits of **UD2** now. By reading the disassembled code, we can see that a comparison with the weird found string is being made. This is the first invocation of strncmp.

```C
iVar1 = strncmp(*(char **)(*(long *)(unaff_RBP + -0xb 0) + 8),"Itz",3);
/* And so on, for the rest of the comparisons */
```

That's about it. 

PS: The newcomer never  returned...

## Simple Encryptor

Writing the reverse script in python posed the most significant challenge for this one.

Before trying to reverse it with Python (guess what 🤡), it is important to know this relevant piece of information:

*"In C, the `rand` function is part of the standard library, and its behavior is implementation-dependent. It typically uses a linear congruential generator (LCG) algorithm.
On the other hand, Python uses the Mersenne Twister algorithm."*

Anyways, let's reverse it using C.

```C
/* ... */
df = fopen("flag.enc","wb");
fwrite(&seed,1,4,df);
fwrite(string,1,pos,df);
```

We can see that in flag.enc the first four bytes (integer) is the seed.
So after reading the seed, we can easily generate the rest of the numbers and reverse the operations.

The solution in C is something like that:

```C
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Myrto */
/* Rev - Simple Encryptor */
int main() {

	int seed;
	char *content;
	size_t size;
	FILE *f;
	int rand_0;
	int rand_1;

	f = fopen("flag", "rb");
	
	if (f == NULL) {
		fprintf(stderr, "Error: Could not open file for reading.\n");
		exit(EXIT_FAILURE);
	}

	fseek(f, 0, SEEK_END);
	size = ftell(f);
	rewind(f);
	
	content = malloc(size);
	if (content == NULL) {
		fprintf(stderr, "Error: Could not allocate memory for file content.\n");
		return EXIT_FAILURE;
	}
	
	fread(content, sizeof(char), size, f);
	memcpy(&seed, content, sizeof(seed));
	printf("Seed: %d\n", seed);
	srand(seed);
	
	for (size_t i = 4; i < size; i++) {
		rand_0 = rand();
		rand_1 = rand() & 7;
		content[i] = ((unsigned char)content[i] >> (rand_1)) |
		((content[i]) << (8 - rand_1));
		content[i] = rand_0 ^ content[i];
	
	}
	
	for (size_t i = 4; i < size; i++)
		printf("%c", content[i]);

	fclose(f);
	free(content);
	return 0;
}
```

## Bypass

Oh, it's  `.exe`  time. That was my initial reaction with this challenge.
Let's begin by... guess what...  `file` and `strings`.

```
Bypass.exe: PE32 executable (console) Intel 80386 Mono/.Net assembly, for MS Windows
```

Oh no, .NET 🤮.

```
...
.NET Framework 4.5.2
...
```

I'm going to be brief with this challenge. There was a tool that made my life easier, which was __.

I opened the executable with dnSpy for 32-bit and started debugging it. 

```C#
public static void 0()
{
	bool flag = global::0.1();
	bool flag2 = flag;
	if (flag2)
	{
		global::0.2();
	}
	else
	{
		Console.WriteLine(5.0);
		global::0.0();
	}
}
```

I changed the value of `flag2` from false to `true` so that the branch is being taken and see what will happen. After that, we get into the `global::0.2()` function where the user is
prompted to enter a secret key.
The key  is `ThisIsAReallyReallySecureKeyButYouCanReadItFromSourceSoItSucks` if you look more carefully the `Locals` section. We type the key and get the flag.

## Exatlon

First, I ran the `file` command.

```
exatlon_v1: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, no section header
```

If we open the file in `hexedit`, we can see that there is a `UPX` string. That means that the executable is likely packed.  This leads to the conclusion that the original executable is compressed. 

![[packed.png | hexedit view]]

To decompress the executable, we run:

```
upx -d exatlon_v1 -o exatlon_unpacked
```

where `-d` is the flag for decompression and `-o`  for redirecting the output to a file.

Then, we open the unpacked executable to Ghidra and wait the analysis to finish. We can see beautiful C++ code unfolding in front of our eyes!

There are two things that raise suspicions. Those are the `exatlon(parameter)` function that is being called, and a comparison with some weird values after the `exatlon` invocation, that looks like this:

```
std::operator==(parameter, "1152 1344 1056 1968 1728 816 1648 784 1584 816 1728 1520 1840 1664 784 1632 1856 1520 1728 816 1632 1856 1520 784 1760 1840 1824 816 1584 1856 784 1776 1760 528 528 2000 "
);
```

Let's unwrap `exatlon` function. It's important to note that I changed the name of the function parameter and local variables for clarification purposes.

There is a loop that iterates over the string, does some binary operations and re-assigns it to the *parameter* passed. Each iteration, the destructor for `temp` is called. So, it holds the value of the  current character shift by 4 bits which then is concatenated with `parameter`. 

```C++
/* Left-shifts current character by 4 bits */
std::__cxx11::to_string(value,(int)curent_character << 4);
std::operator+(temp,(char *)value);
/* Reassigns value calculated to parameter */
std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::operator+=
((basic_string<char,std::char_traits<char>,std::allocator<char>> *)parameter,temp);
/* I skipped some code (destructors, assignments, advancing the iterator) */
```

To reverse this operation (shift is easy :D), I wrote this simple script in python.

```python
# Myrto
# Rev - Exatlon 
encrypted_char_list = [1152, 1344, 1056, 1968, 1728, 816, 1648, 784, 1584, 816, 1728, 1520, 1840, 1664, 784, 1632, 1856, 1520, 1728, 816, 1632, 1856, 1520, 784, 1760, 1840, 1824, 816, 1584, 1856, 784, 1776, 1760, 528, 528, 2000]

decrypted_str = ''.join([chr(char >> 4) for char in encrypted_char_list])
print(decrypted_str)
```

That was it! After unpacking it, it was a piece of cake!
## Golfer - Part 1

*"This is a story of a reverse challenge, but you should know upfront, this is a steganography challenge."*
$-$ Narrator

This was a challenge that helped me familiarize with Ida, but because I was not fond of the rich lady in the logo, I tried to solve it on Radare2 (r2) first.

I write more about my *r2* experience in the [[Tools#Radare2]] section.

Well, I have to say, that in the end, I opened Ida as it was suggested from the challenge hints. I was hating it at first, but now I have an OK relationship with it.

Enough talking, let's begin the challenge. I have to say that I was quite lost with this challenge. I was looking at the code trying to patch everything but the solution was right in front of my eye.

If you `hexdump` it:

```
00000000  7f 45 4c 46 01 61 34 66  54 55 48 7d 79 52 7b 6c  |.ELF.a4fTUH}yR{l|
00000010  02 00 03 00 01 00 00 00  4c 00 00 08 2c 00 00 00  |........L...,...|
00000020  67 5f 33 30 42 72 ef be  34 00 20 00 01 00 00 00  |g_30Br..4. .....|
00000030  00 00 00 00 00 00 00 08  00 00 00 08 38 01 00 00  |............8...|
00000040  38 01 00 00 05 00 00 00  00 10 00 00 e9 d6 00 00  |8...............|
00000050  00 fe c3 fe c2 b9 0a 00  00 08 e8 d0 00 00 00 b9  |................|
00000060  08 00 00 08 e8 c6 00 00  00 b9 24 00 00 08 e8 bc  |..........$.....|
00000070  00 00 00 b9 0e 00 00 08  e8 b2 00 00 00 b9 0c 00  |................|
00000080  00 08 e8 a8 00 00 00 b9  23 00 00 08 e8 9e 00 00  |........#.......|
00000090  00 b9 09 00 00 08 e8 94  00 00 00 b9 21 00 00 08  |............!...|
000000a0  e8 8a 00 00 00 b9 06 00  00 08 e8 80 00 00 00 b9  |................|
000000b0  0d 00 00 08 e8 76 00 00  00 b9 22 00 00 08 e8 6c  |.....v...."....l|
000000c0  00 00 00 b9 21 00 00 08  e8 62 00 00 00 b9 05 00  |....!....b......|
000000d0  00 08 e8 58 00 00 00 b9  21 00 00 08 e8 4e 00 00  |...X....!....N..|
000000e0  00 b9 20 00 00 08 e8 44  00 00 00 b9 23 00 00 08  |.. ....D....#...|
000000f0  e8 3a 00 00 00 b9 0f 00  00 08 e8 30 00 00 00 b9  |.:.........0....|
00000100  07 00 00 08 e8 26 00 00  00 b9 22 00 00 08 e8 1c  |.....&....".....|
00000110  00 00 00 b9 25 00 00 08  e8 12 00 00 00 b9 0b 00  |....%...........|
00000120  00 08 e8 08 00 00 00 30  c0 fe c0 b3 2a 90 90 55  |.......0....*..U|
00000130  89 e5 b0 04 90 90 c9 c3                           |........|
00000138
```

We can see some weird characters after the ELF header. They kind of look similar to what a flag would contain: *HTB*, underscore...

The main program consisted of a simple loop and above it there were those mov-call pairs. I played around with the offsets (right click on the value and select offset option with the pointer to data icon), and see that I could simple extract the characters and construct the flag.

![[ida_byte_offset.png | Looking at the offsets]]

For example:

```assembly
mov ecx, offset unk_800000A 
# ---> H 
```

You can see the value by hovering the `unk_xxxxxxx`. I'm not sure if there was a faster way, but it was quite easy like that!

Congratulations, you are a 🏌️ now!

## Cyberpsychosis

A friend recommended me this challenge. I really liked it but again, I spent most of the time exploring some theory stuff.

```
diamorphine.ko: ELF 64-bit LSB relocatable, x86-64, version 1 (SYSV), BuildID[sha1]=e6a635e5bd8219ae93d2bc26574fff42dc4e1105, with debug_info, not stripped
```
``
**Some useful links**:
- [GitHub - m0nad/Diamorphine: LKM rootkit for Linux Kernels 2.6.x/3.x/4.x/5.x/6.x (x86/x86_64 and ARM64)](https://github.com/m0nad/Diamorphine)
- [How did I approach making linux LKM rootkit, “reveng\_rtkit” ? | reveng007’s Blog](https://reveng007.github.io/blog/2022/03/08/reveng_rkit_detailed.html)

So, what is an *LKM*? 

>In [computing](https://en.wikipedia.org/wiki/Computing "Computing"), a **loadable kernel module** (**LKM**) is an [object file](https://en.wikipedia.org/wiki/Object_file "Object file") that contains code to [extend](https://en.wikipedia.org/wiki/Extensibility "Extensibility") the running [kernel](https://en.wikipedia.org/wiki/Kernel_(operating_system) "Kernel (operating system)"), or so-called _base kernel_, of an [operating system](https://en.wikipedia.org/wiki/Operating_system "Operating system").

So, first I opened the `diamorphine.ko` file with Ghidra, and then with Ida for some reason. Both can do the job just fine. Anyways, let's go to `init_module` or `diamorphine_init` (entry point).

Following m0nad's repository, we can see that  in order to make the module visible we have to:

```bash
kill -63 0
```

But in our case, after observing the disassembled code, we can see that we need to send another signal to kill (disarm) the rootkit.

![[kill.png]]

So, after connecting to the instance we resume by sending :

```bash
kill -46 0
```

And then to become root:

```bash
kill -64 0
```

Then, we can just remove the module:

```bash
rmmod diamorphine
```

To find the location of the flag, I just did some tree-grep thingie (I don't like *find*), but let's also put the find command that I won't remember it after one day.

```bash
find . -maxdepth 10 -type f -name 'flag.txt'
```

Good challenge!