## Assembly

Some quick cheatsheets and tutorials:
- [x64-Cheatsheet](https://cs.brown.edu/courses/cs033/docs/guides/x64_cheatsheet.pdf)
- [x86-Architecture](https://en.wikibooks.org/wiki/X86_Assembly/X86_Architecture)
- [Quick Start](https://wiki.cdot.senecacollege.ca/wiki/X86_64_Register_and_Instruction_Quick_Start)

This *still makes my brain explode.
- `mov dest, src` is called **[Intel syntax](https://stackoverflow.com/tags/intel-syntax/info)**. (e.g. `mov eax, 123`)
- `mov src, dest` is called **[AT&T syntax](https://stackoverflow.com/tags/att/info)**. (e.g. `mov $123, %eax`)

UNIX assemblers including the GNU assembler uses AT&T syntax, all other known x86 assemblers Intel syntax. You can read up on the differences [on wikipedia](http://en.wikipedia.org/wiki/X86_assembly_language#Syntax)

```asm
.data
var1 BYTE 10h,
.code
mov al,var1 ; AL = 10h
mov al,[var1] ; AL = 10h
```

## Stack

You can start by reading [Stack explained](https://cratecode.com/info/x86-assembly-nasm-stack).
This is an example of a function and a stack frame after invoking that function.

```C
/* Example of function with many parameters */
long func(long a, long b, long c, long d,
            long e, long f, long g, long h)
{
    long xx = a * b * c * d * e * f * g * h;
    long yy = a + b + c + d + e + f + g + h;
    long zz = utilfunc(xx, yy, xx % yy);
    return zz + 20;
}
```

![[x64_frame_nonleaf.png | Stack frame after calling func]]


https://en.wikipedia.org/wiki/Win32_Thread_Information_Block#Accessing_the_TIB
## Operation Precedence

`raise NotImplementedError`

## Information on Executables



`raise NotImplementedError`
