
- https://github.com/corkami/pics/tree/master/binary
- https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
- https://learn.microsoft.com/en-us/previous-versions/ms809762(v=msdn.10)?redirectedfrom=MSDN

*If the linker assumed an image base of 0x10000, the address of the variable i will end up containing something like 0x12004. At the memory used to hold the pointer "ptr", the linker will have written out 0x12004, since that's the address of the variable i. If the loader for whatever reason decided to load the file at a base address of 0x70000, the address of i would be 0x72004. The .reloc section is a list of places in the image where the difference between the linker assumed load address and the actual load address needs to be factored in.*

![[Pasted image 20231220195245.png | PE executable example]]