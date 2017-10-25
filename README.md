# ROP Emporium solutions

[ROP Emporium](http://ropemporium.com/) contains 7 challenges (32-bit and 64-bit versions) in somewhat increasing difficulty to teach ROP basics.

This repo contains python scripts that either print the flag or result in a shell, pretty much all of the challenges can getyou a shell if you really want to.

### Dependencies:
1. [pwntools](https://github.com/Gallopsled/pwntools)
2. A functioning brain.

## Useful commands/tools to use for any challenge

1. Get function names: `nm binary | grep ' t '`
2. Get GOT entries: `readelf --relocs binary`
3. Get PLT entries: `objdump -M intel -dj .plt binary`
4. Get strings: `strings binary` or the much better alternative `rabin2 -z binary`
5. Virtual address space layout: `vmmap` in PEDA after starting program, otherwise other modules aren't mapped yet.
6. Finding gadgets:
    * Usually you'll make use of gadgets explicitly provided in the binary under `xxxGadgets`
    * Those usually won't do and you'll need more stuff, you can either use [ROPgadget](https://github.com/JonathanSalwan/ROPgadget), r2's `/R` command or [whatever](https://scoding.de/ropper/) [tool](https://www.offensive-security.com/metasploit-unleashed/msfrop/) [you](https://github.com/0vercl0k/rp) [like](https://github.com/packz/ropeme).

Note: You probably want to utilize the [pwntools](http://docs.pwntools.com/en/stable/elf/elf.html#example-usage) support to programmatically get GOT/PLT/segment data/function addresses using. It's easier to tell people than to use it myself..

If some solutions are unclear/confusing/total shit, go ahead and submit a PR.
