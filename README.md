# ropTool
A python module to build ROP chains

# Installation Guide: 
python3 and pwntools must be installed
# ROPgadget:
  pip install ropgadget
# ropper:
  pip install ropper
# invoke:
  pip install invoke
  
# -------Test---------
from ropTool import* </br>
rop=ropTool('toomanybirds1')</br>
code,payload = rop.set_arg(b'hello',mode=1,rax=1)</br>
rop.printROPcode()</br>

# ------Test2----------
python3 test.py

# -----Test3------
python3 test2.py
