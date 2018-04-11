import os
import r2pipe
import sys

r2 = r2pipe.open(sys.argv[1])
r2.cmd("aaa")
cc = r2.cmdj("afC")
print cc