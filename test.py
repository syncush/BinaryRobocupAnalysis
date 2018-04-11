import angr
import os
import r2pipe
import sys

'''
Just a helper function to grab function names from resolved symbols.
This will not be so easy if the binary is stripped.  You will have to
open the binary in a disassembler and find the addresses of the
functions you are trying to find/avoid in your paths rather than using
this helper function.
'''

def radare2Estimation():
    r2 = r2pipe.open('/home/syncush/PycharmProjects/BinaryRobocupAnalysis/hello_world')
    r2.cmd("aaa")
    cc = r2.cmdj("afCc")
    return cc

def main():
    b = angr.Project('/home/syncush/PycharmProjects/BinaryRobocupAnalysis/hello_world', load_options={'auto_load_libs': False})
    cfgA = b.analyses.CFGAccurate()
    cfgF = b.analyses.CFGFast()

    myAngrEstimationCC = cfgA.graph.number_of_edges() - len(cfgA.graph) + 2
    myFastAngrEstimationCC = cfgF.graph.number_of_edges() - len(cfgF.graph) + 2
    radare2EstimationCC = radare2Estimation()
    print "\n\nFor the formula Complexity = Edges - nodes + 2, the static analysis tools results are :\n\n"
    print "Angr Accurate Complexity = {0}\n\nAngr Fast Complexity = {1} \n\nradare2 Complexity = {2}".format(myAngrEstimationCC, myFastAngrEstimationCC, radare2EstimationCC)
main()