import angr
import r2pipe
import sys

'''
This is the list of features I want to extract from a binary file
Angr CFGAccurate Complete McCabe Complexity
Angr CFGFast complete McCabe Complexity
The Number of functions
The number of blocks
'''

def getMcCabeComplexityFromAngr(angr_project):
    cfgA = angr_project.analyses.CFGAccurate()
    cfgF = angr_project.analyses.CFGFast()
    myAngrEstimationCC = cfgA.graph.number_of_edges() - len(cfgA.graph) + 2
    myFastAngrEstimationCC = cfgF.graph.number_of_edges() - len(cfgF.graph) + 2
    return ((myAngrEstimationCC, myFastAngrEstimationCC), cfgF)


def radare2Estimation(file_path, angr_project, cfg):
    r2 = r2pipe.open(file_path)
    r2.cmd("aaa")
    list = []
    for funcAddr, functionObject in cfg.kb.functions.iteritems():
        cc = r2.cmdj("afCc@" + hex(funcAddr))
        list.append((functionObject.name, cc))
    return list


file_path = sys.argv[1]

b = angr.Project(file_path,
                 load_options={'auto_load_libs': False})


