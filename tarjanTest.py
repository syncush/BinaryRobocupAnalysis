import angr
import tarjan

b = angr.Project('/home/syncush/PycharmProjects/BinaryRobocupAnalysis/hello_world',
                 load_options={'auto_load_libs': False})
cfgA = b.analyses.CFGAccurate().graph
cfgF = b.analyses.CFGFast().graph


graphForTarjanA = {}
graphForTarjanF = {}
for n, nbrsdict in cfgA.adjacency():
    if len(list(nbrsdict)) >= 2:
        graphForTarjanA[n] = list(nbrsdict)
for n,nbrsdict in cfgF.adjacency():
    if len(list(nbrsdict)) >= 2:
        graphForTarjanF[n] = list(nbrsdict)
print "\n\nNumber of connected components for CFGAccurate is {0}\n\nNumber of connected components for CFGFast is {1}".format(len(tarjan.tarjan(graphForTarjanA)), len(tarjan.tarjan(graphForTarjanF)))
