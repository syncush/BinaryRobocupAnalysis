import angr
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
    #cfgA = b.analyses.CFGAccurate()
    cfgF = b.analyses.CFGFast()

'''
    myAngrEstimationCC = cfgA.graph.number_of_edges() - len(cfgA.graph) + 2
    myFastAngrEstimationCC = cfgF.graph.number_of_edges() - len(cfgF.graph) + 2
    radare2EstimationCC = radare2_cc_estimation()
    print "\n\nFor the formula Complexity = Edges - nodes + 2, the static analysis tools results are :\n\n"
    print "Angr Accurate Complexity = {0}\n\nAngr Fast Complexity = {1} \n\nradare2 Complexity = {2}".format(myAngrEstimationCC, myFastAngrEstimationCC, radare2EstimationCC)

'''


def extract_features_from_angr(file_path, use_accurate=False):
    b = angr.Project(file_path, load_options={'auto_load_libs': False})
    if use_accurate:
        cfg = b.analyses.CFGAccurate()
    else:
        cfg = b.analyses.CFGFast()
    sum_blocks_sizes_info = {'sum': 0, 'max': 0}
    sum_sys_calls_info = {'sum': 0, 'names': []}
    looping_times_info = {'sum': 0, 'max': 0}
    has_return_info = {'sum': 0}
    block_instructions_info = {'max': 0}
    for nodeInGraph,info in cfg.graph.nodes.iteritems():
        # block sizes info
        sum_blocks_sizes_info["sum"] += nodeInGraph.size
        sum_blocks_sizes_info["max"] = max(sum_blocks_sizes_info["max"], nodeInGraph.size)

        # sys calls info
        if nodeInGraph.is_syscall:
            sum_sys_calls_info["sum"] += 1
            sum_sys_calls_info["names"].append(nodeInGraph.syscall_name)
        # looping times info
        looping_times_info["sum"] += nodeInGraph.looping_times
        looping_times_info["max"] = max(looping_times_info["max"], nodeInGraph.looping_times)

        # return info
        if nodeInGraph.has_return:
            has_return_info["sum"] += 1
        if nodeInGraph.block is not None:
            block_instructions_info["max"] = max(block_instructions_info["max"], len(nodeInGraph.block.instruction_addrs))
    return [sum_blocks_sizes_info, sum_sys_calls_info, looping_times_info, has_return_info, block_instructions_info]


extract_features_from_angr(file_path=sys.argv[1], use_accurate=True)
