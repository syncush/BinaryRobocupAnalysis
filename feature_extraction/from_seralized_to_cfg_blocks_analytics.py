import angr
import pickle
import sys
import numpy

def get_loaded_cfg(path_to_serialized):
    global cfg
    if cfg is not None:
        return cfg
    cfg = pickle.load(open(path_to_serialized, 'rb'))
    return cfg


def extract_features_from_angr(path_to_serialized):
    cfg = get_loaded_cfg(path_to_serialized)
    sum_blocks_sizes_info = []
    sys_calls_info = {"names": [], "count": 0}
    looping_times_info = []
    has_return_info = 0
    block_instructions_info = []

    for nodeInGraph, info in cfg.graph.nodes.iteritems():
        # block sizes info
        sum_blocks_sizes_info.append(nodeInGraph.size)

        # sys calls info
        if nodeInGraph.is_syscall:
            sys_calls_info["count"] += 1
            sys_calls_info["names"].append(nodeInGraph.syscall_name)

        # looping times info
        looping_times_info.append(nodeInGraph.looping_times)

        # return info
        if nodeInGraph.has_return:
            has_return_info += 1
        if nodeInGraph.block is not None:
            block_instructions_info.append(len(nodeInGraph.block.instruction_addrs))
    sum_blocks_sizes_info = numpy.array(sum_blocks_sizes_info)
    looping_times_info = numpy.array(looping_times_info)
    block_instructions_info = numpy.array(block_instructions_info)
    # TODO: FINISH WITH THIS SHIT
    return [sum_blocks_sizes_info, sys_calls_info, looping_times_info, has_return_info, block_instructions_info]


if __name__ == '__main__':
    if len(sys.argv) is not 1 + 1:
        print("\n \t".join(["Expected a parameter:", "The path to the seralized cfg"]))
    else:
        print(extract_features_from_angr(sys.argv[1]))
