import angr
import sys
import pickle
import tarjan

cfg = None


def get_loaded_cfg(path_to_serialized):
    global cfg
    if cfg is not None:
        return cfg
    cfg = pickle.load(open(path_to_serialized, 'rb'))
    return cfg


def get_simple_complete_mccabe_complexity_angr(path_to_seralized_cfg):
    cfg_to_analyze = get_loaded_cfg(path_to_seralized_cfg)
    return cfg_to_analyze.graph.number_of_edges() - len(cfg_to_analyze.graph) + 2


def get_complex_complete_mccabe_complexity_angr(path_to_seralized):
    cfg_to_analyze = get_loaded_cfg(path_to_seralized)
    graph_for_tarjan_algorithm = {}
    for n, nbrsdict in cfg_to_analyze.graph.adjacency():
        if len(list(nbrsdict)) >= 2:
            graph_for_tarjan_algorithm[n] = list(nbrsdict)
    return cfg_to_analyze.graph.number_of_edges() - len(cfg_to_analyze.graph) + 2 * len(tarjan.tarjan(graph_for_tarjan_algorithm))


if __name__ == '__main__':
    if len(sys.argv) is not 1 + 1:
        raise Exception('\n \t'.join["Expected a parameter", "The path to the seralized cfg object"])
    else:
        print({"Simple_McCabe": get_simple_complete_mccabe_complexity_angr(sys.argv[1]), "Complex_McCabe": get_complex_complete_mccabe_complexity_angr(sys.argv[1])})
