import angr
import sys
import pickle


def get_simple_complete_mccabe_complexity_angr(path_to_seralized_cfg):
    cfg = pickle.load(open(path_to_seralized_cfg, 'rb'))
    return cfg.graph.number_of_edges() - len(cfg.graph) + 2


if __name__ == '__main__':
    if len(sys.argv) is not 1 + 1:
        raise Exception('\n \t'.join["Expected a parameter", "The path to the seralized cfg object"])
    else:
        print(get_simple_complete_mccabe_complexity_angr(sys.argv[1]))
