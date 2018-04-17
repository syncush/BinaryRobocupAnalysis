import numpy
import sys
import pickle
import r2pipe


def radare2_cc_estimation(path_to_seralized_file, path_to_binary):
    cfg = pickle.load(open(path_to_seralized_file, 'rb'))
    r2 = r2pipe.open(path_to_binary)
    r2.cmd("aaa")
    list = []
    for func_addr, functionObject in cfg.kb.functions.iteritems():
        cc = r2.cmdj("afCc@" + hex(func_addr))
        if cc is not None and cc >= 0:
            list.append((functionObject.name, cc))
    np_cc_list = numpy.array([y for _, y in list])
    return {"max": np_cc_list.max(), "sum": np_cc_list.sum(), "mean": np_cc_list.mean(), "std": np_cc_list.std(), "list": list}


if __name__ == '__main__':
    if len(sys.argv) is not 2 + 1:
        raise Exception("\n \t".join(["Expected a parameter:", "The path to the seralized cfg", "The path to the binary"]))
    else:
        print(radare2_cc_estimation(sys.argv[1], sys.argv[2]))
