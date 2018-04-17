import pickle
import angr
import sys


def str2bool(v):
    return v.lower() in ("yes", "true", "t", "1")


def get_cfg(binary_path, use_accurate=False):
    angr_project = angr.Project(binary_path, load_options={'auto_load_libs': False})
    if use_accurate:
        return angr_project.analyses.CFGAccurate()
    else:
        return angr_project.analyses.CFGFast()


def seralize_my_cfg(binary_path, dst_path, output_file_name, use_accurate=False):
    pickle.dump(get_cfg(binary_path, use_accurate), open('/'.join([dst_path, output_file_name + '.bin']), "wb"), -1)


if __name__ == '__main__':
    if len(sys.argv) is 4 + 1:
        seralize_my_cfg(sys.argv[1], sys.argv[2], sys.argv[3], str2bool(sys.argv[4]))
    else:
        raise Exception('\n \t '.join(["Expected to get 4 parameters", "Path to the binary file", "Path to the destination file", "The name of the output file", "True to use CFGAccurate, False otherwise"]))
