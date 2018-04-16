import sys
import csv
from os import walk
import extractor


def str2bool(v):
    return v.lower() in ("yes", "true", "t", "1")


def write_to_csv(dir_to_analyze_path='/home/syncush/PycharmProjects/BinaryRobocupAnalysis/test', dst_csv_path='/home/syncush/Desktop', csv_file_name='BinaryRobocup', use_accurate=False):
    binaryPaths = []
    for (dirpath, dirnames, filenames) in walk(dir_to_analyze_path):
        temp = [dirpath + '/' + x for x in filenames]
        binaryPaths.extend(temp)
    with open(dst_csv_path + "/" + csv_file_name + ".csv", 'wb') as out:
        csv_out = csv.writer(out)
        csv_out.writerow(["Binary Path", "cfg_node_size-sum", "cfg_node_size-max", "cfg_syscalls-count", "cfg_syscalls-names", "cfg_looping_time-sum", "cfg_looping_time-max", "cfg_return-count", "cfg_block_size- max", "radare2-max CC", "radare2-func_CC tuple", "complex CC", "simple CC"])
        for binaryPath in binaryPaths:
            analyzer = extractor.FeatureExtractor(binaryPath)
            features = analyzer.analyze_everything(use_accurate)
            cfg_node_size = [features[0]["sum"], features[0]["max"]]
            cfg_sys_calls_info = [features[1]["sum"], '/'.join(features[1]["names"])]
            cfg_looping_times_info = [features[2]["sum"], features[2]["max"]]
            cfg_return_info = [features[3]["sum"]]
            cfg_block_instructions_info = [features[4]["max"]]
            radare2_max_complexity = [features[5]["max"]]
            radare2_complexity = ['/'.join([x + '-' + str(r) for x, r in features[5]["list"]])]
            angr_mc_cabe_complexity = [features[6], features[7]]
            output_to_csv = [binaryPath] + cfg_node_size + cfg_sys_calls_info + cfg_looping_times_info + cfg_return_info + cfg_block_instructions_info + radare2_max_complexity + radare2_complexity + angr_mc_cabe_complexity
            csv_out.writerow(output_to_csv)


if __name__ == '__main__':
    write_to_csv(sys.argv[1], sys.argv[2], sys.argv[3], False)