import angr
import r2pipe
import tarjan

'''
This is the list of features I want to extract from a binary file
Angr CFGAccurate Complete McCabe Complexity
Angr CFGFast complete McCabe Complexity
The Number of functions
The number of blocks
'''


class FeatureExtractor(object):

    def __init__(self, file_path):
        self._file_path = file_path
        self._angr_project = angr.Project(file_path, load_options={'auto_load_libs': False})
        self._cfg_fast = None
        self._cfg_accurate = None

    def __get_cfg__(self,use_accurate = False):
        if use_accurate:
            if self._cfg_accurate is None:
                self._cfg_accurate = self._angr_project.analyses.CFGAccurate()
            return self._cfg_accurate
        elif self._cfg_fast is None:
            self._cfg_fast = self._angr_project.analyses.CFGFast()
            return self._cfg_fast

    def get_simple_complete_mccabe_complexity_angr(self, use_accurate=False):
        cfg = self.__get_cfg__(use_accurate)
        return cfg.graph.number_of_edges() - len(cfg.graph) + 2

    def get_complex_complete_mccabe_complexity_angr(self, use_accurate=False):
        cfg = self.__get_cfg__(use_accurate)
        graph_for_tarjan_algorithm = {}
        for n, nbrsdict in cfg.adjacency():
            if len(list(nbrsdict)) >= 2:
                graph_for_tarjan_algorithm[n] = list(nbrsdict)
        return cfg.graph.number_of_edges() - len(cfg.graph) + 2 * len(tarjan.tarjan(graph_for_tarjan_algorithm))

    def radare2_cc_estimation(self, use_accurate=False):
        cfg = self.__get_cfg__(use_accurate)
        r2 = r2pipe.open(self._file_path)
        r2.cmd("aaa")
        list = []
        for func_addr, functionObject in cfg.kb.functions.iteritems():
            cc = r2.cmdj("afCc@" + hex(func_addr))
            list.append((functionObject.name, cc))

        return {"max": max(list), "sum":sum(list), "list": list}

    def extract_features_from_angr(self, use_accurate=False):
        cfg = self.__get_cfg__(use_accurate)
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