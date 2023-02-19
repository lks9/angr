import logging
import re

from . import ExplorationTechnique

l = logging.getLogger(__name__)
l.setLevel(logging.DEBUG)

class Replayer(ExplorationTechnique):

    def __init__(self, trace_str: str, functions=None):
        super().__init__()
        # Split trace_str into elements
        trace_str = trace_str.encode()
        self.elems = re.findall(br"[A-Z][0-9a-z]*", trace_str)
        self.trace_ind = 0
        self.functions = functions

    def setup(self, simgr):
        self.if_addr = self._addr("_cflow_if")
        self.else_addr = self._addr("_cflow_else")
        self.writing_addr = self._addr("_cflow_writing")
        self.wrote_int_addr = self._addr("_cflow_wrote_int")
        self.int_addr = self._addr("_cflow_int")

    def _addr(self, sym_name):
        try:
            return self.project.loader.main_object.get_symbol(sym_name).rebased_addr
        except AttributeError:
            return None

    def step(self, simgr, stash='active', **kwargs):
        elem = self.elems[self.trace_ind]
        if elem == b"T":

            find = self.if_addr
            avoid = [self.else_addr, self.wrote_int_addr]
        elif elem == b"N":

            find = self.else_addr
            avoid = [self.if_addr, self.wrote_int_addr]
        elif self.functions and b"F" in elem:
            func_num = int(elem[1:], 16)
            if func_num == 0:
                # There is no func with num 0, that simply marks the end of the trace
                return simgr
            func_name = self.functions["hex_list"][func_num]["name"]
            if func_name == "main":
                func_name = "main_original"
            find = self._addr(func_name)
            avoid = [self.else_addr, self.if_addr, self.wrote_int_addr]
        elif b"D" in elem:
            find = self.wrote_int_addr
            avoid = [self.else_addr, self.if_addr]
        else:
            raise ValueError(f'Trace contains unsupported element "{elem}"')

        # step to make sure the current state is not in one of the avoid state
        if self.trace_ind != 0:
            simgr.step()
        simgr.explore(find=find, avoid=avoid, avoid_priority=True)

        if len(simgr.found) != 1:
            l.error("Found %i canditates in simgr %s", len(simgr.found), simgr)

        if b"D" in elem:
            # add the constrain for the int
            trace_int = int(elem[1:], 16)
            state = simgr.found[0]
            mem_int = state.mem[self.int_addr].int
            state.solver.add(trace_int == mem_int)

        # avoid all states not in found
        simgr.drop()

        self.trace_ind += 1
        l.debug("trace with %s, arrive at %s", elem.decode(), simgr.found[0].__str__())

        simgr.move(from_stash='found', to_stash='active')

        return simgr

    def complete(self, simgr):
        return (self.trace_ind >= len(self.elems)) or (b"F0" in self.elems[self.trace_ind])
