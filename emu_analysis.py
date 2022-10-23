from emu_utils import *
import am_graph
import angr


class ReleNode():

    def __init__(self, node=None):
        self.node_inst     = []
        self.relative_addr = []
        self.branch_addr   = [0] * 2
        self.sg_node       = node
        self.have_branch   = False
        self.cmov_inst     = None
        self.branch_type   = None

    def get_node_inst(self, tar_func):
        node_inst = self.node_inst
        if self.sg_node == tar_func.prologue_node:
            edge_addr = tar_func.main_dispatcher_node.addr
        else:
            edge_addr = tar_func.pre_dispatcher_node.addr

        for i in range(len(node_inst)):
            if (node_inst[(i+1)%len(node_inst)]['addr']== edge_addr):
                node_inst = node_inst[:i+1]
                break

        self.node_inst = node_inst

    def patch(self, tar_func):
        base_addr = tar_func.base_addr
        next_addr = self.sg_node.addr + self.sg_node.size

        if self.have_branch:
            patch_addr = self.cmov_inst['addr']
            patch_size = next_addr - patch_addr
            patch_raw  = patch_addr - base_addr

            jx_asm     = 'j' + self.branch_type + ' ' + hex(self.branch_addr[1])
            jmp_asm    = 'jmp ' + hex(self.branch_addr[0])

            patch_asm  = b''
            patch_asm += get_asm(jx_asm, patch_addr)
            patch_asm += get_asm(jmp_asm, patch_addr+len(patch_asm))
            patch_asm += b'\x90' * (patch_size - len(patch_asm))
            patch_asm  = bytearray(patch_asm)

            tar_func.file_buf[patch_raw:patch_raw+patch_size] = patch_asm[:patch_size]
        else:
            patch_addr  = self.node_inst[-2]['addr']
            patch_size  = next_addr - patch_addr
            patch_raw   = patch_addr - base_addr

            jmp_asm     = 'jmp ' + hex(self.branch_addr[0])

            patch_asm   = b''
            patch_asm  += get_asm(jmp_asm, patch_addr)
            patch_asm  += b'\x90' * (patch_size - len(patch_asm))
            patch_asm   = bytearray(patch_asm)

            tar_func.file_buf[patch_raw:patch_raw+patch_size] = patch_asm[:patch_size]


class TarFunc():
    base_addr            = None
    supergraph           = None
    prologue_node        = None
    pre_dispatcher_node  = None
    main_dispatcher_node = None
    relevant_nodes       = {}
    nop_nodes            = []
    retn_node            = None

    def __init__(self, filename=None, start_addr=None, end_addr=None):
        self.filename   = filename
        self.start_addr = start_addr
        self.end_addr   = end_addr

        self.file_buf = bytearray(read(self.filename))
        self.get_supergraph(filename, start_addr, end_addr)
        self.get_prologue_retn_node()
        self.get_dispatcher_nodes()
        self.get_relevant_nop_nodes()

    def get_supergraph(self, filename, start_addr, end_addr):
        # create angr project
        p = angr.Project(
            filename,
            load_options={'auto_load_libs': False},
        )

        # generate control flow graph, and then transit to supergraph
        # A super transition graph is a graph that looks like IDA Pro's CFG
        cfg = p.analyses.CFGFast(
            force_complete_scan=False,
            normalize=True,
        )
        target_func     = cfg.functions.get(start_addr)
        supergraph      = am_graph.to_supergraph(target_func.transition_graph)

        self.base_addr  = p.loader.main_object.mapped_base
        self.supergraph = supergraph

    def get_prologue_retn_node(self):
        supergraph = self.supergraph

        for node in supergraph.nodes():
            if   supergraph.in_degree(node)  == 0:
                prologue_node = node
            elif supergraph.out_degree(node) == 0:
                retn_node     = node

        self.relevant_nodes[hex(retn_node.addr)] = ReleNode(retn_node)
        self.relevant_nodes[hex(prologue_node.addr)] = ReleNode(prologue_node)
        self.prologue_node = prologue_node
        self.retn_node     = retn_node

    def get_dispatcher_nodes(self):
        supergraph    = self.supergraph
        prologue_node = self.prologue_node

        self.main_dispatcher_node  = list(
            supergraph.successors(prologue_node))[0]
        for node in supergraph.predecessors(self.main_dispatcher_node):
            if node.addr != self.prologue_node.addr:
                self.pre_dispatcher_node = node

    def get_relevant_nop_nodes(self):
        supergraph           = self.supergraph
        main_dispatcher_node = self.main_dispatcher_node
        pre_dispatcher_node  = self.pre_dispatcher_node
        prologue_node        = self.prologue_node
        retn_node            = self.retn_node

        relevant_nodes = self.relevant_nodes
        nop_nodes      = self.nop_nodes

        for node in supergraph.nodes():
            if (supergraph.has_edge(node, pre_dispatcher_node) and
                node.size > 12
            ):
                relevant_nodes[hex(node.addr)] = ReleNode(node)
                continue

            elif node.addr not in (
                prologue_node.addr,
                main_dispatcher_node.addr,
                pre_dispatcher_node.addr,
                retn_node.addr
            ):
                nop_nodes.append(node)
                continue

        self.relevant_nodes = relevant_nodes
        self.nop_nodes      = nop_nodes

    def fill_nop(self):
        self.nop_nodes.append(self.main_dispatcher_node)
        self.nop_nodes.append(self.pre_dispatcher_node)
        for node in self.nop_nodes:
            patch_raw = node.addr - self.base_addr
            patch_asm = b'\x90' * node.size
            patch_asm = bytearray(patch_asm)
            pacth_size = len(patch_asm)
            self.file_buf[patch_raw:patch_raw+pacth_size] = patch_asm[:pacth_size]
            
