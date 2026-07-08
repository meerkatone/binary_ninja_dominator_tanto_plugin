"""
Dominator Analysis Plugin for Tanto

This plugin adds unique dominator-related views to the Tanto graph visualization plugin for Binary Ninja
that extend Tanto's built-in capabilities:

Dominator Views:
1. Iterated Dominance Frontier - Shows the iterated dominance frontier (useful for phi node placement)
2. Immediate Dominator - Shows the immediate dominator of the current block
3. Strict Dominators - Shows all dominators except the block itself
4. Full Dominator Tree - Shows the entire dominator tree

Post-Dominator Views:
5. Immediate Post Dominator - Shows the immediate post-dominator of the current block
6. Full Post Dominator Tree - Shows the entire post-dominator tree

Installation:
1. Place this file in your Binary Ninja plugins directory
2. Ensure the Tanto plugin is installed

Note: This plugin should be loaded after the Tanto plugin is fully initialized.
"""

from collections import deque
from typing import Dict, List, Optional, Set, Tuple

import binaryninja
from binaryninja import log_info, log_error, log_debug
from binaryninja.plugin import BackgroundTaskThread

try:
    import tanto
except ModuleNotFoundError:
    import binaryninja
    from os import path
    from sys import path as python_path
    python_path.append(path.abspath(path.join(binaryninja.user_plugin_path(), '../repositories/official/plugins')))
    import tanto

from tanto.tanto_view import TantoView
from tanto.slices import Slice, UpdateStyle
import tanto.helpers

from binaryninja import FlowGraph, FlowGraphNode
from binaryninja.enums import BranchType, FunctionGraphType, HighlightStandardColor, InstructionTextTokenType


MAX_SSA_SLICE_DEPTH = 48
MAX_SSA_SLICE_IPC_HOPS = 2
MAX_SSA_SLICE_NODES = 240
MAX_SSA_SLICE_FANOUT = 64

CONCRETE_CALL_TARGET_TYPES = {
    binaryninja.RegisterValueType.ConstantValue,
    binaryninja.RegisterValueType.ConstantPointerValue,
    binaryninja.RegisterValueType.ImportedAddressValue,
}

KNOWN_CALL_ARG_ROLES = {
    "memcpy": {"dest": 0, "src": 1, "size": 2},
    "memmove": {"dest": 0, "src": 1, "size": 2},
    "memset": {"dest": 0, "size": 2},
    "strcpy": {"dest": 0, "src": 1},
    "strncpy": {"dest": 0, "src": 1, "size": 2},
    "strcat": {"dest": 0, "src": 1},
    "strncat": {"dest": 0, "src": 1, "size": 2},
    "recv": {"dest": 1, "size": 2},
    "recvfrom": {"dest": 1, "size": 2},
    "read": {"dest": 1, "size": 2},
    "fread": {"dest": 0, "size": 1, "count": 2},
    "malloc": {"size": 0},
    "calloc": {"count": 0, "size": 1},
    "realloc": {"dest": 0, "size": 1},
    "snprintf": {"dest": 0, "size": 1, "src": 2},
    "vsnprintf": {"dest": 0, "size": 1, "src": 2},
    "sprintf": {"dest": 0, "src": 1},
    "vsprintf": {"dest": 0, "src": 1},
}

SSA_SETTING_PREFIX = "dominator_plugin.ssa"
SSA_SETTING_DEFAULTS = {
    "depth_cap": MAX_SSA_SLICE_DEPTH,
    "ipc_hops": MAX_SSA_SLICE_IPC_HOPS,
    "max_nodes": MAX_SSA_SLICE_NODES,
    "fanout": MAX_SSA_SLICE_FANOUT,
}


def _register_ssa_settings():
    try:
        settings = binaryninja.Settings()
        settings.register_group("dominator_plugin", "Dominator Plugin")
        settings.register_setting(
            f"{SSA_SETTING_PREFIX}.depth_cap",
            f'{{"title": "SSA Slice Depth Cap", "type": "number", "default": {MAX_SSA_SLICE_DEPTH}, '
            '"description": "Maximum SSA def-use traversal depth for dominator_plugin slices."}',
        )
        settings.register_setting(
            f"{SSA_SETTING_PREFIX}.ipc_hops",
            f'{{"title": "SSA Slice Interprocedural Hops", "type": "number", "default": {MAX_SSA_SLICE_IPC_HOPS}, '
            '"description": "Maximum caller/callee hops for interprocedural SSA slices."}',
        )
        settings.register_setting(
            f"{SSA_SETTING_PREFIX}.max_nodes",
            f'{{"title": "SSA Slice Max Nodes", "type": "number", "default": {MAX_SSA_SLICE_NODES}, '
            '"description": "Approximate maximum graph node budget for SSA slices."}',
        )
        settings.register_setting(
            f"{SSA_SETTING_PREFIX}.fanout",
            f'{{"title": "SSA Slice Fanout", "type": "number", "default": {MAX_SSA_SLICE_FANOUT}, '
            '"description": "Maximum uses/callers/callees explored from one SSA node."}',
        )
    except Exception as e:
        log_debug(f"Could not register SSA dataflow settings: {e}")


def _ssa_setting(name: str) -> int:
    key = f"{SSA_SETTING_PREFIX}.{name}"
    default = SSA_SETTING_DEFAULTS[name]
    settings = binaryninja.Settings()
    for getter in ("get_integer", "get_double"):
        fn = getattr(settings, getter, None)
        if fn is None:
            continue
        try:
            value = fn(key)
            if value is not None:
                return max(0, int(value))
        except Exception:
            pass
    return default


_register_ssa_settings()


class DominanceSliceBase(Slice):
    """Base class for all dominator-related slices"""
    
    def __init__(self, _):
        self.update_style = UpdateStyle.ON_NAVIGATE
        
    def get_block_node(self, flowgraph, block):
        """Helper to create a FlowGraphNode from a basic block"""
        node = FlowGraphNode(flowgraph)
        if block is not None:
            node.lines = block.get_disassembly_text(tanto.helpers.get_disassembly_settings())
        else:
            node.lines = [_text_line("No block found")]
        flowgraph.append(node)
        return node


class PostDominatorTreeChildrenSlice(DominanceSliceBase):
    """Displays immediate post dominator tree children of the current block"""
    
    def get_flowgraph(self) -> FlowGraph:
        flowgraph = FlowGraph()

        current_block = tanto.helpers.get_current_il_basic_block()
        if current_block is None:
            return flowgraph

        node = self.get_block_node(flowgraph, current_block)

        for child in current_block.post_dominator_tree_children:
            child_node = self.get_block_node(flowgraph, child)
            node.add_outgoing_edge(BranchType.UnconditionalBranch, child_node)
        
        return flowgraph


class FullPostDominatorTreeSlice(DominanceSliceBase):
    """Displays the full post dominator tree for the current function"""
    
    def get_flowgraph(self) -> FlowGraph:
        flowgraph = FlowGraph()

        if (function := tanto.helpers.get_current_il_function()) is None:
            return flowgraph

        # Find the entry block of the post dominator tree
        # This is typically the exit block of the function
        exit_blocks = []
        for block in function.basic_blocks:
            if not block.outgoing_edges:
                exit_blocks.append(block)

        if not exit_blocks:
            return flowgraph
        
        # Use the first exit block as our root
        root_block = exit_blocks[0]
        
        root_node = self.get_block_node(flowgraph, root_block)

        def add_children(block, parent_node):
            for child in block.post_dominator_tree_children:
                child_node = self.get_block_node(flowgraph, child)
                parent_node.add_outgoing_edge(BranchType.UnconditionalBranch, child_node)
                add_children(child, child_node)

        add_children(root_block, root_node)
        return flowgraph


class PostDominanceFrontierSlice(DominanceSliceBase):
    """Displays the post dominance frontier for the current block"""
    
    def get_flowgraph(self) -> FlowGraph:
        flowgraph = FlowGraph()

        current_block = tanto.helpers.get_current_il_basic_block()
        if current_block is None:
            return flowgraph

        node = self.get_block_node(flowgraph, current_block)

        for frontier_block in current_block.post_dominance_frontier:
            frontier_node = self.get_block_node(flowgraph, frontier_block)
            node.add_outgoing_edge(BranchType.UnconditionalBranch, frontier_node)
        
        return flowgraph


class PostDominatorsSlice(DominanceSliceBase):
    """Displays all post dominators for the current block"""
    
    def get_flowgraph(self) -> FlowGraph:
        flowgraph = FlowGraph()

        current_block = tanto.helpers.get_current_il_basic_block()
        if current_block is None:
            return flowgraph

        current_node = self.get_block_node(flowgraph, current_block)

        next_block = current_block.immediate_post_dominator
        while next_block is not None:
            next_node = self.get_block_node(flowgraph, next_block)
            current_node.add_outgoing_edge(BranchType.UnconditionalBranch, next_node)
            current_node = next_node
            next_block = next_block.immediate_post_dominator
        
        return flowgraph


class DominatorsSlice(DominanceSliceBase):
    """Displays all dominators for the current block"""
    
    def get_flowgraph(self) -> FlowGraph:
        flowgraph = FlowGraph()

        current_block = tanto.helpers.get_current_il_basic_block()
        if current_block is None:
            return flowgraph

        current_node = self.get_block_node(flowgraph, current_block)

        next_block = current_block.immediate_dominator
        while next_block is not None:
            next_node = self.get_block_node(flowgraph, next_block)
            next_node.add_outgoing_edge(BranchType.UnconditionalBranch, current_node)
            current_node = next_node
            next_block = next_block.immediate_dominator
        
        return flowgraph


class DominanceFrontierSlice(DominanceSliceBase):
    """Displays the dominance frontier for the current block"""
    
    def get_flowgraph(self) -> FlowGraph:
        flowgraph = FlowGraph()

        current_block = tanto.helpers.get_current_il_basic_block()
        if current_block is None:
            return flowgraph

        node = self.get_block_node(flowgraph, current_block)

        for frontier_block in current_block.dominance_frontier:
            frontier_node = self.get_block_node(flowgraph, frontier_block)
            node.add_outgoing_edge(BranchType.UnconditionalBranch, frontier_node)
        
        return flowgraph


class DominatorTreeChildrenSlice(DominanceSliceBase):
    """Displays immediate dominator tree children of the current block"""
    
    def get_flowgraph(self) -> FlowGraph:
        flowgraph = FlowGraph()

        current_block = tanto.helpers.get_current_il_basic_block()
        if current_block is None:
            return flowgraph

        node = self.get_block_node(flowgraph, current_block)

        for child in current_block.dominator_tree_children:
            child_node = self.get_block_node(flowgraph, child)
            node.add_outgoing_edge(BranchType.UnconditionalBranch, child_node)
        
        return flowgraph


class ImmediateDominatorSlice(DominanceSliceBase):
    """Displays the immediate dominator of the current block"""
    
    def get_flowgraph(self) -> FlowGraph:
        flowgraph = FlowGraph()

        current_block = tanto.helpers.get_current_il_basic_block()
        if current_block is None:
            return flowgraph

        current_node = self.get_block_node(flowgraph, current_block)
        
        if current_block.immediate_dominator is not None:
            dom_node = self.get_block_node(flowgraph, current_block.immediate_dominator)
            dom_node.add_outgoing_edge(BranchType.UnconditionalBranch, current_node)
        
        return flowgraph


class ImmediatePostDominatorSlice(DominanceSliceBase):
    """Displays the immediate post dominator of the current block"""
    
    def get_flowgraph(self) -> FlowGraph:
        flowgraph = FlowGraph()

        current_block = tanto.helpers.get_current_il_basic_block()
        if current_block is None:
            return flowgraph

        current_node = self.get_block_node(flowgraph, current_block)
        
        if current_block.immediate_post_dominator is not None:
            dom_node = self.get_block_node(flowgraph, current_block.immediate_post_dominator)
            current_node.add_outgoing_edge(BranchType.UnconditionalBranch, dom_node)
        
        return flowgraph


class StrictDominatorsSlice(DominanceSliceBase):
    """Displays all dominators for the current block except the block itself"""
    
    def get_flowgraph(self) -> FlowGraph:
        flowgraph = FlowGraph()

        current_block = tanto.helpers.get_current_il_basic_block()
        if current_block is None:
            return flowgraph

        # Skip the current block and start with its immediate dominator
        next_block = current_block.immediate_dominator
        if next_block is None:
            node = self.get_block_node(flowgraph, None)
            node.lines = [_text_line("No strict dominators")]
            return flowgraph
            
        current_node = self.get_block_node(flowgraph, next_block)
        
        # Continue with the rest of the dominators
        next_block = next_block.immediate_dominator
        while next_block is not None:
            next_node = self.get_block_node(flowgraph, next_block)
            next_node.add_outgoing_edge(BranchType.UnconditionalBranch, current_node)
            current_node = next_node
            next_block = next_block.immediate_dominator
        
        return flowgraph


class FullDominatorTreeSlice(DominanceSliceBase):
    """Displays the full dominator tree for the current function"""
    
    def get_flowgraph(self) -> FlowGraph:
        flowgraph = FlowGraph()

        if (function := tanto.helpers.get_current_il_function()) is None:
            return flowgraph

        # Use the entry block as the root for dominator tree
        if len(function.basic_blocks) == 0:
            return flowgraph
            
        root_block = function.basic_blocks[0]
        root_node = self.get_block_node(flowgraph, root_block)

        def add_children(block, parent_node):
            for child in block.dominator_tree_children:
                child_node = self.get_block_node(flowgraph, child)
                parent_node.add_outgoing_edge(BranchType.UnconditionalBranch, child_node)
                add_children(child, child_node)

        add_children(root_block, root_node)
        return flowgraph


class IteratedDominanceFrontierSlice(DominanceSliceBase):
    """Displays the iterated dominance frontier for the current block (useful for phi node placement)"""
    
    def get_flowgraph(self) -> FlowGraph:
        flowgraph = FlowGraph()

        current_block = tanto.helpers.get_current_il_basic_block()
        if current_block is None:
            return flowgraph

        node = self.get_block_node(flowgraph, current_block)
        
        # Calculate iterated dominance frontier
        blocks = set([current_block])
        frontier = set()
        worklist = list(blocks)
        
        while worklist:
            block = worklist.pop(0)
            for df_block in block.dominance_frontier:
                if df_block not in frontier:
                    frontier.add(df_block)
                    worklist.append(df_block)
        
        # Display the frontier blocks
        for frontier_block in frontier:
            frontier_node = self.get_block_node(flowgraph, frontier_block)
            node.add_outgoing_edge(BranchType.UnconditionalBranch, frontier_node)
        
        return flowgraph


def _var_key(func_ssa, ssa_var) -> Tuple[int, str]:
    return (func_ssa.source_function.start, f"{ssa_var.var.identifier}#{ssa_var.version}")


def _expr_key(expr) -> Tuple[int, int]:
    return (expr.function.source_function.start, expr.instr_index)


def _append_text_node(flowgraph: FlowGraph, title: str, detail: str = "", address: int = 0) -> FlowGraphNode:
    node = FlowGraphNode(flowgraph)
    lines = [_text_line(title, address)]
    if detail:
        lines.append(_text_line(detail, address))
    node.lines = lines
    flowgraph.append(node)
    return node


def _text_line(text: str, address: int = 0) -> binaryninja.DisassemblyTextLine:
    token = binaryninja.InstructionTextToken(InstructionTextTokenType.TextToken, text)
    return binaryninja.DisassemblyTextLine([token], address=address)


def _highlight_for_role(role: str):
    role = (role or "").upper()
    if role == "SEED":
        return HighlightStandardColor.GreenHighlightColor
    if role == "PARAM":
        return HighlightStandardColor.BlueHighlightColor
    if role == "CALL":
        return HighlightStandardColor.YellowHighlightColor
    if role == "PHI":
        return HighlightStandardColor.MagentaHighlightColor
    if role == "RET":
        return HighlightStandardColor.CyanHighlightColor
    if role in {"MEM", "MEMORY SOURCE", "PARAM BOUNDARY", "PARAM SOURCE"}:
        return HighlightStandardColor.OrangeHighlightColor
    if role.startswith("UNRESOLVED") or role in {"CALL SOURCE", "SSA SOURCE"}:
        return HighlightStandardColor.RedHighlightColor
    return HighlightStandardColor.NoHighlightColor


def _ssa_var_name(ssa_var) -> str:
    try:
        return f"{ssa_var.var.name}#{ssa_var.version}"
    except Exception:
        return str(ssa_var)


def _function_label(func) -> str:
    try:
        return f"{func.name} @ {func.start:#x}"
    except Exception:
        return str(func)


def _operation_name(expr) -> str:
    try:
        return expr.operation.name
    except Exception:
        return type(expr).__name__


def _expr_label(expr, role: str) -> str:
    addr = getattr(expr, "address", 0)
    try:
        text = str(expr).replace("\n", " ")
    except Exception:
        text = _operation_name(expr)
    if len(text) > 110:
        text = text[:107] + "..."
    return f"{role.upper()} {addr:#x}: {text}"


def _is_ssa_var(value) -> bool:
    return isinstance(value, binaryninja.SSAVariable)


def _ssa_vars_of_expression(expr) -> List[binaryninja.SSAVariable]:
    if expr is None:
        return []
    if not isinstance(expr, binaryninja.MediumLevelILInstruction):
        try:
            expr = expr.ssa_form
        except Exception:
            return []
    try:
        ssa_expr = expr if expr.ssa_form is expr else expr.ssa_form
    except Exception:
        ssa_expr = expr

    vars_seen: List[binaryninja.SSAVariable] = []
    for attr in ("vars_read", "vars_written"):
        try:
            for var in getattr(ssa_expr, attr, []):
                if _is_ssa_var(var) and var not in vars_seen:
                    vars_seen.append(var)
        except Exception:
            pass
    for attr in ("src", "dest", "output"):
        try:
            value = getattr(ssa_expr, attr)
        except Exception:
            continue
        candidates = value if isinstance(value, (list, tuple)) else [value]
        for candidate in candidates:
            if _is_ssa_var(candidate) and candidate not in vars_seen:
                vars_seen.append(candidate)
    return vars_seen


def _ssa_vars_written_by_expression(expr) -> List[binaryninja.SSAVariable]:
    if expr is None:
        return []
    try:
        ssa_expr = expr if expr.ssa_form is expr else expr.ssa_form
    except Exception:
        ssa_expr = expr
    vars_seen: List[binaryninja.SSAVariable] = []
    try:
        for var in ssa_expr.vars_written:
            if _is_ssa_var(var) and var not in vars_seen:
                vars_seen.append(var)
    except Exception:
        pass
    for attr in ("output",):
        try:
            value = getattr(ssa_expr, attr)
        except Exception:
            continue
        candidates = value if isinstance(value, (list, tuple)) else [value]
        for candidate in candidates:
            if _is_ssa_var(candidate) and candidate not in vars_seen:
                vars_seen.append(candidate)
    return vars_seen


def _trivial_copy_source(defn):
    try:
        if defn.operation != binaryninja.MediumLevelILOperation.MLIL_SET_VAR_SSA:
            return None
        src = defn.src
        if getattr(src, "operation", None) != binaryninja.MediumLevelILOperation.MLIL_VAR_SSA:
            return None
        vars_read = _ssa_vars_of_expression(src)
        if len(vars_read) == 1:
            return vars_read[0]
    except Exception:
        return None
    return None


def _mlil_ssa_function(source_func) -> Optional[binaryninja.MediumLevelILFunction]:
    try:
        if source_func is None or source_func.medium_level_il is None:
            return None
        return source_func.medium_level_il.ssa_form
    except Exception:
        return None


def _selected_mlil_ssa_expr():
    try:
        expr = tanto.helpers.get_selected_expr()
    except Exception:
        expr = None

    if isinstance(expr, binaryninja.MediumLevelILInstruction):
        try:
            return expr if expr.ssa_form is expr else expr.ssa_form
        except Exception:
            return expr

    source_func = None
    try:
        source_func = tanto.helpers.get_current_source_function()
    except Exception:
        source_func = None
    func_ssa = _mlil_ssa_function(source_func)
    if func_ssa is None:
        return None

    addr = None
    try:
        addr = getattr(expr, "address", None)
    except Exception:
        addr = None
    if addr is None:
        try:
            addr = tanto.helpers.get_current_address()
        except Exception:
            addr = None

    if addr is None:
        return None

    try:
        idx = func_ssa.get_instruction_start(addr)
        if idx is not None:
            return func_ssa[idx]
    except Exception:
        pass
    try:
        for instr in func_ssa.instructions:
            if instr.address == addr:
                return instr
    except Exception:
        pass
    return None


def _selected_ssa_var_from_token():
    try:
        from binaryninjaui import UIContext
        view_context = UIContext.activeContext()
        if view_context is None or view_context.getCurrentView() is None:
            return None, None
        hts = view_context.getCurrentView().getHighlightTokenState()
        if hts is None or not hts.valid:
            return None, None
        token = hts.token
        if not getattr(token, "localVarValid", False):
            return None, None
        source_func = tanto.helpers.get_current_source_function()
        func_ssa = _mlil_ssa_function(source_func)
        if func_ssa is None:
            return None, None
        var = binaryninja.Variable.from_core_variable(func_ssa, token.localVar)
        token_text = str(token.token)
        if "#" in token_text:
            version_text = token_text.rsplit("#", 1)[-1]
            try:
                return func_ssa, binaryninja.SSAVariable(var, int(version_text))
            except Exception:
                pass
        try:
            version = func_ssa.get_ssa_var_version(var, 0)
            return func_ssa, binaryninja.SSAVariable(var, version)
        except Exception:
            return func_ssa, var
    except Exception:
        return None, None


def _param_index_of(func: binaryninja.Function, ssa_var) -> Optional[int]:
    try:
        for idx, param_var in enumerate(func.parameter_vars):
            if param_var == ssa_var.var:
                return idx
    except Exception:
        return None
    return None


def _callee_address(call_expr) -> Optional[int]:
    try:
        dest_val = call_expr.dest.value
        if dest_val.type in CONCRETE_CALL_TARGET_TYPES:
            return dest_val.value
    except Exception:
        return None
    return None


def _normalize_call_name(name: str) -> str:
    name = (name or "").split("@", 1)[0]
    name = name.rsplit(".", 1)[0]
    while name.startswith("_"):
        name = name[1:]
    if name.startswith("j_"):
        name = name[2:]
    return name


def _callee_name(call_expr, bv=None) -> str:
    callee_addr = _callee_address(call_expr)
    if bv is not None and callee_addr is not None:
        try:
            func = bv.get_function_at(callee_addr)
            if func is not None and func.name:
                return _normalize_call_name(func.name)
        except Exception:
            pass
    try:
        return _normalize_call_name(str(call_expr.dest))
    except Exception:
        return ""


def _known_call_arg_index(call_expr, bv, role_names) -> Optional[int]:
    call_name = _callee_name(call_expr, bv)
    roles = KNOWN_CALL_ARG_ROLES.get(call_name)
    if roles is None:
        return None
    for role in role_names:
        if role in roles:
            return roles[role]
    return None


def _call_params(call_expr) -> List:
    try:
        return list(call_expr.params)
    except Exception:
        return []


def _is_call_expr(expr) -> bool:
    try:
        return "CALL" in expr.operation.name
    except Exception:
        return False


def _is_phi_expr(expr) -> bool:
    try:
        return "PHI" in expr.operation.name
    except Exception:
        return False


def _expr_role(expr, default_role: str) -> str:
    if _is_call_expr(expr):
        return "CALL" if default_role == "def" else default_role
    if _is_phi_expr(expr):
        return "PHI"
    try:
        if expr.operation == binaryninja.MediumLevelILOperation.MLIL_RET:
            return "RET"
    except Exception:
        pass
    try:
        if "LOAD" in expr.operation.name or "MEM" in expr.operation.name:
            return "MEM"
    except Exception:
        pass
    return default_role


def _call_output_vars(call_expr) -> List[binaryninja.SSAVariable]:
    vars_seen: List[binaryninja.SSAVariable] = []
    for attr in ("output", "dest"):
        try:
            value = getattr(call_expr, attr)
        except Exception:
            continue
        candidates = value if isinstance(value, (list, tuple)) else [value]
        for candidate in candidates:
            if _is_ssa_var(candidate) and candidate not in vars_seen:
                vars_seen.append(candidate)
    try:
        for var in call_expr.vars_written:
            if _is_ssa_var(var) and var not in vars_seen:
                vars_seen.append(var)
    except Exception:
        pass
    return vars_seen


def _return_value_vars(func_ssa) -> List[Tuple[object, binaryninja.SSAVariable]]:
    seeds: List[Tuple[object, binaryninja.SSAVariable]] = []
    try:
        instructions = list(func_ssa.instructions)
    except Exception:
        return seeds
    for instr in instructions:
        if getattr(instr, "operation", None) != binaryninja.MediumLevelILOperation.MLIL_RET:
            continue
        try:
            srcs = instr.src or []
        except Exception:
            srcs = []
        for src in srcs:
            for var in _ssa_vars_of_expression(src):
                seeds.append((instr, var))
    return seeds


def _callsite_param_ssa_vars(
    bv: binaryninja.BinaryView, callee_start: int, param_idx: int
) -> List[Tuple[object, binaryninja.MediumLevelILFunction, binaryninja.SSAVariable]]:
    seeds: List[Tuple[object, binaryninja.MediumLevelILFunction, binaryninja.SSAVariable]] = []
    try:
        refs = list(bv.get_code_refs(callee_start))
    except Exception:
        return seeds
    for ref in refs:
        caller = ref.function
        func_ssa = _mlil_ssa_function(caller)
        if func_ssa is None:
            continue
        candidates = []
        try:
            idx = func_ssa.get_instruction_start(ref.address)
            if idx is not None:
                candidates.append(func_ssa[idx])
        except Exception:
            pass
        try:
            for instr in func_ssa.instructions:
                if instr.address == ref.address:
                    candidates.append(instr)
        except Exception:
            pass
        for instr in candidates:
            if not _is_call_expr(instr) or _callee_address(instr) != callee_start:
                continue
            params = _call_params(instr)
            if param_idx >= len(params):
                continue
            for var in _ssa_vars_of_expression(params[param_idx]):
                seeds.append((instr, func_ssa, var))
    return seeds


def _callee_param_ssa_var(callee: binaryninja.Function, param_idx: int):
    try:
        param_var = callee.parameter_vars[param_idx]
    except Exception:
        return None
    func_ssa = _mlil_ssa_function(callee)
    if func_ssa is None:
        return None
    try:
        version = func_ssa.get_ssa_var_version(param_var, 0)
        return binaryninja.SSAVariable(param_var, version)
    except Exception:
        try:
            for var in func_ssa.vars:
                if _is_ssa_var(var) and var.var == param_var:
                    return var
        except Exception:
            pass
    try:
        return binaryninja.SSAVariable(param_var, 0)
    except Exception:
        return None
    return None


def _selected_call_expr():
    expr = _selected_mlil_ssa_expr()
    if _is_call_expr(expr):
        return expr

    try:
        source_func = tanto.helpers.get_current_source_function()
        func_ssa = _mlil_ssa_function(source_func)
        addr = tanto.helpers.get_current_address()
    except Exception:
        func_ssa = None
        addr = None
    if func_ssa is None or addr is None:
        return None

    try:
        idx = func_ssa.get_instruction_start(addr)
        if idx is not None and _is_call_expr(func_ssa[idx]):
            return func_ssa[idx]
    except Exception:
        pass
    try:
        for instr in func_ssa.instructions:
            if instr.address == addr and _is_call_expr(instr):
                return instr
    except Exception:
        pass
    return None


def _copy_text_to_clipboard(text: str) -> bool:
    try:
        from PySide6.QtWidgets import QApplication
        clipboard = QApplication.clipboard()
        if clipboard is None:
            return False
        clipboard.setText(text)
        return True
    except Exception:
        return False


def _summary_expr_text(expr) -> str:
    try:
        text = str(expr).replace("\n", " ")
    except Exception:
        text = _operation_name(expr)
    if len(text) > 140:
        text = text[:137] + "..."
    return f"{getattr(expr, 'address', 0):#x}: {text}"


def _backward_summary_lines(func_ssa, seed_vars, max_lines: int = 32) -> List[str]:
    lines: List[str] = []
    queue = deque((func_ssa, var, 0) for var in seed_vars)
    visited: Set[Tuple[int, str]] = set()
    while queue and len(lines) < max_lines:
        cur_func_ssa, var, depth = queue.popleft()
        if not _is_ssa_var(var):
            continue
        key = _var_key(cur_func_ssa, var)
        if key in visited:
            continue
        visited.add(key)
        indent = "  " * min(depth, 6)
        try:
            defn = cur_func_ssa.get_ssa_var_definition(var)
        except Exception:
            defn = None
        if defn is None:
            lines.append(f"{indent}{_ssa_var_name(var)} <- PARAM boundary in {_function_label(cur_func_ssa.source_function)}")
            continue

        copy_src = _trivial_copy_source(defn)
        if copy_src is not None:
            lines.append(f"{indent}{_ssa_var_name(var)} <- {_ssa_var_name(copy_src)}")
            queue.append((cur_func_ssa, copy_src, depth + 1))
            continue

        role = _expr_role(defn, "def")
        lines.append(f"{indent}{_ssa_var_name(var)} <- {role}: {_summary_expr_text(defn)}")
        for src_var in _ssa_vars_of_expression(defn)[:_ssa_setting("fanout")]:
            queue.append((cur_func_ssa, src_var, depth + 1))
    if queue:
        lines.append("... summary truncated")
    return lines


class SSADataflowSliceBase(Slice):
    """Bidirectional MLIL SSA def-use graph seeded from the selected expression/variable."""

    interprocedural = False
    direction = "both"
    stop_at_parameters = False

    def __init__(self, parent):
        self.parent = parent
        self.bv = getattr(parent, "bv", None)
        self.update_style = UpdateStyle.ON_NAVIGATE
        self.navigation_style = tanto.slices.NavigationStyle.ABSOLUTE_ADDRESS
        self.pinned_seed = None
        self.pinned_seed_vars = None
        self.pinned_seed_label = None
        self.pinned_func = None
        try:
            parent.register_for_variable(
                "Set SSA Dataflow Seed",
                self.set_seed_variable,
                menu_group="DataflowGroup0",
                menu_order=0,
            )
            parent.register_for_binary_view(
                "Clear SSA Dataflow Seed",
                self.clear_seed_variable,
                is_valid=lambda _bv: self.pinned_seed is not None or self.pinned_seed_vars is not None,
                menu_group="DataflowGroup0",
                menu_order=1,
            )
            for arg_idx in range(4):
                parent.register_for_binary_view(
                    f"Seed Selected Call Arg {arg_idx}",
                    lambda _bv, idx=arg_idx: self.set_seed_call_argument(idx),
                    menu_group="DataflowGroup1",
                    menu_order=arg_idx,
                )
            parent.register_for_binary_view(
                "Seed Sink Dest/Buffer",
                lambda _bv: self.set_seed_call_role(("dest",)),
                menu_group="DataflowGroup2",
                menu_order=0,
            )
            parent.register_for_binary_view(
                "Seed Sink Source",
                lambda _bv: self.set_seed_call_role(("src",)),
                menu_group="DataflowGroup2",
                menu_order=1,
            )
            parent.register_for_binary_view(
                "Seed Sink Size/Count",
                lambda _bv: self.set_seed_call_role(("size", "count")),
                menu_group="DataflowGroup2",
                menu_order=2,
            )
            parent.register_for_binary_view(
                "Copy SSA Slice Summary",
                lambda _bv: self.copy_slice_summary(),
                menu_group="DataflowGroup3",
                menu_order=0,
            )
        except Exception:
            pass

    def get_il_view_type(self):
        return binaryninja.FunctionViewType(FunctionGraphType.MediumLevelILSSAFormFunctionGraph)

    def set_seed_variable(self, _bv, var):
        try:
            self.pinned_func = tanto.helpers.get_current_source_function()
        except Exception:
            self.pinned_func = None
        self.pinned_seed = var
        self.pinned_seed_vars = None
        self.pinned_seed_label = "pinned variable"
        try:
            self.parent.flowgraph_widget.setGraph(self.get_flowgraph())
        except Exception:
            pass

    def set_seed_call_argument(self, arg_idx: int, role_label: Optional[str] = None):
        call_expr = _selected_call_expr()
        if call_expr is None:
            log_error("No selected/current MLIL SSA call found for SSA dataflow seed")
            return
        params = _call_params(call_expr)
        if arg_idx >= len(params):
            log_error(f"Selected call has no argument {arg_idx}")
            return
        seed_vars = _ssa_vars_of_expression(params[arg_idx])
        if not seed_vars:
            log_error(f"Argument {arg_idx} has no SSA variables to seed")
            return
        try:
            self.pinned_func = call_expr.function.source_function
        except Exception:
            self.pinned_func = None
        self.pinned_seed = None
        self.pinned_seed_vars = seed_vars
        call_name = _callee_name(call_expr, self.bv) or "call"
        role_text = f" ({role_label})" if role_label else ""
        self.pinned_seed_label = f"pinned call argument {arg_idx}{role_text}: {call_name} @ {call_expr.address:#x}"
        try:
            self.parent.flowgraph_widget.setGraph(self.get_flowgraph())
        except Exception:
            pass

    def set_seed_call_role(self, role_names):
        call_expr = _selected_call_expr()
        if call_expr is None:
            log_error("No selected/current MLIL SSA call found for SSA dataflow seed")
            return
        arg_idx = _known_call_arg_index(call_expr, self.bv, role_names)
        if arg_idx is None:
            call_name = _callee_name(call_expr, self.bv)
            roles = ", ".join(role_names)
            log_error(f"No known {roles} argument mapping for call {call_name or '<unknown>'}")
            return
        self.set_seed_call_argument(arg_idx, "/".join(role_names))

    def clear_seed_variable(self, _bv=None):
        self.pinned_seed = None
        self.pinned_seed_vars = None
        self.pinned_seed_label = None
        self.pinned_func = None
        try:
            self.parent.flowgraph_widget.setGraph(self.get_flowgraph())
        except Exception:
            pass

    def copy_slice_summary(self):
        func_ssa, seed_vars, seed_source = self._seed_vars()
        if func_ssa is None or not seed_vars:
            log_error("No SSA dataflow seed available for summary")
            return

        title = f"SSA slice summary ({seed_source})"
        lines = [title, f"function: {_function_label(func_ssa.source_function)}"]
        try:
            call_expr = _selected_call_expr()
            if call_expr is not None:
                lines.append(f"selected call: {_callee_name(call_expr, self.bv) or '<unknown>'} at {call_expr.address:#x}")
        except Exception:
            pass
        lines.append("seeds: " + ", ".join(_ssa_var_name(var) for var in seed_vars))
        lines.extend(_backward_summary_lines(func_ssa, seed_vars))
        text = "\n".join(lines)
        copied = _copy_text_to_clipboard(text)
        if copied:
            log_info("[SSA dataflow] copied slice summary to clipboard:\n" + text)
        else:
            log_info("[SSA dataflow] slice summary:\n" + text)

    def _seed_vars(self) -> Tuple[Optional[binaryninja.MediumLevelILFunction], List[binaryninja.SSAVariable], str]:
        if self.pinned_seed_vars is not None and self.pinned_func is not None:
            func_ssa = _mlil_ssa_function(self.pinned_func)
            if func_ssa is not None:
                return func_ssa, list(self.pinned_seed_vars), self.pinned_seed_label or "pinned call argument"

        if self.pinned_seed is not None and self.pinned_func is not None:
            func_ssa = _mlil_ssa_function(self.pinned_func)
            if func_ssa is not None:
                if _is_ssa_var(self.pinned_seed):
                    return func_ssa, [self.pinned_seed], self.pinned_seed_label or "pinned variable"
                try:
                    version = func_ssa.get_ssa_var_version(self.pinned_seed, 0)
                    return func_ssa, [binaryninja.SSAVariable(self.pinned_seed, version)], self.pinned_seed_label or "pinned variable"
                except Exception:
                    pass

        token_func_ssa, token_var = _selected_ssa_var_from_token()
        if token_func_ssa is not None and token_var is not None:
            if _is_ssa_var(token_var):
                return token_func_ssa, [token_var], "selected variable token"
            try:
                version = token_func_ssa.get_ssa_var_version(token_var, 0)
                return token_func_ssa, [binaryninja.SSAVariable(token_var, version)], "selected variable token"
            except Exception:
                pass

        expr = _selected_mlil_ssa_expr()
        if expr is None:
            return None, [], "selected expression"
        func_ssa = expr.function
        return func_ssa, _ssa_vars_of_expression(expr), "selected expression"

    def _make_graph_builder(self, flowgraph: FlowGraph):
        var_nodes: Dict[Tuple[int, str], FlowGraphNode] = {}
        expr_nodes: Dict[Tuple[int, int, str], FlowGraphNode] = {}
        terminal_nodes: Dict[Tuple[int, str, str], FlowGraphNode] = {}

        def var_node(func_ssa, var):
            key = _var_key(func_ssa, var)
            node = var_nodes.get(key)
            if node is None:
                node = FlowGraphNode(flowgraph)
                func = func_ssa.source_function
                var_role = "VAR"
                try:
                    if func_ssa.get_ssa_var_definition(var) is None:
                        var_role = "PARAM"
                except Exception:
                    pass
                node.lines = [
                    _text_line(f"{var_role} {_ssa_var_name(var)}", func.start),
                    _text_line(_function_label(func), func.start),
                ]
                node.highlight = _highlight_for_role(var_role)
                flowgraph.append(node)
                var_nodes[key] = node
            return node

        def expr_node(expr, role):
            role = _expr_role(expr, role)
            key = (_expr_key(expr)[0], _expr_key(expr)[1], role)
            node = expr_nodes.get(key)
            if node is None:
                node = FlowGraphNode(flowgraph)
                addr = getattr(expr, "address", 0)
                node.lines = [
                    _text_line(_expr_label(expr, role), addr),
                    _text_line(_operation_name(expr), addr),
                ]
                node.highlight = _highlight_for_role(role)
                flowgraph.append(node)
                expr_nodes[key] = node
            return node

        def terminal_node(func_ssa, title, detail=""):
            key = (func_ssa.source_function.start, title, detail)
            node = terminal_nodes.get(key)
            if node is None:
                node = FlowGraphNode(flowgraph)
                addr = func_ssa.source_function.start
                lines = [_text_line(title, addr)]
                if detail:
                    lines.append(_text_line(detail, addr))
                node.lines = lines
                node.highlight = _highlight_for_role(title)
                flowgraph.append(node)
                terminal_nodes[key] = node
            return node

        return var_node, expr_node, terminal_node, var_nodes, expr_nodes, terminal_nodes

    def _follow_backward(self, flowgraph, func_ssa, seed_vars, var_node, expr_node, terminal_node) -> int:
        queue = deque((func_ssa, var, 0, 0) for var in seed_vars)
        visited: Set[Tuple[int, str, str]] = set()
        edges = 0
        max_nodes = _ssa_setting("max_nodes")
        depth_cap = _ssa_setting("depth_cap")
        ipc_hops = _ssa_setting("ipc_hops")
        fanout = _ssa_setting("fanout")
        while queue and len(visited) < max_nodes:
            cur_func_ssa, var, depth, hops = queue.popleft()
            if depth > depth_cap or not _is_ssa_var(var):
                continue
            visit_key = (*_var_key(cur_func_ssa, var), "back")
            if visit_key in visited:
                continue
            visited.add(visit_key)
            sink_node = var_node(cur_func_ssa, var)
            try:
                defn = cur_func_ssa.get_ssa_var_definition(var)
            except Exception:
                defn = None

            if defn is None:
                if self.stop_at_parameters:
                    terminal_node(
                        cur_func_ssa,
                        "PARAM BOUNDARY",
                        f"stopped at {_ssa_var_name(var)}",
                    ).add_outgoing_edge(BranchType.FalseBranch, sink_node)
                    edges += 1
                    continue
                if self.interprocedural and hops < ipc_hops and self.bv is not None:
                    param_idx = _param_index_of(cur_func_ssa.source_function, var)
                    if param_idx is not None:
                        caller_seeds = _callsite_param_ssa_vars(self.bv, cur_func_ssa.source_function.start, param_idx)[:fanout]
                        for call_instr, caller_ssa, caller_var in caller_seeds:
                            call_node = expr_node(call_instr, f"arg->param{param_idx}")
                            var_node(caller_ssa, caller_var).add_outgoing_edge(BranchType.TrueBranch, call_node)
                            call_node.add_outgoing_edge(BranchType.TrueBranch, sink_node)
                            queue.append((caller_ssa, caller_var, depth + 1, hops + 1))
                            edges += 1
                        if not caller_seeds:
                            terminal_node(
                                cur_func_ssa,
                                "UNRESOLVED PARAM SOURCE",
                                f"no callers found for param {param_idx}",
                            ).add_outgoing_edge(BranchType.FalseBranch, sink_node)
                            edges += 1
                else:
                    terminal_node(
                        cur_func_ssa,
                        "PARAM SOURCE",
                        f"{_ssa_var_name(var)} has no local SSA definition",
                    ).add_outgoing_edge(BranchType.FalseBranch, sink_node)
                    edges += 1
                continue

            copy_src = _trivial_copy_source(defn)
            if copy_src is not None:
                var_node(cur_func_ssa, copy_src).add_outgoing_edge(BranchType.UnconditionalBranch, sink_node)
                queue.append((cur_func_ssa, copy_src, depth + 1, hops))
                edges += 1
                continue

            def_node = expr_node(defn, "def")
            def_node.add_outgoing_edge(BranchType.UnconditionalBranch, sink_node)
            edges += 1

            if self.interprocedural and _is_call_expr(defn) and hops < ipc_hops and self.bv is not None:
                callee_addr = _callee_address(defn)
                callee = self.bv.get_function_at(callee_addr) if callee_addr is not None else None
                callee_ssa = _mlil_ssa_function(callee)
                if callee_ssa is not None:
                    for ret_instr, ret_var in _return_value_vars(callee_ssa)[:fanout]:
                        ret_node = expr_node(ret_instr, "ret->call")
                        var_node(callee_ssa, ret_var).add_outgoing_edge(BranchType.TrueBranch, ret_node)
                        ret_node.add_outgoing_edge(BranchType.TrueBranch, def_node)
                        queue.append((callee_ssa, ret_var, depth + 1, hops + 1))
                        edges += 1
                elif callee_addr is None:
                    terminal_node(
                        cur_func_ssa,
                        "UNRESOLVED INDIRECT CALL",
                        f"call at {getattr(defn, 'address', 0):#x}",
                    ).add_outgoing_edge(BranchType.FalseBranch, def_node)
                    edges += 1
                else:
                    terminal_node(
                        cur_func_ssa,
                        "UNRESOLVED CALLEE",
                        f"no function at {callee_addr:#x}",
                    ).add_outgoing_edge(BranchType.FalseBranch, def_node)
                    edges += 1

            inputs = _ssa_vars_of_expression(defn)[:fanout]
            if not inputs:
                try:
                    op_name = defn.operation.name
                except Exception:
                    op_name = ""
                if "LOAD" in op_name or "MEM" in op_name:
                    title = "MEMORY SOURCE"
                elif _is_call_expr(defn):
                    title = "CALL SOURCE"
                else:
                    title = "SSA SOURCE"
                terminal_node(
                    cur_func_ssa,
                    title,
                    f"no SSA inputs at {getattr(defn, 'address', 0):#x}",
                ).add_outgoing_edge(BranchType.FalseBranch, def_node)
                edges += 1
            for src_var in inputs:
                var_node(cur_func_ssa, src_var).add_outgoing_edge(BranchType.UnconditionalBranch, def_node)
                queue.append((cur_func_ssa, src_var, depth + 1, hops))
                edges += 1
        return edges

    def _follow_forward(self, flowgraph, func_ssa, seed_vars, var_node, expr_node) -> int:
        queue = deque((func_ssa, var, 0, 0) for var in seed_vars)
        visited: Set[Tuple[int, str, str]] = set()
        edges = 0
        max_nodes = _ssa_setting("max_nodes")
        depth_cap = _ssa_setting("depth_cap")
        ipc_hops = _ssa_setting("ipc_hops")
        fanout = _ssa_setting("fanout")
        while queue and len(visited) < max_nodes:
            cur_func_ssa, var, depth, hops = queue.popleft()
            if depth > depth_cap or not _is_ssa_var(var):
                continue
            visit_key = (*_var_key(cur_func_ssa, var), "fwd")
            if visit_key in visited:
                continue
            visited.add(visit_key)
            source_node = var_node(cur_func_ssa, var)
            try:
                uses = list(cur_func_ssa.get_ssa_var_uses(var))[:fanout]
            except Exception:
                uses = []
            for use in uses:
                use_node = expr_node(use, "use")
                source_node.add_outgoing_edge(BranchType.UnconditionalBranch, use_node)
                edges += 1

                if self.interprocedural and _is_call_expr(use) and hops < ipc_hops and self.bv is not None:
                    callee_addr = _callee_address(use)
                    callee = self.bv.get_function_at(callee_addr) if callee_addr is not None else None
                    callee_ssa = _mlil_ssa_function(callee)
                    params = _call_params(use)
                    if callee is not None and callee_ssa is not None:
                        for param_idx, param_expr in enumerate(params):
                            if var not in _ssa_vars_of_expression(param_expr):
                                continue
                            callee_var = _callee_param_ssa_var(callee, param_idx)
                            if callee_var is None:
                                continue
                            param_node = expr_node(use, f"arg->param{param_idx}")
                            use_node.add_outgoing_edge(BranchType.TrueBranch, param_node)
                            param_node.add_outgoing_edge(BranchType.TrueBranch, var_node(callee_ssa, callee_var))
                            queue.append((callee_ssa, callee_var, depth + 1, hops + 1))
                            edges += 1

                outputs = _call_output_vars(use) if _is_call_expr(use) else _ssa_vars_written_by_expression(use)
                outputs = outputs[:fanout]
                if not outputs:
                    continue
                for out_var in outputs:
                    if out_var == var:
                        continue
                    use_node.add_outgoing_edge(BranchType.UnconditionalBranch, var_node(cur_func_ssa, out_var))
                    queue.append((cur_func_ssa, out_var, depth + 1, hops))
                    edges += 1
        return edges

    def get_flowgraph(self) -> FlowGraph:
        flowgraph = FlowGraph()
        func_ssa, seed_vars, seed_source = self._seed_vars()
        if func_ssa is None:
            _append_text_node(flowgraph, "No MLIL SSA expression selected", "Select an expression or right-click an SSA variable and set it as the seed.")
            return flowgraph
        if not seed_vars:
            _append_text_node(flowgraph, "No SSA variables found", f"Seed source: {seed_source}")
            return flowgraph

        try:
            flowgraph.function = func_ssa.source_function
            flowgraph.il_function = func_ssa
        except Exception:
            pass

        var_node, expr_node, terminal_node, var_nodes, expr_nodes, terminal_nodes = self._make_graph_builder(flowgraph)
        for seed_var in seed_vars:
            seed_node = var_node(func_ssa, seed_var)
            seed_node.lines = [
                _text_line(f"SEED {_ssa_var_name(seed_var)}", func_ssa.source_function.start),
                _text_line(f"{seed_source}: {_function_label(func_ssa.source_function)}", func_ssa.source_function.start),
            ]
            seed_node.highlight = _highlight_for_role("SEED")

        edge_count = 0
        if self.direction in ("backward", "both"):
            edge_count += self._follow_backward(flowgraph, func_ssa, seed_vars, var_node, expr_node, terminal_node)
        if self.direction in ("forward", "both"):
            edge_count += self._follow_forward(flowgraph, func_ssa, seed_vars, var_node, expr_node)

        if edge_count == 0:
            _append_text_node(flowgraph, "No SSA def-use edges found", "The selected value may be a constant, unresolved memory value, or isolated variable.")
        max_nodes = _ssa_setting("max_nodes")
        if len(var_nodes) + len(expr_nodes) + len(terminal_nodes) >= max_nodes:
            _append_text_node(flowgraph, "SSA slice truncated", f"Node cap reached: {max_nodes}")
        return flowgraph


class IntraproceduralSSABackwardSlice(SSADataflowSliceBase):
    """Current-function backward MLIL SSA slice."""

    interprocedural = False
    direction = "backward"


class IntraproceduralSSAForwardSlice(SSADataflowSliceBase):
    """Current-function forward MLIL SSA use slice."""

    interprocedural = False
    direction = "forward"


class IntraproceduralSSABidirectionalSlice(SSADataflowSliceBase):
    """Current-function bidirectional MLIL SSA def-use slice."""

    interprocedural = False
    direction = "both"


class InterproceduralSSABackwardSlice(SSADataflowSliceBase):
    """Bounded backward MLIL SSA slice across direct calls."""

    interprocedural = True
    direction = "backward"


class BoundarySSABackwardSlice(SSADataflowSliceBase):
    """Backward MLIL SSA slice that stops at function parameters."""

    interprocedural = True
    direction = "backward"
    stop_at_parameters = True


class InterproceduralSSAForwardSlice(SSADataflowSliceBase):
    """Bounded forward MLIL SSA use slice across direct calls."""

    interprocedural = True
    direction = "forward"


class InterproceduralSSABidirectionalSlice(SSADataflowSliceBase):
    """Bounded bidirectional MLIL SSA def-use slice across direct calls."""

    interprocedural = True
    direction = "both"


# Register all slice types with Tanto
def register_slices():
    # Register only the unique views that don't conflict with Tanto's built-in views
    TantoView.register_slice_type("Iterated Dominance Frontier", IteratedDominanceFrontierSlice)
    TantoView.register_slice_type("Immediate Dominator", ImmediateDominatorSlice)
    TantoView.register_slice_type("Strict Dominators", StrictDominatorsSlice)
    TantoView.register_slice_type("Full Dominator Tree", FullDominatorTreeSlice)
    TantoView.register_slice_type("Immediate Post Dominator", ImmediatePostDominatorSlice)
    TantoView.register_slice_type("Full Post Dominator Tree", FullPostDominatorTreeSlice)
    TantoView.register_slice_type("SSA Backward Slice (Intra)", IntraproceduralSSABackwardSlice)
    TantoView.register_slice_type("SSA Forward Slice (Intra)", IntraproceduralSSAForwardSlice)
    TantoView.register_slice_type("SSA Def-Use Slice (Intra)", IntraproceduralSSABidirectionalSlice)
    TantoView.register_slice_type("SSA Backward Slice (Boundary)", BoundarySSABackwardSlice)
    TantoView.register_slice_type("SSA Backward Slice (Inter)", InterproceduralSSABackwardSlice)
    TantoView.register_slice_type("SSA Forward Slice (Inter)", InterproceduralSSAForwardSlice)
    TantoView.register_slice_type("SSA Def-Use Slice (Inter)", InterproceduralSSABidirectionalSlice)


# We'll register the slices in a background task to ensure Tanto is properly initialized
class RegisterSlicesTask(BackgroundTaskThread):
    def __init__(self):
        BackgroundTaskThread.__init__(self, "Registering Dominator Analysis Slices", True)
    
    def run(self):
        # Tanto may still be initializing when this plugin loads. Retry the
        # registration with a short bounded backoff instead of guessing a
        # fixed sleep, and fail loudly only after exhausting the attempts.
        import time
        last_error = None
        for attempt in range(20):  # ~5s worst case at 0.25s steps
            try:
                register_slices()
                log_info("Dominator Analysis slices registered successfully")
                return
            except Exception as e:
                last_error = e
                time.sleep(0.25)
        log_error(f"Failed to register Dominator Analysis slices after retries: {last_error}")


# Register slices when this plugin is loaded, but do it in a background task
# to avoid the initialization issue
RegisterSlicesTask().start()


# Add utility functions for generating Mermaid diagrams for various dominator relationships
def generate_post_dominator_mermaid(bv, function_address):
    """
    Generate a Mermaid diagram of the post dominator tree for a given function
    
    :param bv: Binary view
    :param function_address: Address of the function
    :return: Mermaid diagram string
    """
    func = bv.get_function_at(function_address)
    mermaid_syntax = "graph TD;\n"
    
    if func is not None:
        for bb in func.basic_blocks:
            mermaid_syntax += f"BB{hex(bb.start)}(({hex(bb.start)}))\n"
            for frontier in bb.post_dominator_tree_children:
                mermaid_syntax += f"BB{hex(bb.start)} --> BB{hex(frontier.start)}\n"
    else:
        mermaid_syntax = f"No function found at address {hex(function_address)}"
    
    return "```mermaid\n" + mermaid_syntax + "\n```"


def generate_dominator_mermaid(bv, function_address):
    """
    Generate a Mermaid diagram of the dominator tree for a given function
    
    :param bv: Binary view
    :param function_address: Address of the function
    :return: Mermaid diagram string
    """
    func = bv.get_function_at(function_address)
    mermaid_syntax = "graph TD;\n"
    
    if func is not None:
        for bb in func.basic_blocks:
            mermaid_syntax += f"BB{hex(bb.start)}(({hex(bb.start)}))\n"
            for frontier in bb.dominator_tree_children:
                mermaid_syntax += f"BB{hex(bb.start)} --> BB{hex(frontier.start)}\n"
    else:
        mermaid_syntax = f"No function found at address {hex(function_address)}"
    
    return "```mermaid\n" + mermaid_syntax + "\n```"


def generate_dominance_frontier_mermaid(bv, function_address):
    """
    Generate a Mermaid diagram of the dominance frontier for each block in a function
    
    :param bv: Binary view
    :param function_address: Address of the function
    :return: Mermaid diagram string
    """
    func = bv.get_function_at(function_address)
    mermaid_syntax = "graph TD;\n"
    
    if func is not None:
        # Add all blocks first
        for bb in func.basic_blocks:
            mermaid_syntax += f"BB{hex(bb.start)}(({hex(bb.start)}))\n"
        
        # Add dominance frontier edges with a different style
        for bb in func.basic_blocks:
            for frontier in bb.dominance_frontier:
                mermaid_syntax += f"BB{hex(bb.start)} -->|frontier| BB{hex(frontier.start)}\n"
    else:
        mermaid_syntax = f"No function found at address {hex(function_address)}"
    
    return "```mermaid\n" + mermaid_syntax + "\n```"


def generate_post_dominance_frontier_mermaid(bv, function_address):
    """
    Generate a Mermaid diagram of the post dominance frontier for each block in a function
    
    :param bv: Binary view
    :param function_address: Address of the function
    :return: Mermaid diagram string
    """
    func = bv.get_function_at(function_address)
    mermaid_syntax = "graph TD;\n"
    
    if func is not None:
        # Add all blocks first
        for bb in func.basic_blocks:
            mermaid_syntax += f"BB{hex(bb.start)}(({hex(bb.start)}))\n"
        
        # Add post dominance frontier edges with a different style
        for bb in func.basic_blocks:
            for frontier in bb.post_dominance_frontier:
                mermaid_syntax += f"BB{hex(bb.start)} -->|post frontier| BB{hex(frontier.start)}\n"
    else:
        mermaid_syntax = f"No function found at address {hex(function_address)}"
    
    return "```mermaid\n" + mermaid_syntax + "\n```"


def generate_iterated_dominance_frontier_mermaid(bv, function_address, variable_blocks=None):
    """
    Generate a Mermaid diagram of the iterated dominance frontier for specific blocks in a function
    
    :param bv: Binary view
    :param function_address: Address of the function
    :param variable_blocks: List of block addresses where a variable is defined (if None, uses first block)
    :return: Mermaid diagram string
    """
    func = bv.get_function_at(function_address)
    mermaid_syntax = "graph TD;\n"
    
    if func is not None:
        # Add all blocks first
        for bb in func.basic_blocks:
            mermaid_syntax += f"BB{hex(bb.start)}(({hex(bb.start)}))\n"
        
        # If no variable blocks specified, use the first block
        if variable_blocks is None and len(func.basic_blocks) > 0:
            variable_blocks = [func.basic_blocks[0].start]
        
        if variable_blocks:
            # Calculate iterated dominance frontier
            blocks = set()
            for addr in variable_blocks:
                for bb in func.basic_blocks:
                    if bb.start == addr:
                        blocks.add(bb)
                        break
            
            frontier = set()
            worklist = list(blocks)
            
            while worklist:
                block = worklist.pop(0)
                for df_block in block.dominance_frontier:
                    if df_block not in frontier:
                        frontier.add(df_block)
                        worklist.append(df_block)
            
            # Style the variable definition blocks
            for block in blocks:
                mermaid_syntax += f"style BB{hex(block.start)} fill:#afa,stroke:#6a6\n"
            
            # Style the frontier blocks and add edges
            for block in blocks:
                for frontier_block in frontier:
                    mermaid_syntax += f"BB{hex(block.start)} -->|IDF| BB{hex(frontier_block.start)}\n"
                    mermaid_syntax += f"style BB{hex(frontier_block.start)} fill:#faa,stroke:#a66\n"
    else:
        mermaid_syntax = f"No function found at address {hex(function_address)}"
    
    return "```mermaid\n" + mermaid_syntax + "\n```"


def generate_immediate_dominator_mermaid(bv, function_address):
    """
    Generate a Mermaid diagram showing immediate dominator relationships for all blocks
    
    :param bv: Binary view
    :param function_address: Address of the function
    :return: Mermaid diagram string
    """
    func = bv.get_function_at(function_address)
    mermaid_syntax = "graph TD;\n"
    
    if func is not None:
        # Add all blocks first
        for bb in func.basic_blocks:
            mermaid_syntax += f"BB{hex(bb.start)}(({hex(bb.start)}))\n"
        
        # Add immediate dominator edges
        for bb in func.basic_blocks:
            if bb.immediate_dominator is not None and bb.immediate_dominator != bb:
                mermaid_syntax += f"BB{hex(bb.immediate_dominator.start)} -->|idom| BB{hex(bb.start)}\n"
    else:
        mermaid_syntax = f"No function found at address {hex(function_address)}"
    
    return "```mermaid\n" + mermaid_syntax + "\n```"


def generate_immediate_post_dominator_mermaid(bv, function_address):
    """
    Generate a Mermaid diagram showing immediate post dominator relationships for all blocks
    
    :param bv: Binary view
    :param function_address: Address of the function
    :return: Mermaid diagram string
    """
    func = bv.get_function_at(function_address)
    mermaid_syntax = "graph TD;\n"
    
    if func is not None:
        # Add all blocks first
        for bb in func.basic_blocks:
            mermaid_syntax += f"BB{hex(bb.start)}(({hex(bb.start)}))\n"
        
        # Add immediate post dominator edges
        for bb in func.basic_blocks:
            if bb.immediate_post_dominator is not None and bb.immediate_post_dominator != bb:
                mermaid_syntax += f"BB{hex(bb.start)} -->|ipdom| BB{hex(bb.immediate_post_dominator.start)}\n"
    else:
        mermaid_syntax = f"No function found at address {hex(function_address)}"
    
    return "```mermaid\n" + mermaid_syntax + "\n```"
