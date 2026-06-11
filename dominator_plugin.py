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
from binaryninja.enums import BranchType


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
            node.lines = [binaryninja.DisassemblyTextLine("No block found", [], 0)]
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
            node.lines = [binaryninja.DisassemblyTextLine("No strict dominators", [], 0)]
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


# Register all slice types with Tanto
def register_slices():
    # Register only the unique views that don't conflict with Tanto's built-in views
    TantoView.register_slice_type("Iterated Dominance Frontier", IteratedDominanceFrontierSlice)
    TantoView.register_slice_type("Immediate Dominator", ImmediateDominatorSlice)
    TantoView.register_slice_type("Strict Dominators", StrictDominatorsSlice)
    TantoView.register_slice_type("Full Dominator Tree", FullDominatorTreeSlice)
    TantoView.register_slice_type("Immediate Post Dominator", ImmediatePostDominatorSlice)
    TantoView.register_slice_type("Full Post Dominator Tree", FullPostDominatorTreeSlice)


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
