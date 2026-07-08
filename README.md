# Dominator Analysis and SSA Dataflow Slices for Binary Ninja

This plugin extends the [Tanto](https://github.com/Vector35/tanto) graph
visualization plugin for Binary Ninja with:

- Dominator and post-dominator tree views.
- MLIL SSA def-use dataflow slices.
- Sink-aware call argument slicing for common vulnerability review workflows.

The SSA slices are especially useful for answering questions like:

```text
Where did this memcpy size argument come from?
Where does this return value flow?
Is this pointer directly parameter-controlled?
```

## Features

### Dominator Views

The plugin adds these Tanto slice types:

1. **Iterated Dominance Frontier** - Shows the iterated dominance frontier, useful for phi-node placement.
2. **Immediate Dominator** - Shows the immediate dominator of the current block.
3. **Strict Dominators** - Shows all dominators except the current block.
4. **Full Dominator Tree** - Displays the full dominator tree for the current function.
5. **Immediate Post Dominator** - Shows the immediate post-dominator of the current block.
6. **Full Post Dominator Tree** - Displays the full post-dominator tree for the current function.

### SSA Dataflow Views

The plugin also adds MLIL SSA dataflow slice types:

1. **SSA Backward Slice (Intra)** - Current-function provenance: definitions feeding the selected SSA value.
2. **SSA Forward Slice (Intra)** - Current-function uses: where the selected SSA value flows.
3. **SSA Def-Use Slice (Intra)** - Current-function bidirectional def-use graph.
4. **SSA Backward Slice (Boundary)** - Backward provenance that stops at function parameters. This is usually the best first view for sink argument review.
5. **SSA Backward Slice (Inter)** - Backward provenance with bounded caller/callee traversal.
6. **SSA Forward Slice (Inter)** - Forward uses with bounded caller/callee traversal.
7. **SSA Def-Use Slice (Inter)** - Bidirectional interprocedural graph.

The slices seed from the selected SSA variable or expression. If selection is ambiguous, use the right-click seed actions described below.

## Common Workflow: memcpy Size Review

For a call like:

```c
memcpy(dest, src, size)
```

Use:

1. Open a **Tanto** view.
2. Select **SSA Backward Slice (Boundary)**.
3. Put the cursor on the `memcpy(...)` call.
4. Right-click in the Tanto view and choose **Seed Sink Size/Count**.

For `memcpy`, this seeds argument 2 and produces a graph like:

```text
PARAM arg1#0
CALL strlen(arg1)
PHI result_1#2
DEF r2_2#3 = result_1#2 + 1
SEED r2_2#3
```

This answers the provenance question without expanding into every caller.

## Right-Click Actions

Each SSA dataflow slice registers these actions in the Tanto context menu:

- **Set SSA Dataflow Seed** - Pin the right-clicked SSA variable as the slice seed.
- **Clear SSA Dataflow Seed** - Return to selection-based seeding.
- **Seed Selected Call Arg 0**
- **Seed Selected Call Arg 1**
- **Seed Selected Call Arg 2**
- **Seed Selected Call Arg 3**
- **Seed Sink Dest/Buffer**
- **Seed Sink Source**
- **Seed Sink Size/Count**
- **Copy SSA Slice Summary**

The sink-aware actions use known argument roles for common APIs such as:

- `memcpy`, `memmove`, `memset`
- `strcpy`, `strncpy`, `strcat`, `strncat`
- `recv`, `recvfrom`, `read`, `fread`
- `malloc`, `calloc`, `realloc`
- `sprintf`, `snprintf`, `vsprintf`, `vsnprintf`

The summary action logs a compact backward provenance summary and attempts to copy it to the system clipboard.

## Node Colors

SSA slice nodes use role-based highlighting:

- **SEED** - green
- **PARAM** - blue
- **CALL** - yellow
- **PHI** - magenta
- **RET** - cyan
- **MEM / parameter boundary/source** - orange
- **Unresolved or warning terminals** - red

Terminal nodes make analysis boundaries explicit, for example:

- `PARAM BOUNDARY`
- `PARAM SOURCE`
- `UNRESOLVED PARAM SOURCE`
- `UNRESOLVED INDIRECT CALL`
- `UNRESOLVED CALLEE`
- `MEMORY SOURCE`
- `CALL SOURCE`
- `SSA SOURCE`

## Settings

SSA slice limits are configurable through Binary Ninja settings:

| Setting | Default | Meaning |
| --- | ---: | --- |
| `dominator_plugin.ssa.depth_cap` | `48` | Maximum SSA def-use traversal depth. |
| `dominator_plugin.ssa.ipc_hops` | `2` | Maximum interprocedural caller/callee hops. |
| `dominator_plugin.ssa.max_nodes` | `240` | Approximate graph node budget. |
| `dominator_plugin.ssa.fanout` | `64` | Maximum uses/callers/callees explored from one node. |

The settings are read when the slice graph is rebuilt, so changing them should affect the next refresh or reseed.

## Installation

1. Ensure you have the [Tanto plugin](https://github.com/Vector35/tanto) installed
2. Place the `dominator_plugin.py` file in your Binary Ninja plugins directory:
   - Windows: `%APPDATA%\Binary Ninja\plugins`
   - Linux: `~/.binaryninja/plugins`
   - MacOS: `~/Library/Application Support/Binary Ninja/plugins`
3. Restart Binary Ninja or reload plugins

**Important Note:** If you encounter any initialization errors, try the following:
1. Make sure Binary Ninja is fully loaded before using the plugin
2. Open a Tanto view first and then switch to one of the custom views
3. If errors persist, try restarting Binary Ninja

## Usage

1. Open a binary in Binary Ninja.
2. Navigate to a function.
3. Open the Tanto view.
4. Select one of the added slice types from the Tanto dropdown.
5. For SSA slices, select an expression/variable or use a right-click seed action.

## Mermaid Diagram Generation

The plugin includes several utility functions to generate Mermaid diagrams for different dominator relationships. You can use these from the Binary Ninja Python console:

```python
from dominator_plugin import generate_dominator_mermaid, generate_post_dominator_mermaid

# Generate dominator tree diagram
dominator_diagram = generate_dominator_mermaid(bv, function_address)  # Replace with your function address
print(dominator_diagram)

# Generate post-dominator tree diagram
post_dom_diagram = generate_post_dominator_mermaid(bv, function_address)
print(post_dom_diagram)
```

### Available Mermaid Generator Functions:

1. `generate_dominator_mermaid(bv, function_address)` - Dominator tree
2. `generate_post_dominator_mermaid(bv, function_address)` - Post-dominator tree
3. `generate_dominance_frontier_mermaid(bv, function_address)` - Dominance frontier
4. `generate_post_dominance_frontier_mermaid(bv, function_address)` - Post-dominance frontier
5. `generate_immediate_dominator_mermaid(bv, function_address)` - Immediate dominator relationships
6. `generate_immediate_post_dominator_mermaid(bv, function_address)` - Immediate post-dominator relationships
7. `generate_iterated_dominance_frontier_mermaid(bv, function_address, variable_blocks=None)` - Iterated dominance frontier

These diagrams can be useful for understanding control flow, planning SSA transformations, and visualizing the structure of complex functions.

## What Are Dominators and Post-Dominators?

- A block A **dominates** block B if all paths from the function entry to B must go through A.
- A block A **post-dominates** block B if all paths from B to the function exit must go through A.
- The **dominance frontier** of a block A is the set of blocks that are not dominated by A but have predecessors that are dominated by A.
- The **post-dominance frontier** of a block A is the set of blocks that are not post-dominated by A but have successors that are post-dominated by A.
- The **iterated dominance frontier** is used for determining where to place phi nodes in SSA form.

These relationships are useful for understanding control flow, identifying loops and conditional structures, and performing program analysis tasks like variable liveness analysis.

## SSA Dataflow Caveats

- The SSA slices use MLIL SSA, not full alias analysis.
- Register and scalar SSA flows are usually clear; memory, globals, and unresolved indirect calls are necessarily conservative.
- Interprocedural traversal follows direct calls that Binary Ninja resolves.
- Boundary mode intentionally stops at function parameters to keep sink argument provenance readable.
- Trivial copy assignments are collapsed, but copied variable nodes may still appear where they help preserve graph structure.
