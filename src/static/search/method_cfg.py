from __future__ import annotations

from collections import deque
from collections.abc import Iterable
from bisect import bisect_left
from dataclasses import dataclass
from itertools import pairwise
from typing import Any

from src.static.model.values import MethodIR
from src.static.search.dex_ir import destination_register


@dataclass(frozen=True)
class ReachingDefinitions:
    instruction_indices: tuple[int, ...]
    reaches_entry: bool


@dataclass(frozen=True)
class BranchReachability:
    """Structural evidence that a branch may influence sink reachability."""

    branch_instruction_index: int
    sink_reaching_successor_indices: tuple[int, ...]
    sink_bypass_successor_indices: tuple[int, ...]

class MethodCFG:
    """Instruction-level view backed by Androguard DEXBasicBlock edges."""

    def __init__(self, method: MethodIR, method_analysis: Any) -> None:
        self.method = method
        count = len(method.instructions)
        successors: list[set[int]] = [set() for _ in range(count)]
        blocks = list(method_analysis.get_basic_blocks())
        self.basic_block_count = len(blocks)
        self.block_for_instruction: dict[int, int] = {}
        self.block_first: dict[int, int] = {}
        self.block_last: dict[int, int] = {}

        offsets = [instruction.offset for instruction in method.instructions]
        for block_index, block in enumerate(blocks):
            first_index = bisect_left(offsets, block.get_start())
            end_index = bisect_left(offsets, block.get_end(), lo=first_index)
            indices = range(first_index, end_index)
            if not indices:
                continue
            self.block_first[block_index] = first_index
            self.block_last[block_index] = end_index - 1
            for index in indices:
                self.block_for_instruction[index] = block_index
            for left, right in pairwise(indices):
                successors[left].add(right)

        block_index_by_start = {block.get_start(): index for index, block in enumerate(blocks)}
        for block_index, block in enumerate(blocks):
            last = self.block_last.get(block_index)
            if last is None:
                continue
            for _source_offset, _target_offset, child in block.get_next():
                child_index = block_index_by_start.get(child.get_start())
                first = self.block_first.get(child_index) if child_index is not None else None
                if first is not None:
                    successors[last].add(first)

        # Retain straight-line instructions that an unusual/broken block layout
        # did not cover, without reconstructing branch targets ourselves.
        for index in range(count - 1):
            if index not in self.block_for_instruction and not method.instructions[
                index
            ].name.startswith(("return", "throw", "goto")):
                successors[index].add(index + 1)

        predecessors: list[set[int]] = [set() for _ in range(count)]
        for source, targets in enumerate(successors):
            for target in targets:
                predecessors[target].add(source)
        self.successors = tuple(tuple(sorted(item)) for item in successors)
        self.predecessors = tuple(tuple(sorted(item)) for item in predecessors)
        self._reaching_cache: dict[tuple[int, int], ReachingDefinitions] = {}
        self._branch_reachability_cache: dict[
            int, tuple[BranchReachability, ...]
        ] = {}
        self._blocks_reaching_cache: dict[int, frozenset[int]] = {}
        self._blocks_must_reach_cache: dict[int, frozenset[int]] = {}
        self._entry_reachable_cache: frozenset[int] | None = None
        self._dominators_cache: dict[int, frozenset[int]] | None = None
        self._block_successors_cache: dict[int, tuple[int, ...]] | None = None
        self._block_predecessors_cache: dict[int, tuple[int, ...]] | None = None
        self.single_runs = 0
        self.single_cache_hits = 0
        self.batch_runs = 0
        self.batch_queries = 0
        self.batch_cache_hits = 0
        self.batch_node_steps = 0
        self.batch_lane_steps = 0
        self.batch_shared_lane_steps = 0
        self.batch_max_width = 0

    def reaching_definitions(self, register: int, before: int) -> ReachingDefinitions:
        """Use the compact v4-style solver for the overwhelmingly common one-lane case."""

        key = (register, before)
        cached = self._reaching_cache.get(key)
        if cached is not None:
            self.single_cache_hits += 1
            return cached
        self.single_runs += 1
        result = self._reaching_definitions_single(register, before)
        self._reaching_cache[key] = result
        return result

    def _reaching_definitions_single(self, register: int, before: int) -> ReachingDefinitions:
        if before <= 0 or not self.method.instructions:
            return ReachingDefinitions((), True)

        worklist = (
            list(self.predecessors[before])
            if before < len(self.method.instructions)
            else [index for index, targets in enumerate(self.successors) if not targets]
        )
        reaches_entry = not worklist
        definitions: set[int] = set()
        visited: set[int] = set()
        while worklist:
            index = worklist.pop()
            if index in visited:
                continue
            visited.add(index)
            instruction = self.method.instructions[index]
            if destination_register(instruction) == register and not instruction.name.startswith(
                "check-cast"
            ):
                definitions.add(index)
                continue
            previous = self.predecessors[index]
            if not previous:
                reaches_entry = True
            else:
                worklist.extend(previous)
        return ReachingDefinitions(tuple(sorted(definitions)), reaches_entry)

    def reaching_definitions_many(
        self, requests: Iterable[tuple[int, int]]
    ) -> dict[tuple[int, int], ReachingDefinitions]:
        """Solve compatible backward definition queries in one delta propagation.

        A lane is one ``(register, before)`` query.  Lanes that meet at the same
        CFG instruction are carried together; a definition kills only its own
        lane, while the remaining lanes continue to the predecessors.  Cached
        answers remain fact-specific, so batching changes scheduling rather
        than the meaning or budget of an individual trace request.
        """

        ordered = tuple(dict.fromkeys(requests))
        if not ordered:
            return {}

        result: dict[tuple[int, int], ReachingDefinitions] = {}
        pending: list[tuple[int, int]] = []
        for request in ordered:
            cached = self._reaching_cache.get(request)
            if cached is None:
                pending.append(request)
            else:
                self.batch_cache_hits += 1
                result[request] = cached

        if not pending:
            return result

        # Do not pay for per-node lane sets when only one uncached fact remains.
        if len(pending) == 1:
            request = pending[0]
            computed = self.reaching_definitions(*request)
            result[request] = computed
            return {request: result[request] for request in ordered}

        self.batch_runs += 1
        self.batch_queries += len(pending)

        count = len(self.method.instructions)
        definitions = {request: set() for request in pending}
        reaches_entry = {request: False for request in pending}
        scheduled: dict[int, set[tuple[int, int]]] = {}
        worklist: deque[int] = deque()
        queued: set[int] = set()
        seen_at: dict[int, set[tuple[int, int]]] = {}

        def schedule(index: int, lanes: set[tuple[int, int]]) -> None:
            if not lanes:
                return
            bucket = scheduled.setdefault(index, set())
            bucket.update(lanes)
            if index not in queued:
                queued.add(index)
                worklist.append(index)

        for request in pending:
            _register, before = request
            if before <= 0 or count == 0:
                reaches_entry[request] = True
                continue
            starts = (
                self.predecessors[before]
                if before < count
                else tuple(index for index, targets in enumerate(self.successors) if not targets)
            )
            if not starts:
                reaches_entry[request] = True
            for index in starts:
                schedule(index, {request})

        while worklist:
            index = worklist.popleft()
            queued.discard(index)
            incoming = scheduled.pop(index, set())
            visited = seen_at.setdefault(index, set())
            lanes = incoming - visited
            if not lanes:
                continue
            visited.update(lanes)

            width = len(lanes)
            self.batch_node_steps += 1
            self.batch_lane_steps += width
            self.batch_shared_lane_steps += max(0, width - 1)
            self.batch_max_width = max(self.batch_max_width, width)

            instruction = self.method.instructions[index]
            destination = destination_register(instruction)
            live: set[tuple[int, int]] = set()
            for request in lanes:
                register, _before = request
                if destination == register and not instruction.name.startswith("check-cast"):
                    definitions[request].add(index)
                else:
                    live.add(request)

            if not live:
                continue
            previous = self.predecessors[index]
            if not previous:
                for request in live:
                    reaches_entry[request] = True
            else:
                for predecessor in previous:
                    schedule(predecessor, live)

        for request in pending:
            computed = ReachingDefinitions(
                tuple(sorted(definitions[request])), reaches_entry[request]
            )
            self._reaching_cache[request] = computed
            result[request] = computed
        return {request: result[request] for request in ordered}

    def batch_metrics(self) -> dict[str, int]:
        return {
            "single_runs": self.single_runs,
            "single_cache_hits": self.single_cache_hits,
            "batch_runs": self.batch_runs,
            "batch_queries": self.batch_queries,
            "batch_cache_hits": self.batch_cache_hits,
            "batch_node_steps": self.batch_node_steps,
            "batch_lane_steps": self.batch_lane_steps,
            "batch_shared_lane_steps": self.batch_shared_lane_steps,
            "batch_max_width": self.batch_max_width,
        }

    def controlling_branches(self, target_instruction: int) -> tuple[int, ...]:
        return tuple(
            item.branch_instruction_index
            for item in self.controlling_branch_reachability(target_instruction)
        )

    def controlling_branch_reachability(
        self, target_instruction: int
    ) -> tuple[BranchReachability, ...]:
        """Return branches whose outcomes may influence ``target_instruction``.

        An outcome profile records whether the sink is reachable and whether it
        can also be bypassed. At least two outcomes must have different profiles,
        which excludes a branch that merely rejoins before an unrelated sink.
        This structural may-control relation does not recover compound predicates,
        prove an outcome feasible, or establish AND/OR grouping.
        """

        cache = getattr(self, "_branch_reachability_cache", None)
        if cache is None:
            cache = self._branch_reachability_cache = {}
        cached = cache.get(target_instruction)
        if cached is not None:
            return cached

        target_block = self.block_for_instruction.get(target_instruction)
        if target_block is None:
            return ()
        entry_block = self.block_for_instruction.get(0)
        entry_reachable = self._entry_reachable_blocks()
        if entry_block is None or target_block not in entry_reachable:
            return ()
        blocks_reaching_target = self._blocks_reaching(target_block)
        blocks_must_reach_target = self._blocks_must_reach(target_block)
        dominators = self._dominators()
        result: list[BranchReachability] = []
        for last_instruction in self.block_last.values():
            opcode = self.method.instructions[last_instruction].name
            if not opcode.startswith(("if-", "packed-switch", "sparse-switch")):
                continue
            child_entries = {
                self.block_for_instruction[item]: item
                for item in self.successors[last_instruction]
                if item in self.block_for_instruction
            }
            children = set(child_entries)
            if len(children) < 2:
                continue
            branch_block = self.block_for_instruction.get(last_instruction)
            if (
                branch_block is None
                or branch_block not in entry_reachable
                or target_block in dominators.get(branch_block, ())
            ):
                # A loop-back branch reached only after the sink does not
                # control the sink's first execution.
                continue
            profiles = {
                child: (
                    child in blocks_reaching_target,
                    child not in blocks_must_reach_target,
                )
                for child in children
            }
            if len(set(profiles.values())) < 2:
                # Both outcomes have the same may-reach/may-bypass behavior,
                # as when they merge before an unrelated sink.
                continue
            reaching_children = {
                child for child, (may_reach, _may_bypass) in profiles.items()
                if may_reach
            }
            bypass_children = {
                child for child, (_may_reach, may_bypass) in profiles.items()
                if may_bypass
            }
            reaching = tuple(
                sorted(child_entries[child] for child in reaching_children)
            )
            bypass = tuple(
                sorted(child_entries[child] for child in bypass_children)
            )
            if reaching and bypass:
                result.append(
                    BranchReachability(
                        branch_instruction_index=last_instruction,
                        sink_reaching_successor_indices=reaching,
                        sink_bypass_successor_indices=bypass,
                    )
                )
        resolved = tuple(sorted(result, key=lambda item: item.branch_instruction_index))
        cache[target_instruction] = resolved
        return resolved

    def _block_reachable(self, start: int, target: int) -> bool:
        return start in self._blocks_reaching(target)

    def _block_must_reach(self, start: int, target: int) -> bool:
        """Whether every finite or cyclic continuation must pass ``target``."""

        return start in self._blocks_must_reach(target)

    def _block_graph(
        self,
    ) -> tuple[dict[int, tuple[int, ...]], dict[int, tuple[int, ...]]]:
        successors = getattr(self, "_block_successors_cache", None)
        predecessors = getattr(self, "_block_predecessors_cache", None)
        if successors is not None and predecessors is not None:
            return successors, predecessors
        successor_sets: dict[int, set[int]] = {
            block: set() for block in self.block_last
        }
        predecessor_sets: dict[int, set[int]] = {
            block: set() for block in self.block_last
        }
        for block, last in self.block_last.items():
            for instruction in self.successors[last]:
                child = self.block_for_instruction.get(instruction)
                if child is None:
                    continue
                successor_sets[block].add(child)
                predecessor_sets.setdefault(child, set()).add(block)
        successors = {
            block: tuple(sorted(children))
            for block, children in successor_sets.items()
        }
        predecessors = {
            block: tuple(sorted(parents))
            for block, parents in predecessor_sets.items()
        }
        self._block_successors_cache = successors
        self._block_predecessors_cache = predecessors
        return successors, predecessors

    def _entry_reachable_blocks(self) -> frozenset[int]:
        cached = getattr(self, "_entry_reachable_cache", None)
        if cached is not None:
            return cached
        entry = self.block_for_instruction.get(0)
        if entry is None:
            result = frozenset()
        else:
            successors, _predecessors = self._block_graph()
            queue = deque([entry])
            visited: set[int] = set()
            while queue:
                block = queue.popleft()
                if block in visited:
                    continue
                visited.add(block)
                queue.extend(successors.get(block, ()))
            result = frozenset(visited)
        self._entry_reachable_cache = result
        return result

    def _blocks_reaching(self, target: int) -> frozenset[int]:
        cache = getattr(self, "_blocks_reaching_cache", None)
        if cache is None:
            cache = self._blocks_reaching_cache = {}
        cached = cache.get(target)
        if cached is not None:
            return cached
        _successors, predecessors = self._block_graph()
        queue = deque([target])
        visited: set[int] = set()
        while queue:
            block = queue.popleft()
            if block in visited:
                continue
            visited.add(block)
            queue.extend(predecessors.get(block, ()))
        result = frozenset(visited)
        cache[target] = result
        return result

    def _blocks_must_reach(self, target: int) -> frozenset[int]:
        """Solve the least must-pass fixed point once for each target block."""

        cache = getattr(self, "_blocks_must_reach_cache", None)
        if cache is None:
            cache = self._blocks_must_reach_cache = {}
        cached = cache.get(target)
        if cached is not None:
            return cached
        successors, predecessors = self._block_graph()
        must_reach = {target}
        remaining = {
            block: len(children)
            for block, children in successors.items()
        }
        queue = deque([target])
        while queue:
            reached = queue.popleft()
            for parent in predecessors.get(reached, ()):
                if parent in must_reach:
                    continue
                remaining[parent] -= 1
                if successors.get(parent) and remaining[parent] == 0:
                    must_reach.add(parent)
                    queue.append(parent)
        result = frozenset(must_reach)
        cache[target] = result
        return result

    def _dominators(self) -> dict[int, frozenset[int]]:
        cached = getattr(self, "_dominators_cache", None)
        if cached is not None:
            return cached
        entry = self.block_for_instruction.get(0)
        reachable = set(self._entry_reachable_blocks())
        if entry is None or not reachable:
            self._dominators_cache = {}
            return {}
        _successors, predecessors = self._block_graph()
        dominators: dict[int, set[int]] = {
            block: ({entry} if block == entry else set(reachable))
            for block in reachable
        }
        changed = True
        while changed:
            changed = False
            for block in reachable - {entry}:
                parents = [
                    parent for parent in predecessors.get(block, ())
                    if parent in reachable
                ]
                inherited = (
                    set.intersection(*(dominators[parent] for parent in parents))
                    if parents
                    else set()
                )
                updated = {block, *inherited}
                if updated != dominators[block]:
                    dominators[block] = updated
                    changed = True
        result = {
            block: frozenset(values) for block, values in dominators.items()
        }
        self._dominators_cache = result
        return result

    def _block_dominates(self, dominator: int, target: int) -> bool:
        """Return whether ``dominator`` lies on every Entry-to-target path."""

        return dominator in self._dominators().get(target, ())

    def instruction_dominates(self, dominator: int, target: int) -> bool:
        dominator_block = self.block_for_instruction.get(dominator)
        target_block = self.block_for_instruction.get(target)
        if dominator_block is None or target_block is None:
            return False
        if dominator_block == target_block:
            return dominator <= target
        return self._block_dominates(dominator_block, target_block)
