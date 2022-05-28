from collections import deque, namedtuple
from typing import Callable, List
from capstone import *
import bisect
import itertools

CodePatternMatch = namedtuple("CodePatternMatch", "matched_instructions start_address start_offset")
SentinelInstruction = namedtuple("SentinelInstruction", "address size")
InstructionCache = namedtuple("InstructionCache", "instr_list instr_str_list")

class CodePatternFinder(object):
    def __init__(self, code: bytes, base_address: int = 0):
        self.code = code
        self.base_address = base_address
        self.thumb_cache = self.__build_cache(thumb_mode=True)
        self.arm_cache = self.__build_cache(thumb_mode=False)

    def search(self, condition_lambdas: List[Callable[[CsInsn, int], bool]], start_address: int = None, thumb_mode: bool = True, stop_at_first: bool = True, after_match_count: int = None) -> List[CodePatternMatch]:
        cache = self.thumb_cache if thumb_mode else self.arm_cache
        wordsize = self.__get_wordsize(thumb_mode)

        if start_address is None:
            start_address = self.base_address

        if start_address < self.base_address:
            raise ValueError(f"Starting address {start_address:#x} cannot be less than base address {self.base_address:#x}")

        if start_address > self.base_address + len(self.code):
            raise ValueError(f"Starting address {start_address:#x} is higher the end of code address")

        if (start_address % wordsize) != 0:
            raise ValueError(f"Start address must be aligned to word size {wordsize}")

        bisect_cache = list(i.address for i in cache.instr_list)
        start_offset = bisect.bisect(bisect_cache, start_address)
        workinglist = deque(cache[start_offset:])

        matches = []
        while workinglist:
            invocation_list = list(itertools.islice(workinglist, 0, len(condition_lambdas)))
            invocations = [not isinstance(i, SentinelInstruction) and l(i, i.address - self.base_address) for i, l in zip(invocation_list, condition_lambdas)]
            if all(invocations):
                matched_address = invocation_list[0].address
                matched_offset = matched_address - self.base_address
                matched_instructions = invocation_list if after_match_count is None else list(itertools.islice(workinglist, 0, len(condition_lambdas) + after_match_count))
                match = CodePatternMatch(matched_instructions=matched_instructions, start_address=matched_address, start_offset=matched_offset)
                if stop_at_first:
                    return [match]
                else:
                    matches.append(match)

            workinglist.popleft()
        
        return matches

    def bytecode_search(self, bytecode: bytes, stop_at_first: bool = True):
        offset = self.code.index(bytecode, 0)
        if offset == -1:
            return []

        matches = [self.base_address + offset]
        if stop_at_first:
            return matches

        offset = self.code.index(bytecode, offset+1)
        while offset != -1:
            matches.append(self.base_address + offset)
            offset = self.code.index(bytecode, offset+1)

        return matches

    def __build_cache(self, thumb_mode: bool):
        mode = CS_MODE_THUMB if thumb_mode else CS_MODE_ARM
        md = Cs(CS_ARCH_ARM, mode)
        md.detail = True
        wordsize = self.__get_wordsize(thumb_mode)

        cache = []
        offset = 0
        sentinel_size = 0
        while offset < len(self.code):
            address = offset + self.base_address
            instrs = list(md.disasm(self.code[offset:], offset=address))
            increment = sum((i.size for i in instrs)) or wordsize
            if instrs:
                cache.extend(instrs)
                if sentinel_size:
                    cache.append(SentinelInstruction(address=(address-sentinel_size), size=sentinel_size))
                    sentinel_size = 0
            else:
                sentinel_size += wordsize
            offset += increment

        instr_cache = InstructionCache(cache, list(map(lambda i: f"{i.mnemonic} {i.op_str}", cache)))

        return instr_cache

    def __get_wordsize(self, thumb_mode: bool):
        return 2 if thumb_mode else 4