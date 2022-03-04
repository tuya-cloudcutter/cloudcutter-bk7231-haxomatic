from collections import namedtuple
from operator import le
import sys
from typing import Callable, List, Tuple

from capstone import *
import capstone.arm as arm


CodePatternMatch = namedtuple("CodePatternMatch", "matched_instructions start_address start_offset")


class CodePatternFinder(object):
    def __init__(self, code: bytes, base_address: int = 0):
        self.code = code
        self.base_address = base_address

    def search(self, condition_lambdas: List[Callable[[CsInsn, int], bool]], start_address = None, thumb_mode=True, stop_at_first=True) -> List[CodePatternMatch]:
        mode = CS_MODE_THUMB if thumb_mode else CS_MODE_ARM
        wordsize = 2 if thumb_mode else 4

        if start_address is None:
            start_address = self.base_address

        if start_address < self.base_address:
            raise ValueError(f"Starting address {start_address:#x} cannot be less than base address {self.base_address:#x}")

        start_offset = (start_address - self.base_address)
        end_offset = len(self.code)
        
        md = Cs(CS_ARCH_ARM, mode)
        md.detail = True

        offset = start_offset
        matches = []
        while offset < end_offset:
            address = self.base_address + offset
            instrs = list(md.disasm(self.code[offset:], offset=address))
            increment = (len(instrs) * wordsize) or wordsize

            workinglist = instrs[::]
            while len(workinglist) >= len(condition_lambdas):
                invocation_list = workinglist[:len(condition_lambdas)]
                invocations = [l(i, i.address - self.base_address) for i, l in zip(invocation_list, condition_lambdas)]
                
                if all(invocations):
                    matched_address = workinglist[0].address
                    matched_offset = matched_address - self.base_address
                    match = CodePatternMatch(matched_instructions=invocation_list, start_address=matched_address, start_offset=matched_offset)
                    if stop_at_first:
                        return [match]
                    else:
                        matches.append(match)

                workinglist.pop(0)

            offset += increment
        
        return matches

    def __build_cache(self, mode: int, wordsize: int):
        md = Cs(CS_ARCH_ARM, mode)
        md.detail = True

        cache = []
        offset = 0
        while offset < len(self.code):
            address = offset + self.base_address
            instrs = list(md.disasm(self.code[offset:], offset=address))
            increment = (len(instrs) * wordsize) or wordsize
            if instrs:
                cache.extend(instrs)
            else:
                cache.append(None)
            offset += increment

        return cache

def walk_app_code(appcode: bytes):
    # TODO: maybe match here already on strings in the binary?
    if b'wifisdk_for_bk7231/project' in appcode:
        pass
    elif b'EmbedSDKs/ty_iot_wf_bt_sdk_bk' in appcode:
        pass
    else:
        raise RuntimeError('Unknown appcode provided')

    APPCODE_START_ADDRESS = 0x10000
    matcher = CodePatternFinder(appcode, APPCODE_START_ADDRESS)

    post_vuln_pattern = [
        lambda i0, _: i0.id == arm.ARM_INS_LDR and i0.operands[0].reg == arm.ARM_REG_R3 and len(i0.operands) > 1 and i0.operands[1].mem.disp == 0x50,
        lambda i1, _: i1.id == arm.ARM_INS_LDR and i1.operands[0].reg == arm.ARM_REG_R1 and len(i1.operands) > 1 and i1.operands[1].reg == arm.ARM_REG_PC and i1.operands[1].mem.disp > 0,
        lambda i2, _: i2.id in [arm.ARM_INS_SUB, arm.ARM_INS_ADD] and len(i2.operands) > 2 and i2.operands[0].reg == arm.ARM_REG_R0 and i2.operands[2].imm == 0,
        lambda i3, _: i3.id == arm.ARM_INS_BLX and i3.operands[0].reg == arm.ARM_REG_R3
    ]

    match = matcher.search(condition_lambdas=post_vuln_pattern, thumb_mode=True)
    if not match:
        raise RuntimeError("No matching vuln invocation locations found")

    print(match)

    ldr_r3 = match[0].matched_instructions[0]
    reg_lan_obj = ldr_r3.operands[1].reg
    reg_json_obj = arm.ARM_REG_R7

    fixup_gadget_pattern = [
        lambda i0, _: i0.id == arm.ARM_INS_LDR and i0.operands[0].reg == arm.ARM_REG_R3 and i0.operands[1].reg == reg_lan_obj and i0.operands[1].mem.disp == 0 and i0.operands[1].mem.index == 0,
        lambda i1, _: i1.id in [arm.ARM_INS_SUB, arm.ARM_INS_ADD] and len(i1.operands) > 2 and i1.operands[0].reg == arm.ARM_REG_R0 and i1.operands[1].reg == reg_json_obj and i1.operands[2].imm == 0,
        lambda i2, _: i2.id == arm.ARM_INS_BLX and i2.operands[0].reg == arm.ARM_REG_R3
    ]

    fixup_match = matcher.search(condition_lambdas=fixup_gadget_pattern, thumb_mode=True, stop_at_first=False)
    print(fixup_match)

if __name__ == '__main__':
    if not sys.argv[1:]:
        print('Usage: python haxomatic.py <app code file>')
        sys.exit(1)

    appcode_path = sys.argv[1]
    with open(appcode_path, 'rb') as fs:
        appcode = fs.read()
        walk_app_code(appcode)