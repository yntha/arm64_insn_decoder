from enum import Enum


insn_bytes = 0x48010b9b


class InsnVariants(Enum):
    VAR_008 = 0b0001
    VAR_016 = 0b0101
    VAR_032 = 0b1001
    VAR_064 = 0b1101
    VAR_128 = 0b0011


class ARM64Registers(Enum):
    REG_00 = 0
    REG_01 = 1
    REG_02 = 2
    REG_03 = 3
    REG_04 = 4
    REG_05 = 5
    REG_06 = 6
    REG_07 = 7
    REG_08 = 8
    REG_09 = 9
    REG_10 = 10
    REG_11 = 11
    REG_12 = 12
    REG_13 = 13
    REG_14 = 14
    REG_15 = 15
    REG_16 = 16
    REG_17 = 17
    REG_18 = 18
    REG_19 = 19
    REG_20 = 20
    REG_21 = 21
    REG_22 = 22
    REG_23 = 23
    REG_24 = 24
    REG_25 = 25
    REG_26 = 26
    REG_27 = 27
    REG_28 = 28
    REG_29 = 29  # frame pointer
    REG_30 = 30  # link register
    REG_SPxZR = 31  # Stack Pointer or Zero Register



def extract_bits(num, start, stop):
    mask = (1 << (start - stop + 1)) - 1
    mask <<= stop
    extracted_bits = (num & mask) >> stop

    return extracted_bits


def little_endian(num):
    return ((num & 0x000000FF) << 24 |
            (num & 0x0000FF00) << 8  |
            (num & 0x00FF0000) >> 8  |
            (num & 0xFF000000) >> 24)


def decode_ldur(insn: int):
    size = extract_bits(insn, 31, 30)
    opc = extract_bits(insn, 23, 22)
    imm9 = extract_bits(insn, 20, 12)
    rn = ARM64Registers(extract_bits(insn, 9, 5))
    rt = ARM64Registers(extract_bits(insn, 4, 0))

    variant = InsnVariants((size << 2) + opc)

    print(f"LDUR: Size: {size}, Opcode: {opc} ({variant}), Imm9: {imm9}, Rn: {rn}, Rt: {rt}")


def decode_madd(insn: int):
    sf = extract_bits(insn, 31, 31)
    rm = ARM64Registers(extract_bits(insn, 20, 16))
    ra = ARM64Registers(extract_bits(insn, 14, 10))
    rn = ARM64Registers(extract_bits(insn, 9, 5))
    rd = ARM64Registers(extract_bits(insn, 4, 0))

    variant = InsnVariants.VAR_032 if sf == 0b0 else InsnVariants.VAR_064

    print(f"MADD: SF: {sf} ({variant}), rd: {rd}, rn: {rn}, rm: {rm}, ra: {ra}")


def decode_insn(insn: int):
    # convert insn to little endian
    insn = little_endian(insn)

    print(bin(insn)[2:].rjust(32, "0"))
    
    for mask in instruction_masks:
        instruction = instructions.get(insn & mask, None)

        if not instruction:
            continue

        instruction["decode_func"](insn)


instruction_masks = [
    0b00111111011000000000110000000000,
    0b01111111111000001000000000000000
]
instructions = {
    0b00111100010000000000000000000000: {
        "mnemonic": "ldur",
        "decode_func": decode_ldur
    },
    0b00011011000000000000000000000000: {
        "mnemonic": "madd",
        "decode_func": decode_madd
    }
}


decode_insn(insn_bytes)