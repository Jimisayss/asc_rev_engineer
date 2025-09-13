import lief
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

def disassemble_from_va(binary, start_va, size=2048):
    """
    Disassembles a chunk of code from a given virtual address.
    """
    try:
        code_bytes = bytes(binary.get_content_from_virtual_address(start_va, size))
    except lief.bad_address:
        print(f"Error: Bad address or size when disassembling at {hex(start_va)}")
        return None

    md = Cs(CS_ARCH_X86, CS_MODE_32)
    disassembly = ""
    for i in md.disasm(code_bytes, start_va):
        disassembly += f"0x{i.address:x}:\t{i.mnemonic}\t{i.op_str}\n"

    return disassembly

def main():
    EXE_PATH = "Ascension.exe"
    START_OFFSET = 0x50d170
    TARGET_OFFSET = 0x50D242


    binary = lief.parse(EXE_PATH)
    if not binary:
        print(f"Error: Could not parse {EXE_PATH}")
        return

    image_base = binary.optional_header.imagebase
    start_va = image_base + START_OFFSET
    target_va = image_base + TARGET_OFFSET

    print(f"Image Base: {hex(image_base)}")
    print(f"Analyzing code from offset 0x{START_OFFSET:X} (VA: {hex(start_va)})")
    print(f"Target address for patch is 0x{TARGET_OFFSET:X} (VA: {hex(target_va)})")
    print("-" * 40)

    disassembly = disassemble_from_va(binary, start_va)

    if disassembly:
        print(disassembly)
    else:
        print("Failed to disassemble code at the target address.")

if __name__ == "__main__":
    main()
