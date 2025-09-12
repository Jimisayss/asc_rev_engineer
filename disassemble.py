import json
import lief
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
import struct
import os

def find_function_start(ref_address, function_prologues_sorted):
    """
    Finds the start of a function given an address inside it.
    It does this by finding the last function prologue that appears before the address.
    """
    best_prologue = 0
    # This is not efficient, but given the small number of lookups, it's acceptable.
    # A binary search would be ideal for performance.
    for prologue_addr in function_prologues_sorted:
        if prologue_addr <= ref_address:
            best_prologue = prologue_addr
        else:
            break
    return best_prologue

def get_next_function_start(current_start, function_prologues_sorted):
    """
    Finds the start address of the next function in the list.
    """
    try:
        current_index = function_prologues_sorted.index(current_start)
        if current_index + 1 < len(function_prologues_sorted):
            return function_prologues_sorted[current_index + 1]
    except ValueError:
        pass  # This can happen if the function prologue is not in our list
    return None

def disassemble_from_va(binary, start_va, size=4096):
    """
    Disassembles a chunk of code from a given virtual address.
    """
    try:
        code_bytes = bytes(binary.get_content_from_virtual_address(start_va, size))
    except lief.bad_address:
        print(f"Warning: Bad address or size when disassembling at {hex(start_va)}")
        return None, 0

    md = Cs(CS_ARCH_X86, CS_MODE_32)
    disassembly = ""
    last_address = 0
    for i in md.disasm(code_bytes, start_va):
        disassembly += f"0x{i.address:x}:\t{i.mnemonic}\t{i.op_str}\n"
        last_address = i.address

    return disassembly, last_address

def main():
    """
    Main function to find references to key strings and disassemble the
    functions that contain them.
    """
    EXE_PATH = "Ascension.exe"

    try:
        with open('strings.json', 'r') as f:
            string_data = json.load(f)
    except FileNotFoundError:
        print("Error: strings.json not found. Run recon.py first.")
        return

    try:
        with open('signatures.json', 'r') as f:
            signature_data = json.load(f)
    except FileNotFoundError:
        print("Error: signatures.json not found. Run scan.py first.")
        return

    chat_message_strings = string_data.get("SendChatMessage", [])
    if not chat_message_strings:
        print("No 'SendChatMessage' strings found in strings.json.")
        return

    prologue_vas = sorted([int(addr, 16) for addr in signature_data['addresses']])

    binary = lief.parse(EXE_PATH)
    if not binary:
        print(f"Error: Could not parse {EXE_PATH}")
        return

    image_base = binary.optional_header.imagebase
    text_section = binary.get_section(".text")
    text_section_content = bytes(text_section.content)
    text_section_base_va = image_base + text_section.virtual_address

    print("Searching for cross-references to 'SendChatMessage'...")

    disassembled_functions = set()
    ref_count = 0

    for string_info in chat_message_strings:
        string_va_hex = string_info['virtual_address']
        string_va_int = int(string_va_hex, 16)

        address_bytes = struct.pack('<I', string_va_int)

        offset = -1
        while True:
            offset = text_section_content.find(address_bytes, offset + 1)
            if offset == -1:
                break

            ref_va = text_section_base_va + offset
            func_start_va = find_function_start(ref_va, prologue_vas)

            if func_start_va == 0 or func_start_va in disassembled_functions:
                continue

            disassembled_functions.add(func_start_va)

            next_func_start = get_next_function_start(func_start_va, prologue_vas)
            size_to_disassemble = 4096  # Fallback size
            if next_func_start:
                size_to_disassemble = next_func_start - func_start_va

            disassembly, last_addr = disassemble_from_va(binary, func_start_va, size=size_to_disassemble)

            if disassembly:
                filename = f"disassembly_func_{hex(func_start_va)}.txt"
                with open(filename, 'w') as out_f:
                    out_f.write(f"// Disassembly of function at {hex(func_start_va)}\n")
                    out_f.write(f"// Found reference to string 'SendChatMessage' at {string_va_hex}\n")
                    out_f.write(f"// The reference is located near virtual address: {hex(ref_va)}\n")
                    out_f.write(f"// Disassembled from {hex(func_start_va)} to {hex(last_addr)}\n\n")
                    out_f.write(disassembly)
                print(f"Saved full disassembly to {filename}")
                ref_count += 1

    if ref_count == 0:
        print("Could not find any code references to 'SendChatMessage'.")
    else:
        print(f"\nFound and disassembled {ref_count} unique functions referencing 'SendChatMessage'.")

if __name__ == "__main__":
    main()
