# Standalone scanner to find the Lua protection signature in Ascension.exe

import lief
import re
import sys

# --- Configuration ---
# Use the same successful regex from the patcher.
SIGNATURE_RE = re.compile(b'\\x84\\xc0\\x75\\x17\\x68.{4}\\x53')

def find_signature_rva(binary, signature_re):
    """
    Scans the .text section of the binary for a given regex signature.
    Returns the RVA of the patch target within the signature.
    """
    text_section = binary.get_section(".text")
    if not text_section:
        return None, 0

    content = bytes(text_section.content)
    matches = list(signature_re.finditer(content))

    if not matches:
        return None, 0

    # The patch target is the 'jne' instruction, which starts 2 bytes into our signature.
    patch_rvas = []
    for match in matches:
        patch_offset = match.start() + 2
        patch_rva = text_section.virtual_address + patch_offset
        patch_rvas.append(patch_rva)

    return patch_rvas, len(matches)

def main(file_path):
    """
    Scans the specified executable for the security check signature.
    """
    print(f"--- Scanning {file_path} for Lua protection signature ---")

    try:
        binary = lief.PE.parse(file_path)
        if not binary:
            print(f"Error: Could not parse {file_path}")
            return

        rvas, count = find_signature_rva(binary, SIGNATURE_RE)

        print(f"\nSignature: {SIGNATURE_RE.pattern.hex()}")
        if rvas:
            print(f"Found {count} occurrence(s).")
            for i, rva in enumerate(rvas):
                va = binary.optional_header.imagebase + rva
                print(f"  - Match {i+1}: RVA = {hex(rva)}, VA = {hex(va)}")
            print("\nThe RVA is the address of the 'jne' instruction to be patched.")
        else:
            print("Signature not found in the binary.")

    except FileNotFoundError:
        print(f"Error: {file_path} not found.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python3 {sys.argv[0]} <path_to_exe>")
        sys.exit(1)

    main(sys.argv[1])
