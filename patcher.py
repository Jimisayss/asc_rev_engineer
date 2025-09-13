# Ascension.exe Patcher
# Bypasses a security check by dynamically finding a code signature and patching it.

import lief
import os
import re

# --- Configuration ---
TARGET_EXE = "Ascension.exe"
PATCHED_EXE = "Ascension_patched.exe"

# A regular expression signature to uniquely identify the patch location.
# This corresponds to:
#   test al, al        (84 C0)
#   jne <offset>       (75 17)  <- This is our patch target
#   push <4-byte addr> (68 ?? ?? ?? ??)
#   push ebx           (53)
# The .{4} is a wildcard for the 4-byte address which can change.
PATCH_SIGNATURE_RE = re.compile(b'\\x84\\xc0\\x75\\x17\\x68.{4}\\x53')

# The patch itself: NOP out the 'jne' instruction.
PATCH_BYTES = b"\x90\x90"


def find_signature_rva(binary, signature_re):
    """
    Scans the .text section of the binary for a given regex signature.
    Returns the RVA of the found signature's patch target.
    """
    print(f"Scanning for regex signature: {signature_re.pattern.hex()}...")

    text_section = binary.get_section(".text")
    if not text_section:
        print("Error: .text section not found.")
        return None

    # Get the raw content of the .text section
    content = bytes(text_section.content)

    # Use the regex to find all matches
    matches = list(signature_re.finditer(content))

    if not matches:
        print("Error: Patch signature not found.")
        return None

    if len(matches) > 1:
        print(f"Warning: Found {len(matches)} occurrences of the signature. Using the first one.")
        match_spans = [m.span() for m in matches]
        print(f"  Found at offsets: {[hex(s[0]) for s in match_spans]}")

    # The match object's start() gives the offset of the signature start
    found_offset = matches[0].start()

    # The patch target is the 'jne' instruction, which starts at the 3rd byte (offset 2)
    # of our signature pattern.
    patch_offset = found_offset + 2

    # Calculate the RVA
    patch_rva = text_section.virtual_address + patch_offset

    print(f"Signature found at offset 0x{found_offset:x} in .text section.")
    print(f"Calculated patch RVA: 0x{patch_rva:x}")

    return patch_rva


def main():
    """
    Patches the target executable to bypass the security check.
    """
    print("--- Ascension.exe Dynamic Patcher (Regex Mode) ---")

    if not os.path.exists(TARGET_EXE):
        print(f"Error: Target executable '{TARGET_EXE}' not found.")
        return

    try:
        binary = lief.PE.parse(TARGET_EXE)

        patch_rva = find_signature_rva(binary, PATCH_SIGNATURE_RE)
        if patch_rva is None:
            print("Patcher cannot continue. Exiting.")
            return

        image_base = binary.optional_header.imagebase
        patch_va = image_base + patch_rva

        print(f"\nPatching at dynamic location:")
        print(f"  - Patch VA:   {hex(patch_va)}")

        original_bytes = binary.get_content_from_virtual_address(patch_va, len(PATCH_BYTES))
        print(f"  - Original bytes to be patched: {[hex(b) for b in original_bytes]}")

        # Final check to ensure we are patching what we expect
        if bytes(original_bytes) != b'\x75\x17':
             print("Error: The bytes at the patch location are not the expected 'jne' instruction (75 17).")
             print("Aborting patch.")
             return

        print(f"Applying {len(PATCH_BYTES)}-byte NOP patch...")
        binary.patch_address(patch_va, list(PATCH_BYTES))

        new_bytes = binary.get_content_from_virtual_address(patch_va, len(PATCH_BYTES))
        if list(new_bytes) == list(PATCH_BYTES):
             print("  - Patch successfully applied in memory.")
        else:
            print("  - Error: Patch verification failed.")
            return

        print(f"Building and saving new executable to '{PATCHED_EXE}'...")
        builder = lief.PE.Builder(binary)
        builder.build()
        builder.write(PATCHED_EXE)

        print(f"\nSuccess! Patched file saved as '{PATCHED_EXE}'.")

    except Exception as e:
        print(f"\nAn unexpected error occurred: {e}")

if __name__ == "__main__":
    main()
