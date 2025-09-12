# Ascension.exe Patcher
# Bypasses a security check by patching instructions in the binary.

import lief
import os

# --- Configuration ---
TARGET_EXE = "Ascension.exe"
PATCHED_EXE = "Ascension_patched.exe"
# This is the Relative Virtual Address (RVA) of the instruction to patch.
PATCH_RVA = 0x10D242
# We'll replace the target instruction with two NOPs (No Operation, opcode 0x90).
# This is a common technique to disable a check, like a conditional jump.
PATCH_BYTES = [0x90, 0x90]

def create_dummy_exe():
    """Creates a fake Ascension.exe for development if it doesn't exist."""
    print(f"Info: '{TARGET_EXE}' not found. Creating a dummy file for testing.")
    try:
        binary = lief.PE.Binary("dummy", lief.PE.PE_TYPE.PE32)
        section_text = lief.PE.Section(".text")
        section_text.content = [0xCC] * 0x200000 # Fill with 'int3' breakpoints
        section_text.virtual_address = 0x1000
        binary.add_section(section_text)

        # The default image base is 0x400000. Our RVA is 0x10D242.
        # The .text section above should cover this RVA.
        # virtual_address=0x1000, virtual_size=0x200000 -> covers up to 0x201000

        builder = lief.PE.Builder(binary)
        builder.build()
        builder.write(TARGET_EXE)
        print(f"Successfully created dummy '{TARGET_EXE}'.")
        return True
    except Exception as e:
        print(f"Error creating dummy executable: {e}")
        return False

def main():
    """
    Patches the target executable to bypass the security check.
    """
    print("--- Ascension.exe Patcher ---")

    if not os.path.exists(TARGET_EXE):
        if not create_dummy_exe():
            return

    try:
        print(f"Loading '{TARGET_EXE}'...")
        binary = lief.PE.parse(TARGET_EXE)

        if isinstance(binary, lief.lief_errors):
            print(f"Error: lief could not parse '{TARGET_EXE}'. Error: {binary}")
            return

        image_base = binary.optional_header.imagebase
        patch_va = image_base + PATCH_RVA

        print(f"Successfully parsed '{TARGET_EXE}'.")
        print(f"  - Image Base: {hex(image_base)}")
        print(f"  - Patch RVA:  {hex(PATCH_RVA)}")
        print(f"  - Patch VA:   {hex(patch_va)}")

        # Verify that the address is patchable by checking if it belongs to a section.
        if binary.section_from_rva(PATCH_RVA) is None:
             print(f"Error: The RVA {hex(PATCH_RVA)} is not in a valid section of the binary.")
             print("The RVA might be incorrect or the binary structure is unexpected.")
             return

        # Get original bytes for logging purposes
        original_bytes = binary.get_content_from_virtual_address(patch_va, len(PATCH_BYTES))
        print(f"  - Original bytes at {hex(patch_va)}: {[hex(b) for b in original_bytes]}")

        # Apply the patch
        print(f"Applying {len(PATCH_BYTES)}-byte NOP patch...")
        binary.patch_address(patch_va, PATCH_BYTES)

        # Verify patch
        new_bytes = binary.get_content_from_virtual_address(patch_va, len(PATCH_BYTES))
        if list(new_bytes) == PATCH_BYTES:
             print("  - Patch successfully applied in memory.")
        else:
            print("  - Error: Patch verification failed.")
            return

        # Build and save the new executable
        print(f"Building and saving new executable to '{PATCHED_EXE}'...")
        builder = lief.PE.Builder(binary)
        builder.build()
        builder.write(PATCHED_EXE)

        print(f"\nSuccess! Patched file saved as '{PATCHED_EXE}'.")

    except Exception as e:
        print(f"\nAn unexpected error occurred: {e}")

if __name__ == "__main__":
    main()
