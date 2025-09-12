import lief
import os

def patch_binary(input_path, output_path):
    """
    Applies a specific patch to the given binary file.
    """
    if not os.path.exists(input_path):
        print(f"Error: Input file '{input_path}' not found.")
        return

    # --- Patch details identified from disassembly analysis ---
    target_va = 0x50d242
    original_bytes = [0x75, 0x17]  # JNE (Jump if Not Equal)
    patched_bytes = [0xEB, 0x17]   # JMP (Unconditional Jump)

    # --- Load binary using LIEF ---
    print(f"Loading '{input_path}'...")
    binary = lief.parse(input_path)
    if not binary:
        print("Error: LIEF could not parse the binary.")
        return

    # --- Sanity Check ---
    print(f"Verifying original bytes at virtual address {hex(target_va)}...")
    try:
        bytes_at_va = binary.get_content_from_virtual_address(target_va, len(original_bytes))

        if list(bytes_at_va) != original_bytes:
            print(f"Error: Sanity check failed! Bytes at the target address do not match.")
            print(f"  Expected: {bytes(original_bytes).hex()}")
            print(f"  Found:    {bytes(bytes_at_va).hex()}")
            print("Aborting patch.")
            return

        print("Sanity check passed. Found expected JNE instruction.")
    except lief.bad_address:
        print(f"Error: Could not read from virtual address {hex(target_va)}. Is the address correct?")
        return

    # --- Apply Patch ---
    print(f"Applying patch: Changing JNE to JMP at {hex(target_va)}...")
    binary.patch_address(target_va, patched_bytes)

    # --- Write the new patched binary ---
    print(f"Writing patched binary to '{output_path}'...")
    binary.write(output_path)

    print(f"\nPatching complete. Patched file saved as '{output_path}'.")

if __name__ == "__main__":
    patch_binary("Ascension.exe", "Ascension_patched.exe")
