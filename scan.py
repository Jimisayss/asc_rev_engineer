import lief
import json
import sys

def scan_signatures(file_path):
    """
    Scans the .text section of a PE file for a given byte signature
    and records the virtual addresses of all occurrences.
    """
    try:
        binary = lief.parse(file_path)
        if binary is None:
            print(f"Error: LIEF could not parse {file_path}")
            sys.exit(1)
    except lief.bad_file as e:
        print(f"Error parsing file with LIEF: {e}")
        sys.exit(1)

    image_base = binary.optional_header.imagebase
    text_section = binary.get_section(".text")

    if not text_section:
        print("Error: .text section not found.")
        sys.exit(1)

    # Signature for 'push ebp; mov ebp, esp'
    prologue_signature = b"\x55\x8b\xec"

    found_addresses = []

    # Use search_all to find all occurrences of the signature
    offsets = text_section.search_all(prologue_signature)

    text_section_va = text_section.virtual_address
    for offset in offsets:
        # Calculate the absolute virtual address
        va = image_base + text_section_va + offset
        found_addresses.append(hex(va))

    output = {
        'prologue_signature': prologue_signature.hex(),
        'count': len(found_addresses),
        'addresses': found_addresses
    }

    with open('signatures.json', 'w') as f:
        json.dump(output, f, indent=4)

    print(f"Signature scanning complete. Found {len(found_addresses)} matches.")
    print("Results saved to signatures.json")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python3 {sys.argv[0]} <path_to_exe>")
        sys.exit(1)

    file_path = sys.argv[1]
    scan_signatures(file_path)
