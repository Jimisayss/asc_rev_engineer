import pefile
import lief
import json
import sys

def analyze_binary(file_path):
    """
    Performs static analysis on a PE file to find Lua-related imports/exports
    and specific strings, including wide-character strings.
    """
    try:
        binary = lief.parse(file_path)
        if binary is None:
            print(f"Error: LIEF could not parse {file_path}")
            sys.exit(1)
        image_base = binary.optional_header.imagebase
    except lief.bad_file as e:
        print(f"Error parsing file with LIEF: {e}")
        sys.exit(1)

    # --- Imports/Exports (same as before) ---
    pe = pefile.PE(file_path)
    imports_data = {}
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode('utf-8')
            lua_imports = []
            for imp in entry.imports:
                try:
                    if imp.name and b'lua' in imp.name.lower():
                        lua_imports.append({
                            'name': imp.name.decode('utf-8'),
                            'address': hex(imp.address)
                        })
                except (UnicodeDecodeError, AttributeError):
                    continue
            if lua_imports:
                imports_data[dll_name] = lua_imports

    exports_data = []
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            try:
                if exp.name and b'lua' in exp.name.lower():
                    exports_data.append({
                        'name': exp.name.decode('utf-8'),
                        'address': hex(image_base + exp.address)
                    })
            except (UnicodeDecodeError, AttributeError):
                continue

    with open('imports.json', 'w') as f:
        json.dump({'imports': imports_data, 'exports': exports_data}, f, indent=4)
        print("Created imports.json")

    # --- Enhanced String Search ---
    strings_to_find = [
        "FrameScript_ExecuteBuffer",
        "SendChatMessage",
        "lua_State",
        "ExecuteBuffer" # Partial string
    ]

    found_strings = {}

    for s in strings_to_find:
        found_strings[s] = []

        # Search for ASCII
        s_bytes_ascii = s.encode('ascii')
        for section in binary.sections:
            for offset in section.search_all(s_bytes_ascii):
                va = image_base + section.virtual_address + offset
                entry = {'virtual_address': hex(va), 'section': section.name, 'encoding': 'ascii'}
                if entry not in found_strings[s]:
                    found_strings[s].append(entry)

        # Search for UTF-16 Little Endian
        s_bytes_utf16 = s.encode('utf-16-le')
        for section in binary.sections:
            for offset in section.search_all(s_bytes_utf16):
                va = image_base + section.virtual_address + offset
                entry = {'virtual_address': hex(va), 'section': section.name, 'encoding': 'utf-16le'}
                if entry not in found_strings[s]:
                    found_strings[s].append(entry)

    with open('strings.json', 'w') as f:
        json.dump(found_strings, f, indent=4)
        print("Created strings.json with enhanced search.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python3 {sys.argv[0]} <path_to_exe>")
        sys.exit(1)

    file_path = sys.argv[1]
    analyze_binary(file_path)
    print("\nAnalysis complete.")
