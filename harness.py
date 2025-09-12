import ctypes
from ctypes import wintypes
import psutil
import struct
import json
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

# --- Globals for Configuration and Logging ---
LOG_DATA = {}

# --- Windows API Definitions ---
PROCESS_ALL_ACCESS = 0x1F0FFF
PAGE_READWRITE = 0x04
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000

kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

# Function prototypes for cleaner API calls
kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.OpenProcess.restype = wintypes.HANDLE
kernel32.ReadProcessMemory.argtypes = [wintypes.HANDLE, wintypes.LPCVOID, wintypes.LPVOID, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
kernel32.ReadProcessMemory.restype = wintypes.BOOL
kernel32.WriteProcessMemory.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.LPCVOID, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
kernel32.WriteProcessMemory.restype = wintypes.BOOL
kernel32.VirtualAllocEx.argtypes = [wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD]
kernel32.VirtualAllocEx.restype = wintypes.LPVOID
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL

def find_process_by_name(process_name):
    """Finds a process by name and returns the psutil.Process object."""
    for proc in psutil.process_iter(['pid', 'name']):
        if proc.info['name'].lower() == process_name.lower():
            LOG_DATA['pid'] = proc.info['pid']
            return proc
    return None

def find_pattern_in_memory(h_process, base_address, size, pattern, wildcard=b'\xCC'):
    """Searches for a byte pattern (with wildcards) in the memory of a process."""
    buffer = ctypes.create_string_buffer(size)
    bytes_read = ctypes.c_size_t(0)

    if not kernel32.ReadProcessMemory(h_process, base_address, buffer, size, ctypes.byref(bytes_read)):
        raise ctypes.WinError(ctypes.get_last_error())

    buffer_bytes = buffer.raw

    for i in range(len(buffer_bytes) - len(pattern)):
        found = True
        for j in range(len(pattern)):
            if pattern[j] != wildcard and pattern[j] != buffer_bytes[i+j]:
                found = False
                break
        if found:
            return base_address + i

    return None

def verify_function_prologue(h_process, address):
    """Reads memory at address and verifies it's a standard function prologue."""
    prologue_bytes = ctypes.create_string_buffer(10)
    bytes_read = ctypes.c_size_t(0)
    kernel32.ReadProcessMemory(h_process, address, prologue_bytes, 10, ctypes.byref(bytes_read))

    md = Cs(CS_ARCH_X86, CS_MODE_32)
    instructions = list(md.disasm(prologue_bytes.raw, address))

    if len(instructions) >= 2 and instructions[0].mnemonic == 'push' and instructions[1].mnemonic == 'mov':
        print(f"  [+] Capstone verification passed: Found '{instructions[0].mnemonic} {instructions[0].op_str}; {instructions[1].mnemonic} {instructions[1].op_str}'")
        return True

    print("  [!] Capstone verification failed: Did not find a standard function prologue.")
    return False

def main():
    PROCESS_NAME = "Ascension.exe"
    LUA_CODE_TO_EXECUTE = b'DEFAULT_CHAT_FRAME:AddMessage("Hello from patched harness!", 1.0, 1.0, 0.0)\x00'

    # --- This is the signature for the function we want to call ---
    # This signature is for the dispatcher function at 0x50d170. While this is not the
    # final function we want to call, finding it is a key step. The wildcard 'None'
    # will match any byte, making the signature resilient to minor changes.
    # We use a wildcard for the call offset because it can change between builds.
    FUNCTION_SIGNATURE = b'\x55\x8b\xec\x83\xec\xe8\xde\x00\x00\x00\xe8' + b'\xcc\xcc\xcc\xcc' # The call address is wildcarded

    # --- This is the assumed prototype of the real script execution function ---
    # We are assuming a function that takes a single string argument (the Lua code).
    # This is a common pattern, but may need to be adjusted based on debugging.
    # The function likely returns void or an int status code.
    TARGET_FUNC_PROTOTYPE = ctypes.WINFUNCTYPE(None, ctypes.c_char_p)

    h_process = None
    try:
        # 1. Find Process and Get Handle
        print(f"[*] Searching for process: {PROCESS_NAME}")
        proc = find_process_by_name(PROCESS_NAME)
        if not proc:
            raise RuntimeError(f"Process '{PROCESS_NAME}' not found. Is the patched game running?")
        print(f"  [+] Found process with PID: {proc.pid}")

        h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, proc.pid)
        if not h_process:
            raise ctypes.WinError(ctypes.get_last_error())
        print(f"  [+] Successfully obtained handle to process.")

        # 2. Dynamic Address Discovery
        print("[*] Finding module base address and size...")
        maps = proc.memory_maps()
        main_module = None
        for m in maps:
            if m.path and m.path.endswith(PROCESS_NAME):
                main_module = m
                break

        if not main_module:
            raise RuntimeError("Could not find the main module in the process memory map.")

        base_address = main_module.addr
        module_size = main_module.size
        LOG_DATA['base_address'] = hex(base_address)
        LOG_DATA['module_size'] = module_size
        print(f"  [+] Module Base Address: {hex(base_address)}")
        print(f"  [+] Module Size: {module_size // 1024} KB")

        # 3. Section-Specific Signature Scanning
        print("[*] Parsing PE header from memory to find .text section...")
        module_data = ctypes.create_string_buffer(module_size)
        bytes_read = ctypes.c_size_t(0)
        kernel32.ReadProcessMemory(h_process, base_address, module_data, module_size, ctypes.byref(bytes_read))

        pe = pefile.PE(data=module_data.raw)
        text_section = None
        for section in pe.sections:
            if section.Name.strip(b'\x00') == b'.text':
                text_section = section
                break

        if not text_section:
            raise RuntimeError("Could not find the .text section in the in-memory PE header.")

        scan_address = base_address + text_section.VirtualAddress
        scan_size = text_section.Misc_VirtualSize
        LOG_DATA['text_section_address'] = hex(scan_address)
        LOG_DATA['text_section_size'] = scan_size
        print(f"  [+] .text section found at {hex(scan_address)} with size {scan_size}")

        print(f"[*] Searching for function signature in .text section...")
        function_address = find_pattern_in_memory(h_process, scan_address, scan_size, FUNCTION_SIGNATURE, wildcard=b'\xcc')

        if not function_address:
            raise RuntimeError("Could not find function signature. The patch might be incorrect or the game has updated.")

        LOG_DATA['found_function_address'] = hex(function_address)
        print(f"  [+] Signature found! Potential function address: {hex(function_address)}")

        # 4. Capstone Verification
        print("[*] Verifying function prologue with Capstone...")
        if not verify_function_prologue(h_process, function_address):
             raise RuntimeError("Function verification failed. The found signature does not point to a valid function.")

        # This part is still speculative. We found the dispatcher, but not the executor.
        # For now, we will assume an offset from the found dispatcher.
        # This will need to be refined with dynamic analysis by the user.
        # For example, let's assume the real function is 0x100 bytes after the dispatcher.
        EXECUTE_FUNCTION_ADDRESS = function_address + 0x100 # Placeholder
        LOG_DATA['execution_target_address'] = hex(EXECUTE_FUNCTION_ADDRESS)
        print(f"[*] Assuming execution function is at {hex(EXECUTE_FUNCTION_ADDRESS)} (This is a placeholder!)")

        # 5. Allocate, Write, and Execute
        print("[*] Injecting and executing Lua code...")
        mem_addr = kernel32.VirtualAllocEx(h_process, 0, len(LUA_CODE_TO_EXECUTE), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
        if not mem_addr:
            raise ctypes.WinError(ctypes.get_last_error())
        LOG_DATA['allocated_memory_address'] = hex(mem_addr)
        print(f"  [+] Memory allocated at {hex(mem_addr)}")

        kernel32.WriteProcessMemory(h_process, mem_addr, LUA_CODE_TO_EXECUTE, len(LUA_CODE_TO_EXECUTE), ctypes.byref(bytes_read))
        print(f"  [+] Wrote {bytes_read.value} bytes of Lua code.")

        # Create the function object and call it
        remote_function = TARGET_FUNC_PROTOTYPE(EXECUTE_FUNCTION_ADDRESS)
        print(f"[*] Calling remote function at {hex(EXECUTE_FUNCTION_ADDRESS)}...")

        # This is where the magic happens. We call the function in the remote process.
        remote_function(mem_addr)

        print("\n[SUCCESS] Harness executed without errors. Check in-game for the message!")

    except Exception as e:
        print(f"\n[ERROR] An exception occurred: {e}")

    finally:
        if h_process:
            kernel32.CloseHandle(h_process)
            print("[*] Process handle closed.")

        # 6. Log results to JSON
        with open("harness_log.json", "w") as f:
            json.dump(LOG_DATA, f, indent=4)
        print("[*] Log data saved to harness_log.json")

if __name__ == "__main__":
    main()
