import ctypes
import sys
import os
import psutil
from ctypes import wintypes

# --- Constants ---
# WinAPI
PROCESS_ALL_ACCESS = (0x000F0000 | 0x00100000 | 0xFFF)
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
MEM_RELEASE = 0x8000
PAGE_READWRITE = 0x04
LIST_MODULES_ALL = 0x03

# Mod-specific
TARGET_PROCESS = "Ascension.exe"
DLL_NAME = "lua_modloader.dll"
# Relative Virtual Address (RVA) for the Lua execution function
FRAME_SCRIPT_EXECUTE_BUFFER_RVA = 0x50D170

# --- WinAPI Function Definitions ---
kernel32 = ctypes.windll.kernel32
psapi = ctypes.windll.psapi

# ... (API definitions remain the same)
kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.OpenProcess.restype = wintypes.HANDLE

kernel32.VirtualAllocEx.argtypes = [wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD]
kernel32.VirtualAllocEx.restype = wintypes.LPVOID

kernel32.VirtualFreeEx.argtypes = [wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD]
kernel32.VirtualFreeEx.restype = wintypes.BOOL

kernel32.WriteProcessMemory.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.LPCVOID, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
kernel32.WriteProcessMemory.restype = wintypes.BOOL

kernel32.GetModuleHandleA.argtypes = [wintypes.LPCSTR]
kernel32.GetModuleHandleA.restype = wintypes.HMODULE

kernel32.GetProcAddress.argtypes = [wintypes.HMODULE, wintypes.LPCSTR]
kernel32.GetProcAddress.restype = ctypes.c_void_p

kernel32.CreateRemoteThread.argtypes = [wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t, ctypes.c_void_p, wintypes.LPVOID, wintypes.DWORD, wintypes.LPVOID]
kernel32.CreateRemoteThread.restype = wintypes.HANDLE

kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
kernel32.WaitForSingleObject.restype = wintypes.DWORD

kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL

psapi.EnumProcessModulesEx.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.HMODULE), wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), wintypes.DWORD]
psapi.EnumProcessModulesEx.restype = wintypes.BOOL

psapi.GetModuleBaseNameA.argtypes = [wintypes.HANDLE, wintypes.HMODULE, wintypes.LPSTR, wintypes.DWORD]
psapi.GetModuleBaseNameA.restype = wintypes.DWORD


def find_process_id(process_name):
    """Finds the process ID for a given process name."""
    for proc in psutil.process_iter(['pid', 'name']):
        if proc.info['name'] == process_name:
            return proc.info['pid']
    return None

def get_module_base_address(h_process, module_name_to_find):
    """Gets the base address of a module within a process."""
    modules = (wintypes.HMODULE * 1024)()
    needed = wintypes.DWORD()
    if not psapi.EnumProcessModulesEx(h_process, modules, ctypes.sizeof(modules), ctypes.byref(needed), LIST_MODULES_ALL):
        print(f"Error: EnumProcessModulesEx failed. Error code: {kernel32.GetLastError()}")
        return None

    num_modules = needed.value // ctypes.sizeof(wintypes.HMODULE)
    for i in range(num_modules):
        module_name_buffer = (ctypes.c_char * 256)()
        if psapi.GetModuleBaseNameA(h_process, modules[i], module_name_buffer, ctypes.sizeof(module_name_buffer)):
            if module_name_buffer.value.decode('utf-8', 'ignore').lower() == module_name_to_find.lower():
                return modules[i]
    return None

def inject_dll(h_process, dll_path):
    """Injects a DLL into a process."""
    dll_path_bytes = dll_path.encode('ascii')
    alloc_address = kernel32.VirtualAllocEx(h_process, 0, len(dll_path_bytes) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
    if not alloc_address:
        print(f"Error: Could not allocate memory for DLL path. Error code: {kernel32.GetLastError()}")
        return False

    if not kernel32.WriteProcessMemory(h_process, alloc_address, dll_path_bytes, len(dll_path_bytes) + 1, None):
        print(f"Error: Could not write DLL path to process memory. Error code: {kernel32.GetLastError()}")
        kernel32.VirtualFreeEx(h_process, alloc_address, 0, MEM_RELEASE)
        return False

    h_kernel32 = kernel32.GetModuleHandleA(b"kernel32.dll")
    load_library_addr = kernel32.GetProcAddress(h_kernel32, b"LoadLibraryA")
    h_thread = kernel32.CreateRemoteThread(h_process, None, 0, load_library_addr, alloc_address, 0, None)
    if not h_thread:
        print(f"Error: Could not create remote thread for DLL injection. Error code: {kernel32.GetLastError()}")
        kernel32.VirtualFreeEx(h_process, alloc_address, 0, MEM_RELEASE)
        return False

    print("Successfully created remote thread. DLL should be injected.")
    kernel32.CloseHandle(h_thread)
    return True

import struct

def generate_shellcode(lua_string_addr, func_addr):
    """
    Generates x86 shellcode to call a function with the correct arguments.
    Signature: func(string, NULL, 1)
    """
    shellcode = b''
    # push 1 (showErrors = 1)
    shellcode += b'\x6A\x01'
    # push 0 (filename = NULL)
    shellcode += b'\x6A\x00'
    # push <lua_string_addr>
    shellcode += b'\x68' + struct.pack('<L', lua_string_addr)
    # mov eax, <func_addr>
    shellcode += b'\xB8' + struct.pack('<L', func_addr)
    # call eax
    shellcode += b'\xFF\xD0'
    # ret
    shellcode += b'\xC3'
    return shellcode

def send_lua_command(process_handle, func_address, command_string):
    """
    Injects and executes shellcode to call the Lua execution function safely.
    """
    # 1. Allocate memory for the Lua string
    lua_code_bytes = command_string.encode('ascii') + b'\x00'
    lua_addr = kernel32.VirtualAllocEx(process_handle, 0, len(lua_code_bytes), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
    if not lua_addr:
        print(f"Error: VirtualAllocEx for Lua string failed. Error code: {kernel32.GetLastError()}")
        return

    # 2. Write the Lua string to the allocated memory
    if not kernel32.WriteProcessMemory(process_handle, lua_addr, lua_code_bytes, len(lua_code_bytes), None):
        print(f"Error: WriteProcessMemory for Lua string failed. Error code: {kernel32.GetLastError()}")
        kernel32.VirtualFreeEx(process_handle, lua_addr, 0, MEM_RELEASE)
        return

    # 3. Generate the shellcode with the dynamic addresses
    shellcode = generate_shellcode(lua_addr, func_address)

    # 4. Allocate memory for the shellcode
    shellcode_addr = kernel32.VirtualAllocEx(process_handle, 0, len(shellcode), MEM_COMMIT | MEM_RESERVE, 0x40) # PAGE_EXECUTE_READWRITE
    if not shellcode_addr:
        print(f"Error: VirtualAllocEx for shellcode failed. Error code: {kernel32.GetLastError()}")
        kernel32.VirtualFreeEx(process_handle, lua_addr, 0, MEM_RELEASE)
        return

    # 5. Write the shellcode to its allocated memory
    if not kernel32.WriteProcessMemory(process_handle, shellcode_addr, shellcode, len(shellcode), None):
        print(f"Error: WriteProcessMemory for shellcode failed. Error code: {kernel32.GetLastError()}")
        kernel32.VirtualFreeEx(process_handle, lua_addr, 0, MEM_RELEASE)
        kernel32.VirtualFreeEx(process_handle, shellcode_addr, 0, MEM_RELEASE)
        return

    # 6. Create a remote thread to execute the shellcode
    h_thread = kernel32.CreateRemoteThread(process_handle, None, 0, shellcode_addr, 0, 0, None)
    if not h_thread:
        print(f"Error: CreateRemoteThread for shellcode failed. Error code: {kernel32.GetLastError()}")
        kernel32.VirtualFreeEx(process_handle, lua_addr, 0, MEM_RELEASE)
        kernel32.VirtualFreeEx(process_handle, shellcode_addr, 0, MEM_RELEASE)
        return

    # 7. Wait for execution and clean up
    kernel32.WaitForSingleObject(h_thread, -1) # -1 is INFINITE
    kernel32.CloseHandle(h_thread)
    kernel32.VirtualFreeEx(process_handle, lua_addr, 0, MEM_RELEASE)
    kernel32.VirtualFreeEx(process_handle, shellcode_addr, 0, MEM_RELEASE)
    print(f"✅ Lua command sent: {command_string}")

def main():
    dll_path = os.path.abspath(os.path.join(os.path.dirname(__file__), DLL_NAME))
    if not os.path.exists(dll_path):
        print(f"Error: {DLL_NAME} not found at {dll_path}")
        sys.exit(1)

    pid = find_process_id(TARGET_PROCESS)
    if not pid:
        print(f"Error: Process '{TARGET_PROCESS}' not found. Is the game running?")
        sys.exit(1)
    print(f"Found {TARGET_PROCESS} with PID: {pid}")

    h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not h_process:
        print(f"Error: Could not open process (invalid handle). Error code: {kernel32.GetLastError()}")
        sys.exit(1)
    print("Successfully opened a handle to the process.")

    print(f"Attempting to inject {dll_path}...")
    if not inject_dll(h_process, dll_path):
        print("DLL injection failed. Exiting.")
        kernel32.CloseHandle(h_process)
        sys.exit(1)
    print("DLL injected successfully.")

    print("Finding base address of the game executable...")
    base_address = get_module_base_address(h_process, TARGET_PROCESS)
    if not base_address:
        print(f"Error: Could not find the base address for {TARGET_PROCESS}.")
        kernel32.CloseHandle(h_process)
        sys.exit(1)

    lua_exec_address = base_address + FRAME_SCRIPT_EXECUTE_BUFFER_RVA
    print(f"Calculated 'FrameScript_ExecuteBuffer' address (base + RVA): {hex(lua_exec_address)}")

    print("\n--- Interactive Lua Shell ---")
    print("Type Lua commands and press Enter. Type 'exit' or 'quit' to quit.")

    while True:
        try:
            command = input("Lua> ")
            if command.lower() in ('exit', 'quit'):
                break
            if command:
                send_lua_command(h_process, lua_exec_address, command)
        except (EOFError, KeyboardInterrupt):
            print("\nExiting shell.")
            break
        except Exception as e:
            print(f"An error occurred: {e}")
            break

    print("Closing handle to process.")
    kernel32.CloseHandle(h_process)
    print("Done.")

if __name__ == "__main__":
    main()
