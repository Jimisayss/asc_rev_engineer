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
    if not psapi.EnumProcessModulesEx(h_process, ctypes.byref(modules), ctypes.sizeof(modules), ctypes.byref(needed), LIST_MODULES_ALL):
        print(f"Error: EnumProcessModulesEx failed. Error code: {kernel32.GetLastError()}")
        return None

    num_modules = needed.value // ctypes.sizeof(wintypes.HMODULE)
    for i in range(num_modules):
        module_name_buffer = (ctypes.c_char * 256)()
        if psapi.GetModuleBaseNameA(h_process, modules[i], module_name_buffer, ctypes.sizeof(module_name_buffer)):
            if module_name_buffer.value.decode('utf-8', 'ignore').lower() == module_name_to_find.lower():
                return modules[i]
    return None

def send_lua_command(process_handle, func_address, command_string):
    """Wraps VirtualAllocEx, WriteProcessMemory, and CreateRemoteThread to send a Lua command."""
    lua_code_bytes = command_string.encode('ascii') + b'\x00'
    alloc_address = kernel32.VirtualAllocEx(process_handle, 0, len(lua_code_bytes), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
    if not alloc_address:
        print(f"Error: VirtualAllocEx failed. Error code: {kernel32.GetLastError()}")
        return

    if not kernel32.WriteProcessMemory(process_handle, alloc_address, lua_code_bytes, len(lua_code_bytes), None):
        print(f"Error: WriteProcessMemory failed. Error code: {kernel32.GetLastError()}")
        kernel32.VirtualFreeEx(process_handle, alloc_address, 0, MEM_RELEASE)
        return

    h_thread = kernel32.CreateRemoteThread(process_handle, None, 0, func_address, alloc_address, 0, None)
    if not h_thread:
        print(f"Error: CreateRemoteThread failed. Error code: {kernel32.GetLastError()}")
        kernel32.VirtualFreeEx(process_handle, alloc_address, 0, MEM_RELEASE)
        return

    kernel32.WaitForSingleObject(h_thread, -1)
    kernel32.CloseHandle(h_thread)
    kernel32.VirtualFreeEx(process_handle, alloc_address, 0, MEM_RELEASE)
    print(f"✅ Lua command sent: {command_string}")

def main():
    if len(sys.argv) < 2:
        print(f"Usage: python {os.path.basename(sys.argv[0])} \"<your_lua_code_here>\"")
        sys.exit(1)
    lua_command = sys.argv[1]

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

    base_address = get_module_base_address(h_process, TARGET_PROCESS)
    if not base_address:
        print(f"Error: Could not find the base address for {TARGET_PROCESS}.")
        kernel32.CloseHandle(h_process)
        sys.exit(1)

    lua_exec_address = base_address + FRAME_SCRIPT_EXECUTE_BUFFER_RVA
    print(f"Calculated 'FrameScript_ExecuteBuffer' address (base + RVA): {hex(lua_exec_address)}")

    send_lua_command(h_process, lua_exec_address, lua_command)

    kernel32.CloseHandle(h_process)
    print("Done.")

if __name__ == "__main__":
    main()
