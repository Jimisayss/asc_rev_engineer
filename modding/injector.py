import ctypes
import sys
import os
import psutil
from ctypes import wintypes

# Constants from the Windows API
PROCESS_ALL_ACCESS = (0x000F0000 | 0x00100000 | 0xFFF)
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_READWRITE = 0x04

# Kernel32 functions
kernel32 = ctypes.windll.kernel32

# Define argtypes and restypes for WinAPI functions for 64-bit compatibility
kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.OpenProcess.restype = wintypes.HANDLE

kernel32.VirtualAllocEx.argtypes = [wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD]
kernel32.VirtualAllocEx.restype = wintypes.LPVOID

kernel32.WriteProcessMemory.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.LPCVOID, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
kernel32.WriteProcessMemory.restype = wintypes.BOOL

kernel32.GetModuleHandleA.argtypes = [wintypes.LPCSTR]
kernel32.GetModuleHandleA.restype = wintypes.HMODULE

kernel32.GetProcAddress.argtypes = [wintypes.HMODULE, wintypes.LPCSTR]
kernel32.GetProcAddress.restype = ctypes.c_void_p

kernel32.CreateRemoteThread.argtypes = [wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t, ctypes.c_void_p, wintypes.LPVOID, wintypes.DWORD, wintypes.LPVOID]
kernel32.CreateRemoteThread.restype = wintypes.HANDLE

kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL


def find_process_id(process_name):
    """Finds the process ID for a given process name."""
    for proc in psutil.process_iter(['pid', 'name']):
        if proc.info['name'] == process_name:
            return proc.info['pid']
    return None

def main():
    target_process = "Ascension.exe"
    dll_name = "lua_modloader.dll"
    dll_path = os.path.abspath(os.path.join(os.path.dirname(__file__), dll_name))

    if not os..path.exists(dll_path):
        print(f"Error: {dll_name} not found at {dll_path}")
        print("Please compile lua_modloader.c first. See README.md for instructions.")
        sys.exit(1)

    print(f"Attempting to inject {dll_path} into {target_process}...")

    # 1. Find the process ID
    pid = find_process_id(target_process)
    if not pid:
        print(f"Error: Process '{target_process}' not found.")
        sys.exit(1)
    print(f"Found {target_process} with PID: {pid}")

    # 2. Get a handle to the process
    h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not h_process:
        print(f"Error: Could not open process. Error code: {kernel32.GetLastError()}")
        sys.exit(1)
    print("Successfully opened a handle to the process.")

    # 3. Allocate memory for the DLL path
    dll_path_bytes = dll_path.encode('ascii')
    alloc_address = kernel32.VirtualAllocEx(h_process, 0, len(dll_path_bytes) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
    if not alloc_address:
        print(f"Error: Could not allocate memory in the target process. Error code: {kernel32.GetLastError()}")
        kernel32.CloseHandle(h_process)
        sys.exit(1)
    print(f"Allocated memory at address: {hex(alloc_address)}")

    # 4. Write the DLL path to the allocated memory
    bytes_written = ctypes.c_size_t(0)
    if not kernel32.WriteProcessMemory(h_process, alloc_address, dll_path_bytes, len(dll_path_bytes) + 1, ctypes.byref(bytes_written)):
        print(f"Error: Could not write to process memory. Error code: {kernel32.GetLastError()}")
        kernel32.CloseHandle(h_process)
        sys.exit(1)
    print("Successfully wrote DLL path to process memory.")

    # 5. Get the address of LoadLibraryA
    h_kernel32 = kernel32.GetModuleHandleA(b"kernel32.dll")
    if not h_kernel32:
        print(f"Error: Could not get handle for kernel32.dll. Error code: {kernel32.GetLastError()}")
        kernel32.CloseHandle(h_process)
        sys.exit(1)

    load_library_addr = kernel32.GetProcAddress(h_kernel32, b"LoadLibraryA")
    if not load_library_addr:
        print(f"Error: Could not find LoadLibraryA address. Error code: {kernel32.GetLastError()}")
        kernel32.CloseHandle(h_process)
        sys.exit(1)
    print(f"Found LoadLibraryA at address: {hex(load_library_addr)}")

    # 6. Create a remote thread to load the DLL
    h_thread = kernel32.CreateRemoteThread(h_process, None, 0, load_library_addr, alloc_address, 0, None)
    if not h_thread:
        print(f"Error: Could not create remote thread. Error code: {kernel32.GetLastError()}")
        kernel32.CloseHandle(h_process)
        sys.exit(1)
    print("Successfully created remote thread. DLL should be injected.")

    # 7. Clean up
    kernel32.CloseHandle(h_thread)
    kernel32.CloseHandle(h_process)
    print("Injection complete. Handles closed.")


if __name__ == "__main__":
    main()
