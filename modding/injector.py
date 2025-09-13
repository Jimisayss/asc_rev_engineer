import ctypes
import sys
import os
import psutil

# Constants from the Windows API
PROCESS_ALL_ACCESS = (0x000F0000 | 0x00100000 | 0xFFF)
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_READWRITE = 0x04

# Kernel32 functions
kernel32 = ctypes.windll.kernel32
LoadLibraryA = kernel32.LoadLibraryA
VirtualAllocEx = kernel32.VirtualAllocEx
WriteProcessMemory = kernel32.WriteProcessMemory
CreateRemoteThread = kernel32.CreateRemoteThread
GetProcAddress = kernel32.GetProcAddress
GetModuleHandleA = kernel32.GetModuleHandleA


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

    if not os.path.exists(dll_path):
        print(f"Error: {dll_name} not found at {dll_path}")
        print("Please compile lua_modloader.c first (e.g., gcc -shared -o lua_modloader.dll lua_modloader.c)")
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
    alloc_address = VirtualAllocEx(h_process, 0, len(dll_path_bytes) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
    if not alloc_address:
        print(f"Error: Could not allocate memory in the target process. Error code: {kernel32.GetLastError()}")
        kernel32.CloseHandle(h_process)
        sys.exit(1)
    print(f"Allocated memory at address: {hex(alloc_address)}")

    # 4. Write the DLL path to the allocated memory
    bytes_written = ctypes.c_size_t(0)
    if not WriteProcessMemory(h_process, alloc_address, dll_path_bytes, len(dll_path_bytes) + 1, ctypes.byref(bytes_written)):
        print(f"Error: Could not write to process memory. Error code: {kernel32.GetLastError()}")
        kernel32.CloseHandle(h_process)
        sys.exit(1)
    print("Successfully wrote DLL path to process memory.")

    # 5. Get the address of LoadLibraryA
    load_library_addr = GetProcAddress(GetModuleHandleA(b"kernel32.dll"), b"LoadLibraryA")
    if not load_library_addr:
        print(f"Error: Could not find LoadLibraryA address. Error code: {kernel32.GetLastError()}")
        kernel32.CloseHandle(h_process)
        sys.exit(1)
    print(f"Found LoadLibraryA at address: {hex(load_library_addr)}")

    # 6. Create a remote thread to load the DLL
    h_thread = CreateRemoteThread(h_process, None, 0, load_library_addr, alloc_address, 0, None)
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
