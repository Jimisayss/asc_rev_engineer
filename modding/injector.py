import ctypes
import sys
import os
import psutil
import platform

# Constants from the Windows API
PROCESS_ALL_ACCESS = (0x000F0000 | 0x00100000 | 0xFFF)
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_READWRITE = 0x04

# Kernel32 functions
# Use use_last_error=True to be able to call GetLastError()
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

def check_architecture_mismatch(pid):
    """Checks if the Python interpreter and target process architectures match."""
    try:
        proc = psutil.Process(pid)
        # This is a bit of a hack. On Windows, psutil's exe() for a 32-bit process
        # running on a 64-bit system might point to a 32-bit PE. We can check the
        # magic number of the PE header.
        # Another way is to check the machine type.
        # A simpler proxy is to check if python is 64-bit and the process is 32-bit.
        python_arch = platform.architecture()[0] # '32bit' or '64bit'

        # Using IsWow64Process to check if the target is 32-bit on a 64-bit OS
        is_wow64 = ctypes.c_bool()
        h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
        if not h_process:
            return # Cannot check

        if ctypes.windll.kernel32.IsWow64Process(h_process, ctypes.byref(is_wow64)):
            target_arch = "32bit" if is_wow64.value else "64bit"
            if python_arch != target_arch:
                print(f"WARNING: Architecture mismatch detected!")
                print(f"         Python is {python_arch}, but target process is {target_arch}.")
                print(f"         Injection is likely to fail.")
                print(f"         Please use a {target_arch} version of Python.")
        kernel32.CloseHandle(h_process)

    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass # Can't check, so just continue.

def find_process_id(process_name):
    """Finds the process ID for a given process name."""
    for proc in psutil.process_iter(['pid', 'name']):
        if proc.info['name'] == process_name:
            return proc.info['pid']
    return None

def main():
    target_process = "game_client.exe"
    dll_name = "mod_loader.dll"
    dll_path = os.path.abspath(os.path.join(os.path.dirname(__file__), dll_name))

    if not os.path.exists(dll_path):
        print(f"Error: {dll_name} not found at {dll_path}")
        print("Please compile mod_loader.c first (e.g., gcc -m32 -shared -o mod_loader.dll mod_loader.c)")
        sys.exit(1)

    print(f"Attempting to inject {dll_path} into {target_process}...")

    # 1. Find the process ID
    pid = find_process_id(target_process)
    if not pid:
        print(f"Error: Process '{target_process}' not found.")
        sys.exit(1)
    print(f"Found {target_process} with PID: {pid}")

    # Check for architecture mismatch
    check_architecture_mismatch(pid)

    # 2. Get a handle to the process
    h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not h_process:
        print(f"Error: Could not open process. Error code: {ctypes.get_last_error()}")
        sys.exit(1)
    print("Successfully opened a handle to the process.")

    # 3. Allocate memory for the DLL path
    dll_path_bytes = dll_path.encode('ascii')
    alloc_address = kernel32.VirtualAllocEx(h_process, 0, len(dll_path_bytes) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
    if not alloc_address:
        print(f"Error: Could not allocate memory in the target process. Error code: {ctypes.get_last_error()}")
        kernel32.CloseHandle(h_process)
        sys.exit(1)
    print(f"Allocated memory at address: {hex(alloc_address)}")

    # 4. Write the DLL path to the allocated memory
    bytes_written = ctypes.c_size_t(0)
    if not kernel32.WriteProcessMemory(h_process, alloc_address, dll_path_bytes, len(dll_path_bytes) + 1, ctypes.byref(bytes_written)):
        print(f"Error: Could not write to process memory. Error code: {ctypes.get_last_error()}")
        kernel32.CloseHandle(h_process)
        sys.exit(1)
    print("Successfully wrote DLL path to process memory.")

    # 5. Get the address of LoadLibraryA
    # This is a more robust way to get the function address.
    # We get the handle to kernel32.dll from the currently loaded libraries in our own process.
    # The address of LoadLibraryA will be the same in the target process (for the same architecture).
    kernel32_handle = kernel32._handle
    load_library_addr = kernel32.GetProcAddress(kernel32_handle, b"LoadLibraryA")
    if not load_library_addr:
        print(f"Error: Could not find LoadLibraryA address. Error code: {ctypes.get_last_error()}")
        kernel32.CloseHandle(h_process)
        sys.exit(1)
    print(f"Found LoadLibraryA at address: {hex(load_library_addr)}")

    # 6. Create a remote thread to load the DLL
    h_thread = kernel32.CreateRemoteThread(h_process, None, 0, load_library_addr, alloc_address, 0, None)
    if not h_thread:
        print(f"Error: Could not create remote thread. Error code: {ctypes.get_last_error()}")
        kernel32.CloseHandle(h_process)
        sys.exit(1)
    print("Successfully created remote thread. DLL should be injected.")

    # 7. Clean up
    kernel32.CloseHandle(h_thread)
    kernel32.CloseHandle(h_process)
    print("Injection complete. Handles closed.")


if __name__ == "__main__":
    main()
