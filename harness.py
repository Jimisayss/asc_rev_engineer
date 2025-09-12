import ctypes
from ctypes import wintypes
import psutil
import struct

# --- Windows API Definitions using ctypes ---

# Constants for process access rights
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_OPERATION = 0x0008
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_CREATE_THREAD = 0x0002
PROCESS_ALL_ACCESS = (
    PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION |
    PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD
)

# Constants for memory allocation
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_READWRITE = 0x04

# Function prototypes for kernel32.dll functions
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

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
    """Finds a process by its name and returns its PID."""
    for proc in psutil.process_iter(['pid', 'name']):
        if proc.info['name'] == process_name:
            return proc.info['pid']
    return None

def find_pattern(h_process, base_address, size, pattern):
    """Searches for a byte pattern in the memory of a process."""
    buffer = ctypes.create_string_buffer(size)
    bytes_read = ctypes.c_size_t(0)

    if not kernel32.ReadProcessMemory(h_process, base_address, buffer, size, ctypes.byref(bytes_read)):
        print(f"Error reading process memory: {ctypes.get_last_error()}")
        return None

    found_offset = buffer.raw.find(pattern)

    if found_offset != -1:
        return base_address + found_offset

    return None


def main():
    # --- CONFIGURATION ---
    # The name of the executable to attach to.
    # IMPORTANT: Use the patched executable you created in the previous step.
    PROCESS_NAME = "Ascension_patched.exe"

    # The Lua code you want to execute in the game.
    # The trailing '\x00' is a null terminator, which is crucial for C-style strings.
    LUA_CODE_TO_EXECUTE = b'DEFAULT_CHAT_FRAME:AddMessage("Hello from Python harness!")\x00'

    # ====================================================================================
    # === CRITICAL AREA: These values are based on static analysis and may need tuning ===
    # ====================================================================================
    #
    # This is the byte signature for the start of the target function.
    # I've identified 0x50d170 as the dispatcher function that handles chat commands.
    # This signature is a sequence of bytes from the beginning of that function.
    # It should be unique enough to find the correct function even with ASLR.
    #
    # Original disassembly at 0x50d170:
    # 0x50d170: push ebp
    # 0x50d171: mov ebp, esp
    # 0x50d173: sub esp, 0xde8
    # 0x50d179: push 0xa
    # 0x50d17b: call 0x5191c0
    #
    # Signature bytes: 55 8B EC 83 EC E8 DE 00 00 00 E8
    FUNCTION_SIGNATURE = b'\x55\x8b\xec\x83\xec\xe8\xde\x00\x00\x00\xe8'

    #
    # This is the ctypes function prototype. It describes the function's arguments and return type.
    # Based on my analysis, this function is a standard Lua CFunction.
    # Such functions take one argument: a pointer to the lua_State.
    # We do NOT know where the lua_State is, so we cannot call this function directly.
    #
    # HOWEVER, the dispatcher we found (0x50d170) is the *target of a Lua call*. The function
    # that *makes* the call is what we need. The analysis suggests that there is a higher-level
    # function that might be the true "FrameScript_ExecuteBuffer".
    #
    # For now, this harness is built on the strong assumption that a function with a
    # simple `void(const char*)` prototype exists and is what we should be calling.
    # A function with this signature is the most common pattern for simple script execution.
    #
    # If this does not work, you may need to use a debugger (like x64dbg) on the patched
    # executable to find the correct function that takes a string and executes it,
    # and then determine its arguments to adjust the prototype below.
    #
    # Let's assume a function with this prototype exists and we will try to find it.
    # For the purpose of this harness, I will target the dispatcher function itself,
    # as it's the most solid lead we have. The actual call might fail if the function
    # expects a different setup (like a valid lua_State), but this is the logical next step.
    #
    # A hypothetical `FrameScript_Execute` might look like:
    # FrameScript_Execute_Prototype = ctypes.WINFUNCTYPE(None, ctypes.c_char_p)
    #
    # Let's try to call the dispatcher we found. It's a C-style function that takes a lua_State*.
    # We will pass NULL for the state and see what happens. This is unlikely to work but is
    # the best we can do without dynamic analysis.
    #
    # The actual prototype is likely: int function(lua_State *L)
    # Since we can't create a lua_State, we'll define it as taking a void pointer.
    TARGET_FUNC_PROTOTYPE = ctypes.WINFUNCTYPE(ctypes.c_int, wintypes.LPVOID)


    # --- SCRIPT LOGIC ---
    print(f"Searching for process: {PROCESS_NAME}")
    pid = find_process_by_name(PROCESS_NAME)
    if not pid:
        print(f"Error: Process '{PROCESS_NAME}' not found. Is it running?")
        return

    print(f"Found process with PID: {pid}")

    h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not h_process:
        print(f"Error: Could not open process. Error code: {ctypes.get_last_error()}")
        return

    print("Successfully opened process handle.")

    # In a 32-bit process, we can assume the base address and size.
    # A more robust solution would enumerate modules, but this is a common case.
    base_address = 0x400000
    module_size = 0x800000 # A reasonable size to search

    print(f"Searching for function signature in memory...")
    function_address = find_pattern(h_process, base_address, module_size, FUNCTION_SIGNATURE)

    if not function_address:
        print("Error: Could not find function signature in process memory.")
        print("The game might have been updated, or ASLR is behaving unexpectedly.")
        kernel32.CloseHandle(h_process)
        return

    print(f"Target function found at: {hex(function_address)}")

    # Allocate memory for the Lua code string in the target process
    print(f"Allocating memory for Lua code...")
    mem_addr = kernel32.VirtualAllocEx(h_process, 0, len(LUA_CODE_TO_EXECUTE), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
    if not mem_addr:
        print(f"Error: Could not allocate memory. Error code: {ctypes.get_last_error()}")
        kernel32.CloseHandle(h_process)
        return

    print(f"Memory allocated at: {hex(mem_addr)}")

    # Write the Lua code to the allocated memory
    bytes_written = ctypes.c_size_t(0)
    if not kernel32.WriteProcessMemory(h_process, mem_addr, LUA_CODE_TO_EXECUTE, len(LUA_CODE_TO_EXECUTE), ctypes.byref(bytes_written)):
        print(f"Error: Could not write to process memory. Error code: {ctypes.get_last_error()}")
        kernel32.CloseHandle(h_process)
        return

    print("Successfully wrote Lua code into process memory.")

    # Create the function object from our prototype and the found address
    # THIS IS THE MOST SPECULATIVE PART
    # We are calling a function that expects a `lua_State*` with a NULL pointer.
    # This will likely crash, but it's the furthest we can get with static analysis.
    # The REAL `FrameScript_ExecuteBuffer` is what should be called, but we don't
    # have its address. The user will need to find a function that takes a char*
    # and use its address/signature here.

    print("\n" + "="*60)
    print("!!! ACTION REQUIRED !!!")
    print("The harness is about to call the function. The function signature and")
    print("address are BEST GUESSES. You may need to find the real FrameScript_Execute")
    print("function address using a debugger and update the FUNCTION_SIGNATURE and")
    print("TARGET_FUNC_PROTOTYPE variables in this script.")
    print("The current target is the 'chat command dispatcher' which is NOT")
    print("the correct function to call directly for script execution.")
    print("This call is set up as a demonstration of the method.")
    print("="*60 + "\n")

    # For demonstration, we will NOT call the function to avoid a guaranteed crash.
    # The user should replace `function_address` with the correct one and uncomment the call.
    # target_function = TARGET_FUNC_PROTOTYPE(function_address)
    # print(f"Calling function at {hex(function_address)} with a pointer to our script...")
    # try:
    #     # A hypothetical correct call would be:
    #     # target_function(mem_addr)
    #     # But since we are targeting the wrong function type, we won't call it.
    #     print("Call skipped. Please modify the script with the correct function address/prototype.")
    # except Exception as e:
    #     print(f"An error occurred while calling the function: {e}")


    print("\nHarness finished. If the game did not show the message,")
    print("you will need to perform dynamic analysis to find the correct")
    print("function address and its calling convention.")

    # Clean up the process handle
    kernel32.CloseHandle(h_process)

if __name__ == "__main__":
    main()
