# Ascension.exe Lua Runner
# Attaches to the patched process, finds the script executor, and runs Lua code.

import ctypes
from ctypes import wintypes
import json
import os
import psutil
import struct
import time
import sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

# --- Configuration ---
TARGET_PROCESS = "Ascension_patched.exe"
LUA_SCRIPT = b'DEFAULT_CHAT_FRAME:AddMessage("Jules\'s Lua Unlocker Active!")\0'
ANALYSIS_DIR = "analysis"
LOG_FILE = os.path.join(ANALYSIS_DIR, "run_log.json")
DISPATCHER_RVA = 0x50D170 - 0x400000
SEARCH_STRINGS = [b"SendChatMessage", b"DEFAULT_CHAT_FRAME"]

# --- Platform Specific Setup ---
if sys.platform == "win32":
    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
    PROCESS_ALL_ACCESS = 0x1F0FFF
    MEM_COMMIT_RESERVE = 0x3000
    MEM_RELEASE = 0x8000
    PAGE_READWRITE = 0x04
    INFINITE = 0xFFFFFFFF
    LPVOID, DWORD, SIZE_T, LPCSTR = ctypes.c_void_p, wintypes.DWORD, ctypes.c_size_t, wintypes.LPCSTR

    # Function Prototypes
    kernel32.OpenProcess.restype, kernel32.OpenProcess.argtypes = wintypes.HANDLE, [DWORD, wintypes.BOOL, DWORD]
    kernel32.CloseHandle.restype, kernel32.CloseHandle.argtypes = wintypes.BOOL, [wintypes.HANDLE]
    kernel32.ReadProcessMemory.restype, kernel32.ReadProcessMemory.argtypes = wintypes.BOOL, [wintypes.HANDLE, LPVOID, LPVOID, SIZE_T, ctypes.POINTER(SIZE_T)]
    kernel32.VirtualAllocEx.restype, kernel32.VirtualAllocEx.argtypes = LPVOID, [wintypes.HANDLE, LPVOID, SIZE_T, DWORD, DWORD]
    kernel32.VirtualFreeEx.restype, kernel32.VirtualFreeEx.argtypes = wintypes.BOOL, [wintypes.HANDLE, LPVOID, SIZE_T, DWORD]
    kernel32.WriteProcessMemory.restype, kernel32.WriteProcessMemory.argtypes = wintypes.BOOL, [wintypes.HANDLE, LPVOID, LPVOID, SIZE_T, ctypes.POINTER(SIZE_T)]
    kernel32.CreateRemoteThread.restype, kernel32.CreateRemoteThread.argtypes = wintypes.HANDLE, [wintypes.HANDLE, LPVOID, SIZE_T, LPVOID, LPVOID, DWORD, LPVOID]
    kernel32.WaitForSingleObject.restype, kernel32.WaitForSingleObject.argtypes = DWORD, [wintypes.HANDLE, DWORD]
else:
    kernel32 = None

# --- Helper Classes & Functions ---

class ProcessManager:
    def __init__(self, process_name):
        self.process_name = process_name
        self.process, self.pid, self.handle, self.base_address = None, None, None, None
        self.log_data = []
        if sys.platform != "win32": return
        self._find_process()
        self._open_handle()
        self._find_base_address()

    def _find_process(self):
        for proc in psutil.process_iter(['pid', 'name']):
            if proc.info['name'].lower() == self.process_name.lower():
                self.process, self.pid = proc, proc.info['pid']
                self.log_data.append({"step": "Find Process", "pid": self.pid, "status": "Success"})
                return
        raise RuntimeError(f"Process '{self.process_name}' not found.")

    def _open_handle(self):
        self.handle = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, self.pid)
        if not self.handle: raise ctypes.WinError(ctypes.get_last_error())
        self.log_data.append({"step": "Open Handle", "handle": self.handle, "status": "Success"})

    def _find_base_address(self):
        try:
            self.base_address = self.process.memory_maps()[0].addr
            self.log_data.append({"step": "Find Base Address", "address": hex(self.base_address), "status": "Success"})
        except (psutil.AccessDenied, IndexError) as e:
            raise RuntimeError(f"Could not find base address: {e}")

    def read_memory(self, address, size):
        buffer = ctypes.create_string_buffer(size)
        bytes_read = SIZE_T(0)
        if kernel32.ReadProcessMemory(self.handle, address, buffer, size, ctypes.byref(bytes_read)):
            return buffer.raw[:bytes_read.value]
        return None

    def inject_and_execute(self, executor_addr, script_bytes):
        self.log_data.append({"step": "Injection Start", "executor_address": hex(executor_addr)})
        mem_addr, thread_handle = None, None
        try:
            script_len = len(script_bytes)
            mem_addr = kernel32.VirtualAllocEx(self.handle, 0, script_len, MEM_COMMIT_RESERVE, PAGE_READWRITE)
            if not mem_addr: raise ctypes.WinError(ctypes.get_last_error())
            self.log_data.append({"step": "Allocate Memory", "address": hex(mem_addr), "size": script_len, "status": "Success"})

            bytes_written = SIZE_T(0)
            if not kernel32.WriteProcessMemory(self.handle, mem_addr, script_bytes, script_len, ctypes.byref(bytes_written)):
                raise ctypes.WinError(ctypes.get_last_error())
            self.log_data.append({"step": "Write Memory", "bytes_written": bytes_written.value, "status": "Success"})

            thread_handle = kernel32.CreateRemoteThread(self.handle, None, 0, executor_addr, mem_addr, 0, None)
            if not thread_handle: raise ctypes.WinError(ctypes.get_last_error())
            self.log_data.append({"step": "Create Thread", "handle": thread_handle, "status": "Success"})

            kernel32.WaitForSingleObject(thread_handle, INFINITE)
            self.log_data.append({"step": "Wait For Thread", "status": "Success"})
        finally:
            if thread_handle: kernel32.CloseHandle(thread_handle)
            if mem_addr:
                kernel32.VirtualFreeEx(self.handle, mem_addr, 0, MEM_RELEASE)
                self.log_data.append({"step": "Free Memory", "address": hex(mem_addr), "status": "Success"})

    def close(self):
        if self.handle: kernel32.CloseHandle(self.handle)

class FunctionFinder:
    def __init__(self, pm):
        self.pm = pm
        self.cs = Cs(CS_ARCH_X86, CS_MODE_32)
        self.cs.detail = True
        self.string_locations = {}
        self.xrefs = {}
        self.candidates = {}
        self.memory_cache = {}

    def _get_memory_region(self, region_name):
        if region_name in self.memory_cache:
            return self.memory_cache[region_name]
        for mmap in self.pm.process.memory_maps():
            if mmap.path and self.pm.process_name in mmap.path:
                if region_name in mmap.path: # A simplification, usually check section names
                    mem = self.pm.read_memory(mmap.addr, mmap.size)
                    if mem:
                        self.memory_cache[region_name] = (mem, mmap.addr)
                        return mem, mmap.addr
        # Fallback to full scan if no named section found
        exe_map = self.pm.process.memory_maps()[0]
        mem = self.pm.read_memory(exe_map.addr, exe_map.size)
        self.memory_cache['full'] = (mem, exe_map.addr)
        return mem, exe_map.addr

    def find_executor(self):
        print("\n--- Starting Dynamic Function Discovery ---")
        self._find_strings()
        if not self.string_locations: raise RuntimeError("Could not find any of the search strings.")
        self._find_string_xrefs()
        if not self.xrefs: raise RuntimeError("Could not find any cross-references to the search strings.")
        self._analyze_candidates()
        if not self.candidates: raise RuntimeError("Found xrefs but could not identify candidate functions.")

        # In a real scenario, we would score candidates. For now, we select the first one.
        best_candidate_addr = list(self.candidates.keys())[0]
        print(f"\n--- Selected best candidate: {hex(best_candidate_addr)} ---")
        self.pm.log_data.append({"step": "Select Best Candidate", "address": hex(best_candidate_addr), "details": self.candidates[best_candidate_addr]})
        return best_candidate_addr

    def _find_strings(self):
        print("1. Scanning for key strings...")
        mem, base_addr = self._get_memory_region('.rdata') # Assume strings are in .rdata
        if not mem: return
        for s in SEARCH_STRINGS:
            offset = mem.find(s)
            if offset != -1:
                addr = base_addr + offset
                self.string_locations[s.decode()] = addr
                print(f"  - Found '{s.decode()}' at {hex(addr)}")
        self.pm.log_data.append({"step": "Find Strings", "locations": {k: hex(v) for k, v in self.string_locations.items()}})

    def _find_string_xrefs(self):
        print("2. Scanning for cross-references to strings...")
        mem, base_addr = self._get_memory_region('.text') # Code is in .text
        if not mem: return
        for name, addr in self.string_locations.items():
            search_bytes = b'\x68' + addr.to_bytes(4, 'little')  # PUSH <addr>
            offset = 0
            while (offset := mem.find(search_bytes, offset)) != -1:
                xref_addr = base_addr + offset
                if name not in self.xrefs: self.xrefs[name] = []
                self.xrefs[name].append(xref_addr)
                print(f"  - Found xref to '{name}' at {hex(xref_addr)}")
                offset += 1
        self.pm.log_data.append({"step": "Find Xrefs", "xrefs": {k: [hex(x) for x in v] for k, v in self.xrefs.items()}})

    def _analyze_candidates(self):
        print("3. Analyzing function candidates from xrefs...")
        for name, addrs in self.xrefs.items():
            for addr in addrs:
                func_start = self._find_function_start(addr)
                if func_start and func_start not in self.candidates:
                    print(f"  - Analyzing new candidate at {hex(func_start)} (from xref to '{name}')")
                    self.candidates[func_start] = {
                        "reason": f"Contains xref to '{name}' at {hex(addr)}",
                        "prototype_analysis": self._analyze_call_sites(func_start)
                    }

    def _find_function_start(self, addr, search_range=1024):
        prologue = b'\x55\x8b\xec'  # PUSH EBP; MOV EBP, ESP
        try:
            mem_chunk = self.pm.read_memory(addr - search_range, search_range)
            if mem_chunk:
                if (prologue_offset := mem_chunk.rfind(prologue)) != -1:
                    return addr - search_range + prologue_offset
        except: pass
        return None

    def _analyze_call_sites(self, func_addr):
        print(f"    - Searching for call sites to {hex(func_addr)}")
        analysis_results = []
        mem, base_addr = self._get_memory_region('.text')
        if not mem: return analysis_results

        offset = 0
        while (offset := mem.find(b'\xe8', offset)) != -1: # CALL rel32
            call_addr = base_addr + offset
            rel_offset = struct.unpack('<i', mem[offset+1:offset+5])[0]
            target_addr = call_addr + 5 + rel_offset

            if target_addr == func_addr:
                print(f"      - Found call site at {hex(call_addr)}")
                # Disassemble preceding instructions for context
                preceding_bytes = self.pm.read_memory(call_addr - 20, 20)
                disassembly = []
                if preceding_bytes:
                    for i in self.cs.disasm(preceding_bytes, call_addr - 20):
                        disassembly.append(f"0x{i.address:x}:\t{i.mnemonic}\t{i.op_str}")
                analysis_results.append({
                    "call_site": hex(call_addr),
                    "stack_args_disassembly": disassembly
                })
            offset += 1
        return analysis_results

def main():
    if sys.platform != "win32":
        print("This script is designed to run on Windows. Execution cannot proceed on this platform.")
        return

    pm = None
    log_data = {}
    try:
        pm = ProcessManager(TARGET_PROCESS)
        finder = FunctionFinder(pm)
        executor_address = finder.find_executor()

        print(f"\n--- EXECUTION ---")
        print(f"Attempting to inject and run script at {hex(executor_address)}")
        pm.inject_and_execute(executor_address, LUA_SCRIPT)
        print("\nInjection successful!")
        log_data["status"] = "Success"

    except (RuntimeError, ctypes.WinError, psutil.Error) as e:
        print(f"\nFATAL ERROR: {e}")
        log_data["status"] = "Failed"; log_data["error"] = str(e)
    finally:
        if pm:
            log_data["run_log"] = pm.log_data
            pm.close()
        if not os.path.exists(ANALYSIS_DIR): os.makedirs(ANALYSIS_DIR)
        with open(LOG_FILE, 'w') as f: json.dump(log_data, f, indent=4)
        print(f"\nLog data written to '{LOG_FILE}'.")

if __name__ == "__main__":
    main()
