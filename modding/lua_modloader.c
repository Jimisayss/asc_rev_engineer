#include <windows.h>
#include <psapi.h>

// Define the patch details
#define PATCH_OFFSET 0x50D242
#define PATCH_SIZE 2
unsigned char patch[PATCH_SIZE] = {0x90, 0x90}; // NOP, NOP

// The thread that will perform the patching
DWORD WINAPI PatchThread(LPVOID lpParam) {
    // 1. Wait for the game to stabilize
    Sleep(2000);

    // 2. Get the module base address of Ascension.exe
    HMODULE hModule = GetModuleHandleA("Ascension.exe");
    if (hModule == NULL) {
        MessageBoxA(NULL, "Failed to get module handle for Ascension.exe", "Mod Loader Error", MB_OK | MB_ICONERROR);
        return 1;
    }

    // 3. Calculate the patch address
    DWORD_PTR patchAddress = (DWORD_PTR)hModule + PATCH_OFFSET;

    // 4. Apply the memory patch
    DWORD oldProtect;
    if (VirtualProtect((LPVOID)patchAddress, PATCH_SIZE, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        // Write the patch
        memcpy((void*)patchAddress, patch, PATCH_SIZE);

        // Restore the original memory protection
        VirtualProtect((LPVOID)patchAddress, PATCH_SIZE, oldProtect, &oldProtect);

        // Flush the instruction cache
        FlushInstructionCache(GetCurrentProcess(), (LPCVOID)patchAddress, PATCH_SIZE);

        MessageBoxA(NULL, "Memory patch applied successfully!", "Mod Loader", MB_OK | MB_ICONINFORMATION);
    } else {
        MessageBoxA(NULL, "Failed to change memory protection.", "Mod Loader Error", MB_OK | MB_ICONERROR);
        return 1;
    }

    return 0;
}

// DllMain entry point
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            // Disable thread library calls for performance
            DisableThreadLibraryCalls(hinstDLL);
            // Spawn a thread to do the patching
            HANDLE hThread = CreateThread(NULL, 0, PatchThread, NULL, 0, NULL);
            if (hThread) {
                CloseHandle(hThread);
            }
            break;
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}
