# Modding Tools for game_client.exe

This directory contains tools for creating a scripting plugin for the game_client.exe application.

## Files

- `mod_loader.c`: The source code for the DLL that enables the scripting interface.
- `mod_loader.dll`: The compiled 32-bit DLL.
- `injector.py`: A Python script to load the DLL into the game process.
- `logs/offsets.txt`: A log of memory offsets and patches.

## Usage

### Prerequisites

- **Python 3 (32-bit)**: You **must** use a 32-bit version of Python to run the injector script, as the target application is 32-bit. You can check your Python architecture by running `python -c "import platform; print(platform.architecture())"`.
- **MinGW-w64 (for 32-bit)**: You need a working MinGW C compiler capable of producing 32-bit DLLs. On 64-bit systems, this often requires specific packages (e.g., `gcc-multilib` on Debian/Ubuntu).

### Compilation and Execution

1.  **Compile the DLL**:
    Open a terminal or command prompt in the `modding` directory and run the following command. This creates the 32-bit `mod_loader.dll`.
    ```bash
    gcc -m32 -shared -o mod_loader.dll mod_loader.c -lpsapi
    ```
    *Note: If you are on a 64-bit system, you may need to use a specific compiler like `i686-w64-mingw32-gcc` if the default `gcc` does not support the `-m32` flag.*

2.  **Run the game**:
    - Start `game_client.exe`.

3.  **Run the injector**:
    - Make sure you are using a **32-bit** Python interpreter.
    ```bash
    python injector.py
    ```

The injector will find the game process and load the DLL. A message box should appear in the game confirming that the mod loader is active.
