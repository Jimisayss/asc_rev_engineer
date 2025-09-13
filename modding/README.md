# Modding Tools for Ascension.exe

This directory contains tools for modding the Ascension.exe game client.

## Files

- `lua_modloader.c`: The source code for the DLL that patches the game.
- `lua_modloader.dll`: The compiled DLL.
- `injector.py`: A Python script to inject the DLL into the game process.
- `logs/offsets.txt`: A log of memory offsets and patches.

## Usage

### Prerequisites

- **MinGW-w64**: You need a working MinGW-w64 C compiler to build the DLL. You can install it on Debian/Ubuntu with `sudo apt-get install mingw-w64`.

### Compilation

1.  **Compile the DLL**:
    Open a terminal or command prompt and run the following command from the `modding` directory:
    ```bash
    x86_64-w64-mingw32-gcc -shared -o lua_modloader.dll lua_modloader.c -lpsapi
    ```
    *Note: The exact name of the gcc executable may vary depending on your system.*
2.  **Run the game**:
    - Start `Ascension.exe`.
3.  **Run the injector**:
    ```bash
    python injector.py
    ```

The injector will find the game process and inject the DLL. A message box should appear in the game confirming that the patch was applied.
