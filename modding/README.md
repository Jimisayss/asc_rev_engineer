# Modding Tools for Ascension.exe

This directory contains tools for modding the Ascension.exe game client.

## Files

- `lua_modloader.c`: The source code for the DLL that patches the game's memory.
- `lua_modloader.dll`: The compiled DLL (you must compile this yourself).
- `injector.py`: A Python script to inject the DLL and open an interactive Lua shell.
- `send_lua_command.py`: A Python script to send a single, non-interactive Lua command to the game.
- `logs/offsets.txt`: A log of memory offsets and patches.

## How It Works

1.  `lua_modloader.dll`: When injected, this DLL patches a specific memory offset in `Ascension.exe` to bypass a script execution restriction. Upon success, it creates a log file at `C:\modding_log.txt` and displays an in-game message box.
2.  `injector.py`: This script finds the `Ascension.exe` process, injects the DLL, and then provides an interactive terminal for sending Lua commands directly to the game.
3.  `send_lua_command.py`: This is a lightweight script for sending a single Lua command without the interactive shell.

## Usage

### 1. Prerequisites

- **Python 3**: With `psutil` installed (`pip install psutil`).
- **MinGW-w64**: A C compiler to build the DLL. On Debian/Ubuntu: `sudo apt-get install mingw-w64`.
- **Ascension.exe**: The game client must be running.

### 2. Compile the DLL

From within the `modding` directory, run the following command:
```bash
x86_64-w64-mingw32-gcc -shared -o lua_modloader.dll lua_modloader.c -lpsapi
```
*Note: The exact name of the gcc executable may vary depending on your system.*

### 3. Using the Interactive Lua Shell

The main injector script now includes an interactive shell. This is the recommended way to test scripts.

1.  **Run the game**, `Ascension.exe`.
2.  **Run the injector**:
    ```bash
    python injector.py
    ```
3.  The script will inject the DLL. A confirmation box should appear in-game.
4.  The terminal will then display a `Lua>` prompt. You can now type any Lua code and press Enter to have it execute inside the game.
    ```
    Lua> print("Hello from the interactive shell!")
    ```
5.  Type `exit` or `quit` and press Enter to close the shell and detach from the process.

### 4. Sending a Single Command

If you need to send a single, non-interactive command, use `send_lua_command.py`. This is useful for automation or quick tests.

1.  **Run the game**, `Ascension.exe`.
2.  **Ensure the DLL has been injected at least once** using `injector.py` since the game was started. The patch needs to be active.
3.  **Run the script** with your Lua code as a command-line argument:
    ```bash
    python send_lua_command.py "your_lua_code_here()"
    ```
    **Example:**
    ```bash
    python send_lua_command.py "print('This is a single command.')"
    ```

### Important Notes

- The address for the `FrameScript_ExecuteBuffer` function is currently hardcoded in the Python scripts as a placeholder constant, `FRAME_SCRIPT_EXECUTE_BUFFER_RVA`. For this to work on a real target, this offset would need to be accurate.
- All tools require the game to be running.
