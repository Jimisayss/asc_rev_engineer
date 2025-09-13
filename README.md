# Ascension.exe Lua Unlocker

This project provides a suite of tools to reverse engineer and patch `Ascension.exe`, a hypothetical x86 game client. The goal is to bypass a security check that restricts the execution of arbitrary Lua scripts.

## The Problem

The `Ascension.exe` binary contains a security check that validates Lua scripts before execution. This is likely intended to prevent cheating or unauthorized modifications to the game's UI and behavior. The check is implemented as a conditional jump (`JNE`) that diverts program flow if the script is not authorized.

## The Solution: Dynamic Patching

Instead of relying on a static address (RVA) which can change between game versions, this patcher uses a dynamic **signature scan** to locate the security check.

### 1. Signature Identification

The target code block was identified and analyzed to find a unique byte pattern:

```assembly
    TEST AL, AL        ; Checks the result of a previous function call
    JNE <offset>       ; The security check jump (if not authorized, jump away)
    PUSH <address>     ; Prepares an argument for a function call
    PUSH EBX           ; Saves a register
```

This sequence translates to the following regular expression byte pattern, which is used for the scan:
`b'\\x84\\xc0\\x75\\x17\\x68.{4}\\x53'`

### 2. The Patch

The patcher script (`patcher.py`) scans the binary for this signature. Once found, it overwrites the 2-byte `JNE` instruction (`75 17`) with two `NOP` (No Operation) instructions (`90 90`). This effectively disables the jump, forcing the program to always continue down the authorized code path.

## How to Use the Tools

### Prerequisites
Install the necessary Python libraries:
```bash
pip install -r requirements.txt
```

### Step 1: Scan for the Signature (Optional)
You can use `sigscan.py` to check if a binary contains the protection signature and find its location.

```bash
python3 sigscan.py Ascension.exe
```

### Step 2: Patch the Executable
Run the patcher to create the modified executable.

```bash
python3 patcher.py
```
This will produce `Ascension_patched.exe`.

### Step 3: Run the Patched Game
The `runner.py` script is a proof-of-concept injector that demonstrates how to execute a Lua script in the patched game (Windows only). It dynamically finds the `FrameScript_Execute` function and calls it with a custom script.

```bash
# Launch Ascension_patched.exe
python3 runner.py
```

## Included Files

- `Ascension.exe`: The original target binary.
- `patcher.py`: The main script. Scans for the signature and applies the patch.
- `runner.py`: A script to run code in the patched game (Windows-only).
- `sigscan.py`: A standalone utility to find the patch signature.
- `recon.py`: Performs initial static analysis (generates `imports.json`, `strings.json`).
- `/analysis/`: Directory for analysis output.
  - `strings_dump.txt`: Human-readable list of interesting strings found.
  - `functions_dump.txt`: Details about the patched function.
