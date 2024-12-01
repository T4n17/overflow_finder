# Angr Overflow Finder

A Python-based tool that automatically discovers and exploits buffer overflow vulnerabilities in binary executables using symbolic execution through the Angr framework.

## Description

This tool uses symbolic execution to automatically:
- Detect potential buffer overflow vulnerabilities
- Generate exploit payloads
- Help identify security weaknesses in binary executables

The script leverages Angr's advanced binary analysis capabilities to find program states where the instruction pointer (RIP) can be controlled, indicating a potential buffer overflow vulnerability.

## Requirements

- Python 3.6 or higher
- Angr framework
- Claripy (included with Angr)

### Installing Dependencies

1. Create a virtual environment (recommended):
```bash
python3 -m venv env
source env/bin/activate
```

2. Install Angr:
```bash
pip install angr
```

For more information about Angr, visit: https://angr.io

## Usage

1. Clone the repository:
```bash
git clone http://github.com/t4n17/overflow_finder
cd overflow_finder
```

2. Activate your Python environment:
```bash
source env/bin/activate
```

3. Configure the script for your target binary:
   - Set the correct binary path in the script
   - Adjust the buffer size if needed (default is 90 bytes)
   - Modify target addresses

4. Run the script:
```bash
python3 overflow_finder.py
```

5. Test the generated exploit:
```bash
./vuln < input.txt
```

## Configuration

The script can be configured by modifying these key parameters:
- `bitvector_size`: Size of the input buffer (default: 90*8 bits)
- `hook_addr`: Address of the input function to hook
- `target_addr`: Address you want to reach with the overflow

## How It Works

1. The script creates a symbolic buffer to represent user input
2. It hooks the program's input function (e.g., scanf) to use this symbolic buffer
3. Using symbolic execution, it explores program states until finding one where the instruction pointer can be controlled
4. When found, it generates concrete input values that trigger the overflow
5. The exploit payload is saved to `input.txt`

## Safety Notice

This tool is intended for educational purposes and authorized security testing only. Do not use it against systems you don't own or don't have permission to test.
