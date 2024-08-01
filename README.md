# Angr Overflow Finder
A configurable Python script to automatically find overflows and potentially generate input to trigger them
# Requirements:
The script needs to run in a python3 environment with angr installed\
Look here: https://angr.io
# Usage:
- Clone the repository: `git clone http://github.com/t4n17/overflow_finder`
- Access to the Python environment: `source bin/activate`
- Configure the script according to the vulnerable executable
- Run the script: `python3 overflow_finder.py`
- Test the generated input: `./vuln < input.txt`
