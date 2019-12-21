#Identify the most commonly called functions and sort by max count.
#@author Don C. Weber (@cutaway)
#@category References
#@keybinding 
#@menupath 
#@toolbar 

import ghidra.app.script.GhidraScript as GS
import ghidra.program.model.listing.Function

##########################
# Global variables
##########################
DEBUG = 0
progname = currentProgram.getName()
scriptname = "References to Functions Count Sorted"

##########################
# Processing Functions
##########################

## getFunctions: return a list of all functions
def getFunctions():
    if DEBUG > 0: print("DEBUG: in getFunctions")
    funcs = []
    inc0  = 0

    # Get the first function
    funcs.append(getFirstFunction())

    # Use the first function to walk thru the rest of the functions
    while (True):
        inc0 += 1
        f = getFunctionAfter(funcs[inc0 - 1])
        if not f:
            break
        funcs.append(f)

    # Return the list of function objects
    return funcs

if __name__== "__main__":
    if DEBUG > 0: print("%s: %s"%(progname,scriptname))

    # Get all functions for the current file
    funcs = getFunctions()

    # Check function for references storing count
    refs = {}
    min_refs = 20
    for e in funcs:
        func_name = "%s:%s"%(e.name,e.getEntryPoint())
        cnt_ref_objects = len(getReferencesTo(e.getEntryPoint()))
        refs[func_name] = cnt_ref_objects

    # Convert to reverse sorted Tuple
    sorted_refs = sorted(refs.items(),key=lambda x:x[1],reverse=True)
    for e in sorted_refs:
        if e[1] > min_refs:
            # Print output to console
            print("%s:%s:%s"%(progname,e[0],e[1]))

