#Identify functions that are never called by other functions.
#@author Don C. Weber (@cutaway)
#@category References
#@keybinding 
#@menupath 
#@toolbar 

import ghidra.app.script.GhidraScript as GS
import ghidra.program.model.listing.Function
import ghidra.feature.fid.hash.FidHashQuad as FHQ
import ghidra.feature.fid.service.FidService as FidService

##########################
# Global variables
##########################
DEBUG = 0
progname = currentProgram.getName()
scriptname = "Zero Referenced Functions"

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

## getFuncHash: return list containing the name and hash of a function
def getFuncHash(f):
    if DEBUG > 0: print("DEBUG: processing: %s at %s"%(f.getName(),f.getEntryPoint()))
    fname = "%s@%s"%(f.getName(),f.getEntryPoint())
    serv = FidService()
    fhash = serv.hashFunction(f)
    if not fhash:
        #print("%s at %s: null function error"%(f.getName(),f.getEntryPoint()))
        return "***"
    else:
        #return fhash.toString()
        # Some values will be negative. Make them positive.
        return hex(fhash.getFullHash() & 0xffffffffffffffff)[2:-1]

if __name__== "__main__":
    if DEBUG > 0: print("%s: %s"%(progname,scriptname))

    # Get all functions for the current file
    funcs = getFunctions()

    # Check function for references storing count
    refs = {}
    max_refs = 1
    for e in funcs:
        func_name = "%s:%s"%(e.name,e.getEntryPoint())
        entP = e.getEntryPoint()
        # Size of function comes from the Max (plus one to get last byte) and Min address of the function body
        fsize = (int(e.getBody().getMaxAddress().toString(),16) + 1) - int(e.getBody().getMinAddress().toString(),16)
        if len(getReferencesTo(entP)) < 1:
            ehash = getFuncHash(e)
            refs[func_name] = [fsize,ehash]

    # Convert to reverse sorted Tuple
    print("Program name, Function name, Function Entry Point, Function Hash, Function Byte Size")
    sorted_refs = sorted(refs.items(),key=lambda x:x[1][0],reverse=True)
    for e in sorted_refs:
        # Print output to console
        print("%s:%s:%s:%s"%(progname,e[0],e[1][1],e[1][0]))

