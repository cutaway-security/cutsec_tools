#Hash all functions from multiple files in a project and return hash collisions
#@author Don C. Weber (@cutaway)
#@category FunctionID
#@keybinding 
#@menupath 
#@toolbar 

import ghidra.app.script.GhidraScript as GS
import ghidra.feature.fid.hash.FidHashQuad as FHQ
import ghidra.feature.fid.service.FidService as FidService
import ghidra.program.model.listing.Function

##########################
# Global variables
##########################
DEBUG = 0
progname = currentProgram.getName()
scriptname = "Function Hash Comparer"

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
        return hex(fhash.getFullHash() & 0xffffffffffffffff)[2:-1]

if __name__== "__main__":
    if DEBUG > 0: print("%s: %s"%(progname,scriptname))

    # Write results to a file because the output can be too long for Jython Console
    onf = askFile("Select file for output.","Save")
    ONF = open(onf.getAbsolutePath(),'w')

    # hashes = {hash:["file:function_name"]}
    hashes = {}

    # Select a project folder to run everything on
    folder = askProjectFolder("Select Project Folder:")

    # Get all files
    files = folder.getFiles()

    # Process each file and get programs
    for f in files:
        # FIXME: This is a hack. Using 'x' for the Consumer variable here. Not sure how to do this properly.
        p = f.getDomainObject('x',1,1,monitor)

        pname = p.getName()
        fm = p.getFunctionManager()

        # Get functions
        funcs = fm.getFunctions(True)

        # Hash functions and print hash
        for e in funcs:
            ehash = getFuncHash(e)
            if ehash in hashes.keys():
                hashes[ehash].append("%s:%s:%s"%(pname,e.name,e.getEntryPoint()))
            else:
                hashes[ehash] = ["%s:%s:%s"%(pname,e.name,e.getEntryPoint())]
        p.release('x')

    # Print Collisions
    print("===============")
    print("Hash Collisions")
    print("===============")
    tab = "    "
    for k in hashes.keys():
        if len(hashes[k]) > 1:
            print("%s:"%k)
            ONF.write("%s:\n"%k)
            for e in hashes[k]:
                print("%s%s"%(tab*1,e))   
                ONF.write("%s%s\n"%(tab*1,e))
    ONF.close()
