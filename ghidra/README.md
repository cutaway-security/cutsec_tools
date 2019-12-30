# Ghidra Scripts
Python scripts to do actions in Ghidra via script manager. These scripts should be stored in your Ghidra scripts directory. See Ghidra documentation for the approprate locations.

##CutSec_HashComparer.py
Hash all functions in multiple programs and detect hash collisions

## CutSec_ReferenceToFunctionsCountSorted.py
Identify the functions that are referenced (XREFS) by other functions. This scripts sorts by the most called function.

## CutSec_ZeroReferencedFunctions.py
Identify functions that are not referenced from other areas of the program. These could be false negatives. These functions are interesting because they could be used to modify the firmware without increasing the size of the binary.

## Helper scripts
Scripts that were used to build other scripts. These could still be useful for analysis.

### CutSec_HashAllFunctionMultiFile.py 
Hash all functions from multiple programs

### CutSec_HashAllFunctions.py         
Hash all functions in the current program
