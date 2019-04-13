#!/usr/bin/python2.7
#@author: missing
## https://ghidra.re/ghidra_docs/api/ghidra/python/PythonScript.html

debug = True

## Purpose: Dump object attributes to console
## Input: obj    some object whose type and attributes are unclear
## Note: Especially helpful for learning how to interact with Ghidra API
def dump(obj):
    if debug:
        printf("[+] Dumping object attributes: %s\n", obj)
        printf("[+] Object type: %s\n", str(type(obj)))
        printf("[+] Attributes:\n")
    for attr in dir(obj):
        try:
            printf("\t%-30s: %s\n", attr, getattr(obj,attr))
        except:
            # Write only object, cannot get value
            printf("\t%-30s: %s\n", attr, "ERROR: Cannot get value")

## Purpose: Get an list object of all of the FunctionDB objects from the ListingDB
## Input:  listing      <type 'ghidra.program.database.ListingDB'>
## Output: func_list    list of <type 'ghidra.program.database.function.FunctionDB'>
def get_all_funcs(listing):
    ## func_iter is of <type 'ghidra.program.database.function.FunctionManagerDB$FunctionIteratorDB'>
    func_iter = listing.getFunctions(True)
    lst = []
    while func_iter.hasNext():
        ## Get the FunctionDB object from FunctionIteratorDB
        lst.append(func_iter.next())
    ## Return a list of FunctionDB objects
    return lst

## Purpose: Return a function obj 
## Input:   func_list       list of <type 'ghidra.program.database.function.FunctionDB'>  
##          name            strings, ex: strcpy, gets, etc
## Output:  fuction list    list of <type 'ghidra.program.database.function.FunctionDB'> 
def get_funcs(func_list, name):
    lst = []
    for func_db_obj in func_list:
        if name == func_db_obj.getName():
            lst.append(func_db_obj)

    return lst

## Purpose: Print all of the function names and starting addresses given a list of FunctionDB objects
## Input: func_list    list of <type 'ghidra.program.database.function.FunctionDB'>
def prt_funcs(funcs):
    if debug:
        printf("[+] Printing list of functions: \n")
    for func in funcs:
        func_name = func.getName()
        printf("\t%-10s: %s\n", str(func.body.minAddress), func_name)

## Purpose: Returns a list of the local variables of the input function
## Input:   func            <type 'ghidra.program.database.function.FunctionDB'> 
## Output:  lst of vars     list of tuples containing stackOffset and varName
## Note: May be a redundant function for func.getVariables(0)
##       The stackOffset is based off of the return address NOT ebp
def get_vars(func):
    vars = func.allVariables
    lst = []
    for var in vars:
        lst.append((var.stackOffset, var.name)) 
    return lst

## Purpose: Print all of the variables in the list of variables
## Input:   var_list    list of variable
def prt_vars(vars):
    if debug:
        printf("[+] Printing list of varibles: \n")
    printf("\t%-10s: %-20s %s\n", "Offset", "Name", "Size (guess)")
    for var in vars:
        if len(var) == 3:
            printf("\t%-10s: %-20s %s\n", var[0], var[1], var[2])
        else:
            printf("\t%-10s: %s\n", var[0], var[1])

## Purpose: Return guesses on the size of local variables in the function 
##          based on the distance between stack offsets
## Input: list_local_vars    list of tuples returned from get_vars()
## Output: new_var_list      list of tuples (stackOffset, varName, guessedSize)
## Note: The stackOffset is based off of the return address NOT ebp
def guess_local_var_sizes(list_local_vars):
    if debug: printf("\n[+] Guessing sizes of local variables\n\n")
    new_var_list = []
    prev_offset = abs(list_local_vars[0][0])
    new_var_list.append(
        (list_local_vars[0][0], list_local_vars[0][1], prev_offset))

    if len(list_local_vars) < 2:
        return new_var_list

    for local in range(1, len(list_local_vars)):
        curr_offset = abs(list_local_vars[local][0])
        if curr_offset > prev_offset:
            var_size = curr_offset - prev_offset
            new_var_list.append(
                (list_local_vars[local][0], list_local_vars[local][1], var_size))
        prev_offset = curr_offset
    return new_var_list

## Purpose: Print operands of an instruction for debugging
## Input: instr    <type 'ghidra.program.database.code.InstructionDB'>
def prt_instr_attrs(instr):
    if debug: printf("\n[+] Printing instruction obj attributes\n\n")
    #dump(instr)
    num_opnds = instr.numOperands
    print "mnemonic: " + str(instr.mnemonicString)
    for op_index in range(0, num_opnds):
        printf("opnd %d: %s\n", op_index
            , instr.getDefaultOperandRepresentation(op_index))

## Purpose: Get the number of arguments expected for a function
## Input: func_db_obj <type 'ghidra.program.database.function.FunctionDB'>
## Output: len(func_db_obj.getParameters())    length of getParameters() list
def get_num_args(func_db_obj):
    return len(func_db_obj.getParameters())

## Purpose: Assuming cdecl calling convention, walk up binary from addr to find the arguments before a function call
## Input: addr      Address object for initial call function()
##        num_args  Number of arguments passed to function() to search for
## Output: args_list   List of instructionDB objects for parameter passing instructions
## Note: Currently only handles MOV [ESP but needs to handle PUSH
##       If an instruction operand is a register so the value is still not known, then call find_register_val(instr_obj, operand) to find that register's value earlier in the binary
def find_cdecl_args(addr, num_args):
    if debug: printf("\n[+] Finding cdecl args\n\n")
    ## Get the address of the function we want to stay within
    top_of_function = getFunctionContaining(addr).body.minAddress
    instrs_walked = 0
    args_found = 0
    args_list = []
    while instrs_walked < 20:
        addr = getInstructionBefore(addr).getMinAddress()
        instr_obj = getInstructionAt(addr)
        mnem = getInstructionAt(addr).mnemonicString
        if mnem in ("JMP", "JA", "CALL") or addr < top_of_function:
            return
        instr_str = instr_obj.toString()
        ## Check if mnem is MOV [ESP], 
        if mnem in "MOV" and "[ESP" in instr_obj.getDefaultOperandRepresentation(0): 
            if debug: printf("\n[+] Possible argument found! %s\n\n"
                ,instr_str)
            ## If operand 1 is a register,
            ## walk the binary again and
            ## see if you can find where the arg is coming from
            ## 512 is the integer value for OperandType register
            if instr_obj.getOperandType(1) == 512:
                if debug: printf("\n[+] Following register value in %s"
                    , instr_obj.getDefaultOperandRepresentation(1))
                args_list.append(find_register_val(instr_obj
                    , instr_obj.getDefaultOperandRepresentation(1)))
            else:
                args_list.append(instr_obj)
            args_found += 1
        if args_found == num_args:
            return args_list
        instrs_walked += 1

## Purpose: When a register operand's value is unknown, walk up the binary to find the earlier value loaded into the register
## Input: instr    instructionDB object (initial) ex: MOV [ESP], EAX
##        needle   (string) register operand that is being searched for
## Output: instr   instructionDB object (load) ex: LEA EAX, [EBP +-0x2c]
def find_register_val(instr, needle):
    if debug: printf("\n[+] Finding value of %s\n\n", needle)
    instrs_walked = 0
    while instrs_walked < 20:
        instr = getInstructionBefore(instr)
        if needle in instr.getDefaultOperandRepresentation(0):
            if debug: printf("\n[+] Found %s loaded by %s\n"
                , needle, instr.toString())
            return instr

## Purpose: Match the offset within the sizeof_local_vars list and return the tuple entry for a matching variable
## Input: offset                signed int 
##        sizeof_local_vars     list of tuples with (offset, varname, varsize)
## Output: var_tup     tuple with (offset, varname, varsize)
## Note: returns None if there is no match
def get_local_var_from_offset(offset, sizeof_local_vars):
    if debug: printf("\n[+] Getting local variables from stack offset\n\n")
    for var_tup in sizeof_local_vars:
        if offset == var_tup[0]:
            return var_tup
    return None 

## Purpose: Match the instruction operand to the local variable list
## Input:    instr_obj_list       list of InstructionDB objects
##           sizeof_local_vars    list of tuples with (offset, varname, varsize)
## Output:   arg_list     list of arguments found from local variable list and immediate values
def match_local_var_from_instr(instr_obj_list, sizeof_local_vars):
    if debug: printf("\n[+] Matching local variables to function arguments\n\n")
    arg_list = []
    for instr_obj in instr_obj_list:
        mnem = instr_obj.mnemonicString
        if mnem in "LEA" and "[EBP" in instr_obj.getDefaultOperandRepresentation(1):
            ebp_offset = instr_obj.getOpObjects(1)[1].getValue()
            ret_offset = ebp_offset - 4
            var = get_local_var_from_offset(ret_offset
                , sizeof_local_vars)
            if var != None:
                arg_list.append(var)
        ## 16384 is assumed to be the operandType code for immediate value
        if mnem in "MOV" and instr_obj.getOperandType(1) == 16384:
            arg_list.append(instr_obj.getOpObjects(1)[0])
    return arg_list

def main():
    listing = currentProgram.getListing()
    #dump(listing)

    all_funcs = get_all_funcs(listing)
    #prt_funcs(all_funcs)
    
    strncpy_funcs = get_funcs(all_funcs, "puts")
    prt_funcs(strncpy_funcs)

    ## Get addr to strncpy() for init example
    strncpy_funcs = get_funcs(all_funcs, "strncpy")
    prt_funcs(strncpy_funcs)

    ## play with the first instance of strncpy
    strncpy_func_obj = strncpy_funcs[0]

    strncpy_ex_addr = strncpy_func_obj.body.minAddress
    print "strncpy address: ", strncpy_ex_addr

    list_vars = get_vars(strncpy_func_obj)
    prt_vars(list_vars)

    ## getReferencesTo(Address) will return an array 
    ## of <type 'ghidra.program.database.references.MemReferenceDB'>
    xrefs_to_strncpy = getReferencesTo(strncpy_ex_addr)

    #for i in xrefs_to_strncpy:
        #dump(i)
        #print i.fromAddress

    ## Get the address of the instruction call strncpy()
    strncpy_xref_addr = xrefs_to_strncpy[0].fromAddress

    ## This will be used to go to the top of the function 
    ## and check the local variables within the stack frame
    ## <type 'ghidra.program.database.function.FunctionDB'>
    func_obj_containing_addr = getFunctionContaining(strncpy_xref_addr)

    ## Returns the stack frame size based from the ret addr, 8 bytes added
    func_stack_size = func_obj_containing_addr.getStackFrame().localSize

    list_local_vars = get_vars(func_obj_containing_addr)
    prt_vars(list_local_vars)

    sizeof_local_vars = guess_local_var_sizes(list_local_vars)
    prt_vars(sizeof_local_vars)

    strncpy_num_args = get_num_args(strncpy_func_obj)
    found_arg_instrs = find_cdecl_args(strncpy_xref_addr, strncpy_num_args)

    print match_local_var_from_instr(found_arg_instrs, sizeof_local_vars)
        
if __name__ == "__main__":
    main()

## FOR DEBUGGING:
## Get an Address object from string
#prt_instr_attrs(getInstructionAt(parseAddress("08048585")))
#print getInstructionAt(parseAddress("080491c7")).getOpObjects(0)
#print getInstructionAt(parseAddress("080491c7")).getOpObjects(1)
#print getInstructionAt(parseAddress("08048597")).getOperandType(0)
#print getInstructionAt(parseAddress("08048597")).getOperandType(1)
