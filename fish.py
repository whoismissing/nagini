#!/usr/bin/python2.7
#@author: missing
## https://ghidra.re/ghidra_docs/api/ghidra/python/PythonScript.html

debug = True

## Purpose: Dump object attributes to console
## Input: obj    some object whose type and attributes are unclear
## Note: Especially helpful for learning how to interact with Ghidra API
def dump(obj):
    if debug: printf("\n[+] Dumping object attributes to console\n\n")
    print type(obj)
    for attr in dir(obj):
        try:
            print("obj.%s = %r" % (attr, getattr(obj, attr)))
        ## Object is write only so handle error
        except AttributeError as error:
            print error

## Purpose: Get an array of all of the FunctionDB objects from the ListingDB
## Input:  listing      <type 'ghidra.program.database.ListingDB'>
## Output: func_list    list of <type 'ghidra.program.database.function.FunctionDB'>
def get_all_funcs(listing):
    ## func_iter is of <type 'ghidra.program.database.function.FunctionManagerDB$FunctionIteratorDB'>
    func_iter = listing.getFunctions(True)
    func_list = []

    while func_iter.hasNext():
        ## Get the FunctionDB object from FunctionIteratorDB
        func_db_obj = func_iter.next()
        func_list.append(func_db_obj)
    ## Return a list of FunctionDB objects
    return func_list

## Purpose: Print all of the function names and starting addresses given a list of FunctionDB objects
## Input: func_list    list of <type 'ghidra.program.database.function.FunctionDB'>
def prt_all_funcs(func_list):
    for func_db_obj in func_list:
        address_set_obj = func_db_obj.body
        func_name = func_db_obj.getName()
        print str(address_set_obj.minAddress) + " " + func_name

## Purpose: Returns a list of the local variables of the input function
## Input: func_db_obj   <type 'ghidra.program.database.function.FunctionDB'> 
## Output: list_local_vars     list of tuples containing stackOffset and varName
## Note: May be a redundant function for func_db_obj.getVariables(0)
##       The stackOffset is based off of the return address NOT ebp
def get_local_vars(func_db_obj):
    all_variable_objs = func_db_obj.allVariables
    list_local_vars = []
    for var in all_variable_objs:
        list_local_vars.append((var.stackOffset, var.name)) 
    return list_local_vars

## Purpose: Return guesses on the size of local variables in the function 
##          based on the distance between stack offsets
## Input: list_local_vars    list of tuples returned from get_local_vars()
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

def get_num_args(func_db_obj):
    return len(func_db_obj.getParameters())

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

def find_register_val(instr, needle):
    if debug: printf("\n[+] Finding value of %s\n\n", needle)
    instrs_walked = 0
    while instrs_walked < 20:
        instr = getInstructionBefore(instr)
        if needle in instr.getDefaultOperandRepresentation(0):
            if debug: printf("\n[+] Found %s loaded by %s\n"
                , needle, instr.toString())
            return instr

def main():
    listing = currentProgram.getListing()
    all_funcs = get_all_funcs(listing)

    strncpy_func_obj = all_funcs[5]
    ## Get addr to strncpy() for init example
    strncpy_ex_addr = strncpy_func_obj.body.minAddress

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

    list_local_vars = get_local_vars(func_obj_containing_addr)
    print list_local_vars

    sizeof_local_vars = guess_local_var_sizes(list_local_vars)
    print sizeof_local_vars

    strncpy_num_args = get_num_args(strncpy_func_obj)
    print find_cdecl_args(strncpy_xref_addr, strncpy_num_args)

        
if __name__ == "__main__":
    main()

## FOR DEBUGGING:
## Get an Address object from string
#prt_instr_attrs(getInstructionAt(parseAddress("08048585")))
#print getInstructionAt(parseAddress("080491c7")).getOpObjects(0)
#print getInstructionAt(parseAddress("080491c7")).getOpObjects(1)
#print getInstructionAt(parseAddress("08048597")).getOperandType(0)
#print getInstructionAt(parseAddress("08048597")).getOperandType(1)
