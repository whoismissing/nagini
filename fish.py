#!/usr/bin/python2.7
#@author: missing
## https://ghidra.re/ghidra_docs/api/ghidra/python/PythonScript.html
import ctypes

debug = False
#debug = True

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

## Purpose: Get a list object of all of the FunctionDB objects from the ListingDB
## Input:  listing      <type 'ghidra.program.database.ListingDB'>
## Output: lst          list of <type 'ghidra.program.database.function.FunctionDB'>
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
## Output:  lst             list of <type 'ghidra.program.database.function.FunctionDB'> that match to name
def get_funcs(func_list, name):
    lst = []
    for func_db_obj in func_list:
        if name == func_db_obj.getName():
            lst.append(func_db_obj)
    return lst

## Purpose: Print all of the function names and starting addresses given a list of FunctionDB objects
## Input: funcs    list of <type 'ghidra.program.database.function.FunctionDB'>
def prt_funcs(funcs):
    if debug: printf("[+] Printing list of functions: \n")

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
## Input:   vars      list of tuples (stackOffset, varName, guessedSize)
def prt_vars(vars):
    if debug: printf("[+] Printing list of varibles: \n")

    printf("\t%-10s: %-20s %s\n", "Offset", "Name", "Size (guess)")
    for var in vars:
        if len(var) == 3:
            printf("\t%-10s: %-20s %s\n", var[0], var[1], var[2])
        else:
            printf("\t%-10s: %s\n", var[0], var[1])

## Purpose: Return guesses on the size of local variables in the function 
##          based on the distance between stack offsets
## Input:  vars     list of tuples returned from get_vars()
## Output: lst      list of tuples (stackOffset, varName, guessedSize)
## Note: The stackOffset is based off of the return address NOT ebp
def guess_local_var_sizes(vars):
    # if debug: printf("[+] Guessing sizes of local variables\n")
    lst = []
    var1 = vars[0]
    prev_offset = abs(var1[0])
    lst.append(
        (var1[0], var1[1], prev_offset))

    if len(vars) < 2: return lst

    for var in vars[1:]:
        curr_offset = abs(var[0])
        if curr_offset > prev_offset:
            var_size = curr_offset - prev_offset
            lst.append(
                (var[0], var[1], var_size))
        prev_offset = curr_offset

    return lst

## Purpose: Print operands of an instruction for debugging
## Input: instr    <type 'ghidra.program.database.code.InstructionDB'>
def prt_instr_attrs(instr):
    if debug: printf("[+] Printing instruction obj attributes\n")
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
## Note: Currently only handles MOV [ESP and PUSH register / immediate
##       If an instruction operand is a register so the value is still not known, then call find_register_val(instr_obj, operand) to find that register's value earlier in the binary
def find_cdecl_args(addr, num_args):
    if debug: printf("[+] Finding cdecl args\n")
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
            if debug: 
                printf("[+] Possible argument found! %s\n", instr_str)
            ## If operand 1 is a register,
            ## walk the binary again and
            ## see if you can find where the arg is coming from
            ## 512 is the integer value for OperandType register
            if instr_obj.getOperandType(1) == 512:
                if debug: printf("[+] Following register value in %s\n"
                    , instr_obj.getDefaultOperandRepresentation(1))
                args_list.append(find_register_val(instr_obj
                    , instr_obj.getDefaultOperandRepresentation(1)))
            else:
                args_list.append(instr_obj)
            args_found += 1
        elif mnem in "PUSH":
            if instr_obj.getOperandType(0) == 512:
                args_list.append(find_register_val(instr_obj
                    , instr_obj.getDefaultOperandRepresentation(0)))
            elif instr_obj.getOperandType(0) == 16384:
                args_list.append(instr_obj)
            args_found += 1
        if args_found == num_args:
            return args_list
        instrs_walked += 1

## Purpose: When a register operand's value is unknown, walk up the binary to find the earlier value loaded into the register
## Input: instr    instructionDB object (initial) ex: MOV [ESP], EAX
##        reg   (string) register operand that is being searched for
## Output: instr   instructionDB object (load) ex: LEA EAX, [EBP +-0x2c]
def find_register_val(instr, reg):
    if debug: printf("[+] Finding value of %s\n", reg)
    instrs_walked = 0
    while instrs_walked < 20:
        instr = getInstructionBefore(instr)
        if reg in instr.getDefaultOperandRepresentation(0):
            if debug: printf("[+] %s Found %s loaded by %s\n"
                , instr.getMinAddress(), reg, instr.toString())
            return instr

## Purpose: Match the offset within the sizeof_local_vars list and return the tuple entry for a matching variable
## Input: offset                signed int 
##        sizeof_local_vars     list of tuples with (offset, varname, varsize)
## Output: var_tup     tuple with (offset, varname, varsize)
## Note: returns None if there is no match
def offset_to_var(offset, sizeof_local_vars):
    #if debug: printf("[+] Getting local variables from stack offset\n")
    for var_tup in sizeof_local_vars:
        if offset == var_tup[0]:
            return var_tup
    return None 

## Purpose: Match the instruction operand to the local variable list
## Input:    instr_obj_list       list of InstructionDB objects
##           sizeof_local_vars    list of tuples with (offset, varname, varsize)
## Output:   arg_list     list of arguments found from local variable list and immediate values
## Note: mnemonics are assumed to be from x86 ISA
def x86_instrs_to_vars(instrs, sizeof_local_vars):
    if debug: printf("[+] Matching local variables to function arguments\n")
    #print instrs
    arg_list = []
    for instr in instrs:
        mnem = instr.mnemonicString
        if mnem == "LEA" and "EBP" in instr.getDefaultOperandRepresentation(1):
            if "[EBP" in instr.getDefaultOperandRepresentation(1):
                ebp_offset = instr.getOpObjects(1)[1].getSignedValue()          
            elif "EBP]" in instr.getDefaultOperandRepresentation(1):
                ebp_offset = instr.getOpObjects(1)[0].getSignedValue()
            ret_offset = ctypes.c_int(int(ebp_offset)).value - 4
            var = offset_to_var(ret_offset, sizeof_local_vars)
            if var != None:
                arg_list.append(var)
        ## 16384 is assumed to be the operandType code for immediate value
        elif mnem == "MOV" and instr.getOperandType(1) == 16384:
            arg_list.append( (instr.getOpObjects(1)[0],) )
        elif mnem == "PUSH" and instr.getOperandType(0) == 16384:
            arg_list.append( (instr.getOpObjects(0)[0],) )
    return arg_list

## Purpose: Pretty print function name and arguments
## Input: args    list of tuples
##        name    string Ex: "strcpy"
def prt_arg(args, name):
    if debug: printf("\n[+] Printing arguments:\n")
    printf("Function: %s\n", name)
    values = []
    for arg in args:
        if len(arg) == 3:
            printf("\t%-20s %-10s %s\n", arg[1], arg[0], arg[2])
            values.append(arg[2])
        elif len(arg) == 1:
            printf("\t%-20s %-10s %s\n", arg[0], "", int(str(arg[0]),16))
            values.append(int(str(arg[0]),16))

## Purpose: Check func name and verify arguments for possible vulnerabilities based on a few signatures
## Input: addr    address object ( location of call func instruction )
##        name    string - name of the function being called
##        args    list of tuples that represent the arguments being passed to the function
##        arg_instrs    list of InstructionDB objects used to verify parameter safety
## Output: addr   address object ( location of call func instruction )
##         None   Nonetype object ( if function call was not found to be vulnerable)
def check_vuln_args(addr, name, args, arg_instrs):
    values = []
    if name == "strncpy":
        for arg in args:
            if len(arg) == 3: values.append(arg[2])
            elif len(arg) == 1: values.append(int(str(arg[0]),16))
        if values[2] > values[0]:
            print "[!]", addr, "call strncpy(dst, src, size) POSSIBLE BUFFER OVERFLOW - size is bigger than guessed dst buffer length"
            return addr

    if name == "strcpy":
        ## if dst is on stack and src is non-data section
        ## 8704 is assumed to be the OperandType code for stack offset 
        ## ex: [0xfffffc63 + EBP]
        if (arg_instrs[0].getOperandType(1) != 8256) and (arg_instrs[0].getOperandType(0) == 8704):
            print "[!]", addr, "call strcpy(dst, src) POSSIBLE BUFFER OVERFLOW - dst buffer is on stack and src is non-data section"
    
    if name == "printf":
        ## 8256 is assumed to be the OperandType code of
        ## data section address
        if (len(args) == 1) and (arg_instrs[0].getOperandType(0) != 8256):
            print "[!]", addr, "call printf(var) POSSIBLE FORMAT STRING ATTACK - only one non-data section argument passed to printf"
            return addr

    return None

## Purpose: Loop through list of specified vulnerable functions to search for, find arguments to those functions, and pass them to check_vuln()
##          to check if the function is used in a vulnerable way
## Input: func_list    list of strings Ex: ["strcpy", "strncpy", ...]
def find_vuln_funcs(func_name):
    name = func_name

    listing = currentProgram.getListing()

    all_funcs = get_all_funcs(listing)
    #prt_funcs(all_funcs)
    
    func_obj_list = get_funcs(all_funcs, name)
    #prt_funcs(func_obj_list)
    index = 0
    for func_obj in func_obj_list:
        print "============== SCANNING", name, index,"==============" 
        index += 1

        func_addr = func_obj.body.minAddress
        print "[+]", name, "address: ", func_addr

        list_vars = get_vars(func_obj)
        #prt_vars(list_vars)

        ## getReferencesTo(Address) will return an array 
        ## of <type 'ghidra.program.database.references.MemReferenceDB'>
        xrefs_to_func = getReferencesTo(func_addr)

        for xref in xrefs_to_func:
            xref_addr = xref.fromAddress
            if debug: print "[+] xref addr:", xref_addr

            ## This will be used to go to the top of the function 
            ## and check the local variables within the stack frame
            ## <type 'ghidra.program.database.function.FunctionDB'>
            func_obj_containing_addr = getFunctionContaining(xref_addr)

            ## Returns the stack frame size 
            ## based from the ret addr, 8 bytes added
            try: 
                func_stack_size = func_obj_containing_addr.getStackFrame().localSize
            except:
                ## If getting the stack frame fails, 
                ## probably a thunk function so skip it
                if debug:
                    print "[-] No stack frame"
                continue

            list_local_vars = get_vars(func_obj_containing_addr)
            #prt_vars(list_local_vars)

            sizeof_local_vars = guess_local_var_sizes(list_local_vars)
            #prt_vars(sizeof_local_vars)

            num_args = get_num_args(func_obj)
            found_arg_instrs = find_cdecl_args(xref_addr, num_args)

            ## If arguments for function call could not be found, skip
            if not found_arg_instrs:
                if debug:
                    print "[-] No arguments found"
                continue
            elif num_args > len(found_arg_instrs):
                if debug:
                    print "[-] Not enough arguments found, arg instructions =", found_arg_instrs
                continue

            args = x86_instrs_to_vars(found_arg_instrs, sizeof_local_vars)
            #prt_arg(args,name)
            check_vuln_args(xref_addr, name, args, found_arg_instrs)

def main():
    
    func_list = ["strncpy", "strcpy", "printf" ]
    if debug: printf("[+] Scanning for vulnerabilities...\n")
    for func_name in func_list:
        find_vuln_funcs(func_name)

if __name__ == "__main__":
    main()

## FOR DEBUGGING:
## Get an Address object from string
#prt_instr_attrs(getInstructionAt(parseAddress("08048585")))
#print getInstructionAt(parseAddress("080491c7")).getOpObjects(0)
#print getInstructionAt(parseAddress("080491c7")).getOpObjects(1)
#print getInstructionAt(parseAddress("08048597")).getOperandType(0)
#print getInstructionAt(parseAddress("08048597")).getOperandType(1)
