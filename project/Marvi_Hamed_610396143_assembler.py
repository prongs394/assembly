
#not complete

#registers:
reg8 = {"al": ["0", "000"], "cl": ["0", "001"], "dl": ["0", "010"], "bl": ["0", "011"], "ah": ["0", "100"],
                 "ch": ["0", "101"], "dh": ["0", "110"], "bh": ["0", "111"], "r8b": ["1", "000"], "r9b": ["1", "001"],
                 "r10b": ["1", "010"], "r11b": ["1", "011"], "r12b": ["1", "100"], "r13b": ["1", "101"],
                 "r14b": ["1", "110"], "r15b": ["1", "111"]}

reg16 = {"ax": ["0", "000"], "cx": ["0", "001"], "dx": ["0", "010"], "bx": ["0", "011"], "sp": ["0", "100"],
                  "bp": ["0", "101"], "si": ["0", "110"], "di": ["0", "111"], "r8w": ["1", "000"], "r9w": ["1", "001"],
                  "r10w": ["1", "010"], "r11w": ["1", "011"], "r12w": ["1", "100"], "r13w": ["1", "101"],
                  "r14w": ["1", "110"], "r15w": ["1", "111"]}

reg32 = {"eax": ["0", "000"], "ecx": ["0", "001"], "edx": ["0", "010"], "ebx": ["0", "011"],
                  "esp": ["0", "100"], "ebp": ["0", "101"], "esi": ["0", "110"], "edi": ["0", "111"],
                  "r8d": ["1", "000"], "r9d": ["1", "001"], "r10d": ["1", "010"], "r11d": ["1", "011"],
                  "r12d": ["1", "100"], "r13d": ["1", "101"], "r14d": ["1", "110"], "r15d": ["1", "111"]}

reg64 = {"rax": ["0", "000"], "rcx": ["0", "001"], "rdx": ["0", "010"], "rbx": ["0", "011"],
                  "rsp": ["0", "100"], "rbp": ["0", "101"], "rsi": ["0", "110"], "rdi": ["0", "111"],
                  "r8": ["1", "000"], "r9": ["1", "001"], "r10": ["1", "010"], "r11": ["1", "011"], "r12": ["1", "100"],
                  "r13": ["1", "101"], "r14": ["1", "110"], "r15": ["1", "111"]}

regr = set(
    ["r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d",
     "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w", "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b",
     "r15b"])

#jump
jump = {"jo": "0000", "jno": "0001", "jb": "0010", "jnae": "0010", "jnb": "0011", "jae": "0011", "je": "0100",
                  "jz": "0100", "jne": "0101", "jnz": "0101", "jbe": "0110", "jna": "0110", "jnbe": "0111",
                  "ja": "0111", "js": "1000", "jns": "1001", "jp": "1010", "jpe": "1010", "jnp": "1011", "jpo": "1011",
                  "jl": "1100", "jnge": "1100", "jnl": "1101", "jge": "1101", "jle": "1110", "jng": "1110",
                  "jnle": "1111", "jg": "1111"}

scaling = {"1": "00", "2": "01", "4": "10", "8": "11"}

#fields:
Prefix = ""

Rex_X = ""
Rex = "0100"    #in 64 bit

OpCode = ""   #opcode/d/w
D = ""
W = ""

MOD = ""
R_M = ""

Scale = ""    #SIB
Index = ""
Base = ""

Displacement = ""

Data = ""

Rex_B = ""
instruction = ""
operand1 = ""
operand2 = ""
machineCode = ""
Rex_W = ""
Rex_R = ""

S = ""
Reg_Op = ""




import copy
def isitrex(a, b):    #checks if a register is 64 bits or not
    if a in reg64 or b in reg64:  return True
    if a in regr or b in regr:  return True
    for x in regr:
        if x in a or x in b:    return True
    return False
#___________________________________________________________________________





"""
 1 -> reg
 2 -> immediate
 3 -> [dis]
 4 -> [scale]
 5 -> [scale + dis]
 6 -> [reg(not rbp)]
 7 -> [rbp]
 8 -> [reg(not rbp) + dis]
 9 -> [rbp + dis]
 10 -> [reg(not rbp) + scale]
 11 -> [rbp + scale]
 12 -> [reg(not rbp) + scale + dis]
 13 -> [rbp + scale + dis]
 14 -> [d1] 
 15 -> d1 
 these are for the below func
 """
#these are for the below func
def denoteoperand(op):    #classifies the operand
    if "[" not in op:
        if op not in reg64 and op not in reg32 and op not in reg16 and op not in reg8:
            u = op[2:]
            if not op.isdigit() or not u.isdigit():
                return 15

    if op in reg64 or op in reg32 or op in reg16 or op in reg8: return 1
    if op.startswith("0x") == True: return 2

    e = op.index("[")
    r = op[e + 1: -1]
    del e

    e = 0

    for t in r:
        if t == "+":    e = e + 1

    if e == 0:
        if r.startswith("0x"):
            return 3
        elif "*" in r:
            return 4
        elif r == "rbp" or r == "ebp":
            return 7
        else:
            return 6

    elif e == 1:
        if "*" in r and "0x" in r:  return 5
        if "0x" in r:
            if r.startswith("rbp") or r.startswith("ebp"):
                return 9
            else:
                return 8

        else:
            if r.startswith("rbp") or r.startswith("ebp"):
                return 11
            else:
                return 10
    else:
        if r.startswith("rbp") or r.startswith("ebp"):
            return 13
        else:
            return 12


def changeData(g, t):
    global Prefix, MOD, R_M, Scale, Index, Base, Displacement, Rex_X, Rex_B, instruction, operand1, operand2, machineCode, Rex, Rex_W, Rex_R, D, W, S, OpCode, Reg_Op, Data

    if g == 0:
        if "b" in t:
            t = t[2:]
            t = hex(int(t, 2))
            t = t = t[2:]

        elif "x" in t:
            t = t[2:]

        else:
            t = hex(int(t, 10))
            t = t = t[2:]

        if len(t) % 2 == 1:
            t = "0" + t

        T = ""
        TT = ""
        for x in t:
            TT = bin(int(x, 16))[2:]
            while len(TT) < 4:
                TT = "0" + TT
            T = T + TT

        t = ""
        ee = len(T) - 8
        eee = len(T)

        while ee >= 0:
            t = t + T[ee: eee]
            ee = ee - 8
            eee = eee - 8

        Data = copy.copy(t)

        del T
        del TT
        del ee
        del eee
    else:
        if "b" in t:
            t = t[2:]
            t = hex(int(t, 2))
            t = t = t[2:]


        elif "x" in t:
            t = t[2:]

        else:
            t = hex(int(t, 10))
            t = t = t[2:]

        if len(t) % 2 == 1:
            t = "0" + t

        if len(t) < 8:

            while len(t) < 8:
                t = "0" + t

        T = ""
        TT = ""
        for x in t:
            TT = bin(int(x, 16))[2:]
            while len(TT) < 4:
                TT = "0" + TT
            T = T + TT

        t = ""
        ee = len(T) - 8
        eee = len(T)

        while ee >= 0:
            t = t + T[ee: eee]
            ee = ee - 8
            eee = eee - 8

        Data = copy.copy(t)

        del T
        del TT
        del ee
        del eee


def memory(op2):
    global Prefix, MOD, R_M, Scale, Index, Base, Displacement, Rex_X, Rex_B, instruction, operand1, operand2, machineCode, Rex, Rex_W, Rex_R, D, W, S, OpCode, Reg_Op, Data

    L = op2[op2.index("[") + 1:op2.index("]")]

    Base_ = ""
    Scale_ = ""
    Index_ = ""
    Displacement_ = ""

    a = 0
    for i in range(len(L)):
        if L[i] == "+":
            a = a + 1

    if a == 0:
        if L.startswith("0x"):
            Displacement_ = copy.copy(L)
        elif "*" in op2:
            for i in range(len(L)):
                if i < L.index("*"):
                    Index_ = Index_ + L[i]
                elif L[i] == "*":
                    pass
                else:
                    Scale_ = Scale_ + L[i]
        else:
            Base_ = copy.copy(L)

    elif a == 1:
        e = 0

        if "*" in L and "0x" in L:
            while L[e] != "*":
                Index_ = Index_ + L[e]
                e = e + 1
            e = e + 1

            Scale_ = L[e]
            e = e + 2

            while e < len(L):
                Displacement_ = Displacement_ + L[e]
                e = e + 1

        elif "*" in L and "0x" not in L:
            while L[e] != "+":
                Base_ = Base_ + L[e]
                e = e + 1

            e = e + 1

            while L[e] != "*":
                Index_ = Index_ + L[e]
                e = e + 1

            e = e + 1

            Scale_ = L[e]

        elif "0x" in L and "*" not in L:
            while L[e] != "+":
                Base_ = Base_ + L[e]
                e = e + 1

            e = e + 1

            while e < len(L):
                Displacement_ = Displacement_ + L[e]
                e = e + 1
    else:
        e = 0
        while L[e] != "+":
            Base_ = Base_ + L[e]
            e = e + 1

        e = e + 1
        while L[e] != "*":
            Index_ = Index_ + L[e]
            e = e + 1

        e = e + 1

        Scale_ = L[e]
        e = e + 2

        while e < len(L):
            Displacement_ = Displacement_ + L[e]
            e = e + 1

    if Displacement_ != "":
        Displacement_ = Displacement_[2:]

    if denoteoperand(op2) == 3:

        if isitrex(operand1, operand2):
            Rex_X = "0"
            Rex_B = "0"

        MOD = "00"
        R_M = "100"
        Scale = scaling["1"]
        Index = "100"
        Base = "101"

        if len(Displacement_) % 2 == 1:
            Displacement_ = "0" + Displacement_

        if len(Displacement_) < 8:

            while len(Displacement_) < 8:
                Displacement_ = "0" + Displacement_

        T = ""
        TT = ""
        for x in Displacement_:
            TT = bin(int(x, 16))[2:]
            while len(TT) < 4:
                TT = "0" + TT
            T = T + TT

        Displacement_ = ""
        ee = len(T) - 8
        eee = len(T)

        while ee >= 0:
            Displacement_ = Displacement_ + T[ee: eee]
            ee = ee - 8
            eee = eee - 8

        Displacement = copy.copy(Displacement_)

        del T
        del TT
        del ee
        del eee

    elif denoteoperand(op2) == 4:

        if isitrex(operand1, operand2):
            if Index_ in reg32:
                Rex_X = reg32[Index_][0]
            else:
                Rex_X = reg64[Index_][0]

            Rex_B = "0"

        if Index_ in reg32:
            Prefix = Prefix + "01100111"

        MOD = "00"
        R_M = "100"
        Scale = scaling[Scale_]
        if Index_ in reg32:
            Index = reg32[Index_][1]
        else:
            Index = reg64[Index_][1]
        Base = "101"

        Displacement_ = "00000000"
        T = ""
        TT = ""
        for x in Displacement_:
            TT = bin(int(x, 16))[2:]
            while len(TT) < 4:
                TT = "0" + TT
            T = T + TT

        Displacement_ = ""
        ee = len(T) - 8
        eee = len(T)

        while ee >= 0:
            Displacement_ = Displacement_ + T[ee: eee]
            ee = ee - 8
            eee = eee - 8

        Displacement = copy.copy(Displacement_)

        del T
        del TT
        del ee
        del eee

    elif denoteoperand(op2) == 5:

        if isitrex(operand1, operand2):
            if Index_ in reg32:
                Rex_X = reg32[Index_][0]
            else:
                Rex_X = reg64[Index_][0]

            Rex_B = "0"

        if Index_ in reg32:
            Prefix = Prefix + "01100111"

        MOD = "00"
        R_M = "100"
        Scale = scaling[Scale_]
        if Index_ in reg32:
            Index = reg32[Index_][1]
        else:
            Index = reg64[Index_][1]
        Base = "101"

        if len(Displacement_) % 2 == 1:
            Displacement_ = "0" + Displacement_

        if len(Displacement_) < 8:

            while len(Displacement_) < 8:
                Displacement_ = "0" + Displacement_

        T = ""
        TT = ""
        for x in Displacement_:
            TT = bin(int(x, 16))[2:]
            while len(TT) < 4:
                TT = "0" + TT
            T = T + TT

        Displacement_ = ""
        ee = len(T) - 8
        eee = len(T)

        while ee >= 0:
            Displacement_ = Displacement_ + T[ee: eee]
            ee = ee - 8
            eee = eee - 8

        Displacement = copy.copy(Displacement_)

        del T
        del TT
        del ee
        del eee
    elif denoteoperand(op2) == 6 or denoteoperand(op2) == 7:

        if isitrex(operand1, operand2):
            Rex_X = "0"
            if Base_ in reg32:
                Rex_B = reg32[Base_][0]
            else:
                Rex_B = reg64[Base_][0]

        if Base_ in reg32:
            Prefix = Prefix + "01100111"

        if denoteoperand(op2) == 6:
            MOD = "00"
        else:
            MOD = "01"

        if Base_ in reg32:
            R_M = reg32[Base_][1]
        else:
            R_M = reg64[Base_][1]

        if denoteoperand(op2) == 7:
            Displacement = "00000000"

    elif denoteoperand(op2) == 8 or denoteoperand(op2) == 9:

        if isitrex(operand1, operand2):
            Rex_X = "0"
            if Base_ in reg32:
                Rex_B = reg32[Base_][0]
            else:
                Rex_B = reg64[Base_][0]

        if Base_ in reg32:
            Prefix = Prefix + "01100111"

        if len(Displacement_) <= 2:
            MOD = "01"
        else:
            MOD = "10"

        if len(Displacement_) % 2 == 1:
            Displacement_ = "0" + Displacement_

        if len(Displacement_) != 2 and len(Displacement_) < 8:

            while len(Displacement_) < 8:
                Displacement_ = "0" + Displacement_

        T = ""
        TT = ""
        for x in Displacement_:
            TT = bin(int(x, 16))[2:]
            while len(TT) < 4:
                TT = "0" + TT
            T = T + TT

        Displacement_ = ""
        ee = len(T) - 8
        eee = len(T)

        while ee >= 0:
            Displacement_ = Displacement_ + T[ee: eee]
            ee = ee - 8
            eee = eee - 8

        Displacement = copy.copy(Displacement_)

        del T
        del TT
        del ee
        del eee

        if Base_ in reg32:
            R_M = reg32[Base_][1]
        else:
            R_M = reg64[Base_][1]

    elif denoteoperand(op2) == 10 or denoteoperand(op2) == 11:

        if isitrex(operand1, operand2):
            if Index_ in reg32:
                Rex_X = reg32[Index_][0]
            else:
                Rex_X = reg64[Index_][0]

            if Base_ in reg32:
                Rex_B = reg32[Base_][0]
            else:
                Rex_B = reg64[Base_][0]

        if Base_ in reg32:
            Prefix = Prefix + "01100111"

        if denoteoperand(op2) == 10:
            MOD = "00"
        else:
            MOD = "01"

        R_M = "100"

        Scale = scaling[Scale_]

        if Base_ in reg32:
            Base = reg32[Base_][1]
        else:
            Base = reg64[Base_][1]

        if Index_ in reg32:
            Index = reg32[Index_][1]
        else:
            Index = reg64[Index_][1]

        if denoteoperand(op2) == 11:
            Displacement = "00000000"

    elif denoteoperand(op2) == 12 or denoteoperand(op2) == 13:

        if isitrex(operand1, operand2):
            if Index_ in reg32:
                Rex_X = reg32[Index_][0]
            else:
                Rex_X = reg64[Index_][0]

            if Base_ in reg32:
                Rex_B = reg32[Base_][0]
            else:
                Rex_B = reg64[Base_][0]

        if Base_ in reg32:
            Prefix = Prefix + "01100111"

        if len(Displacement_) <= 2:
            MOD = "01"
        else:
            MOD = "10"

        R_M = "100"

        Scale = scaling[Scale_]

        if Base_ in reg32:
            Base = reg32[Base_][1]
        else:
            Base = reg64[Base_][1]

        if Index_ in reg32:
            Index = reg32[Index_][1]
        else:
            Index = reg64[Index_][1]

        if len(Displacement_) % 2 == 1:
            Displacement_ = "0" + Displacement_

        if len(Displacement_) != 2 and len(Displacement_) < 8:

            while len(Displacement_) < 8:
                Displacement_ = "0" + Displacement_

        T = ""
        TT = ""
        for x in Displacement_:
            TT = bin(int(x, 16))[2:]
            while len(TT) < 4:
                TT = "0" + TT
            T = T + TT

        Displacement_ = ""
        ee = len(T) - 8
        eee = len(T)

        while ee >= 0:
            Displacement_ = Displacement_ + T[ee: eee]
            ee = ee - 8
            eee = eee - 8

        Displacement = copy.copy(Displacement_)

        del T
        del TT
        del ee
        del eee


def convert(asmcode):




    global Prefix, MOD, R_M, Scale, Index, Base, Displacement, Rex_X, Rex_B, instruction, operand1, operand2, machineCode, Rex, Rex_W, Rex_R, D, W, S, OpCode, Reg_Op, Data
    count = 0

    for i in range(0, len(asmcode)):     #for the first part. in mov rax,rbx --> instruction is mov
        if asmcode[i] == " ":
            break
        instruction = instruction + asmcode[i]
        count = i

    if (count + 1) != len(asmcode):        # operand1 is rax
        for i in range(count + 2, len(asmcode)):
            if asmcode[i] == ",":
                break
            operand1 = operand1 + asmcode[i]
            count = i

    if count + 1 != len(asmcode):     #operand2 is rbx
        for i in range(count + 2, len(asmcode)):
            operand2 = operand2 + asmcode[i]

    del count

    if instruction == "mov" or instruction == "add" or instruction == "adc" or instruction == "sub" or instruction == "sbb":
        if denoteoperand(operand1) == 1 and denoteoperand(operand2) == 1:

            if operand1 in reg16:
                Prefix = Prefix + "01100110"

            if operand1 in reg64:
                Rex_W = "1"
            else:
                Rex_W = "0"

            Rex_X = "0"

            D = "0"

            if operand1 in reg8:
                W = "0"
            else:
                W = "1"

            if operand1 in reg8:
                Rex_R = reg8[operand2][0]
                Rex_B = reg8[operand1][0]
                Reg_Op = reg8[operand2][1]
                R_M = reg8[operand1][1]

            elif operand1 in reg16:
                Rex_R = reg16[operand2][0]
                Rex_B = reg16[operand1][0]
                Reg_Op = reg16[operand2][1]
                R_M = reg16[operand1][1]

            elif operand1 in reg32:
                Rex_R = reg32[operand2][0]
                Rex_B = reg32[operand1][0]
                Reg_Op = reg32[operand2][1]
                R_M = reg32[operand1][1]

            else:
                Rex_R = reg64[operand2][0]
                Rex_B = reg64[operand1][0]
                Reg_Op = reg64[operand2][1]
                R_M = reg64[operand1][1]

            MOD = "11"

            if instruction == "mov":
                OpCode = "100010"

            elif instruction == "add":
                OpCode = "000000"

            elif instruction == "adc":
                OpCode = "000100"

            elif instruction == "sub":
                OpCode = "001010"

            elif instruction == "sbb":
                OpCode = "000110"

            if isitrex(operand1, operand2):
                machineCode = Prefix + Rex + Rex_W + Rex_R + Rex_X + Rex_B + OpCode + D + W + MOD + Reg_Op + R_M
            else:
                machineCode = Prefix + OpCode + D + W + MOD + Reg_Op + R_M

        elif (denoteoperand(operand1) == 1 and denoteoperand(operand2) != 1 and denoteoperand(
                operand2) != 2) or (
                denoteoperand(operand2) == 1 and denoteoperand(operand1) != 1):
            if denoteoperand(operand1) == 1:
                memory(operand2)
                if operand1 in reg16:
                    Prefix = Prefix + "01100110"

                if operand1 in reg64:
                    Rex_W = "1"
                else:
                    Rex_W = "0"

                if operand1 in reg8:
                    Rex_R = reg8[operand1][0]
                    Reg_Op = reg8[operand1][1]

                elif operand1 in reg16:
                    Rex_R = reg16[operand1][0]
                    Reg_Op = reg16[operand1][1]

                elif operand1 in reg32:
                    Rex_R = reg32[operand1][0]
                    Reg_Op = reg32[operand1][1]

                else:
                    Rex_R = reg64[operand1][0]
                    Reg_Op = reg64[operand1][1]

                D = "1"

                if operand1 in reg8:
                    W = "0"
                else:
                    W = "1"


            else:
                memory(operand1)
                if operand2 in reg16:
                    Prefix = Prefix + "01100110"

                if operand2 in reg64:
                    Rex_W = "1"
                else:
                    Rex_W = "0"

                if operand2 in reg8:
                    Rex_R = reg8[operand2][0]
                    Reg_Op = reg8[operand2][1]

                elif operand2 in reg16:
                    Rex_R = reg16[operand2][0]
                    Reg_Op = reg16[operand2][1]

                elif operand2 in reg32:
                    Rex_R = reg32[operand2][0]
                    Reg_Op = reg32[operand2][1]

                else:
                    Rex_R = reg64[operand2][0]
                    Reg_Op = reg64[operand2][1]

                D = 0

                if operand2 in reg8:
                    W = "0"
                else:
                    W = "1"

            if instruction == "mov":
                OpCode = "100010"

            elif instruction == "add":
                OpCode = "000000"

            elif instruction == "adc":
                OpCode = "000100"

            elif instruction == "sub":
                OpCode = "001010"

            elif instruction == "sbb":
                OpCode = "000110"

            if isitrex(operand1, operand2):
                machineCode = Prefix + Rex + Rex_W + Rex_R + Rex_X + Rex_B + OpCode + D + W + MOD + Reg_Op + R_M + Scale + Index + Base + Displacement
            else:
                machineCode = Prefix + OpCode + D + W + MOD + Reg_Op + R_M + Scale + Index + Base + Displacement


        else:
            if denoteoperand(operand1) == 1:
                if operand1 in reg16:
                    Prefix = Prefix + "01100110"

                if operand1 in reg64:
                    Rex_W = "1"
                else:
                    Rex_W = "0"

                Rex_X = "0"
                Rex_B = "0"

                if operand1 in reg8:
                    Rex_R = reg8[operand1][0]
                    Reg_Op = reg8[operand1][1]
                elif operand1 in reg16:
                    Rex_R = reg16[operand1][0]
                    Reg_Op = reg16[operand1][1]
                elif operand1 in reg32:
                    Rex_R = reg32[operand1][0]
                    Reg_Op = reg32[operand1][1]
                else:
                    Rex_R = reg64[operand1][0]
                    Reg_Op = reg64[operand1][1]

                if operand1 in reg8:
                    W = "0"
                else:
                    W = "1"

                if instruction == "mov":
                    S = "1"
                else:
                    if operand1 in reg8:
                        S = "0"
                        changeData(0, operand2)
                    else:
                        changeData(1, operand2)

                        while Data.endswith("0000"):
                            Data = Data[: len(Data) - 4]
                        if "-" in operand2:
                            if "x" in operand2:
                                u = operand2[3:]

                            elif "b" in operand2:
                                u = operand2[3:]
                                u = hex(int(operand2, 2))
                                u = u[2:]

                            else:
                                u = operand2[1:]
                                u = hex(int(operand2, 10))
                                u = u[2:]

                        else:
                            if "x" in operand2:
                                u = operand2[2:]

                            elif "b" in operand2:
                                u = operand2[2:]
                                u = hex(int(operand2, 2))
                                u = u[2:]

                            else:
                                u = hex(int(operand2, 10))
                                u = u[2:]

                        if len(u) <= 2:
                            S = "1"
                        else:
                            S = "0"


            else:
                memory(operand1)

                if "WORD" in operand1 and "DWORD" not in operand1 and "QWORD" not in operand1:
                    Prefix = Prefix + "01100110"

                if "QWORD" in operand1:
                    Rex_W = "1"
                else:
                    Rex_W = "0"

                Rex_R = "0"

                if "BYTE" in operand1:
                    W = "0"
                else:
                    W = "1"

                if instruction == "mov":
                    OpCode = "110001"
                    Reg_Op = "000"
                elif instruction == "add":
                    OpCode = "100000"
                    Reg_Op = "000"
                elif instruction == "adc":
                    OpCode = "100000"
                    Reg_Op = "010"
                elif instruction == "sub":
                    OpCode = "100000"
                    Reg_Op = "101"
                elif instruction == "sbb":
                    OpCode = "100000"
                    Reg_Op = "011"

                if instruction == "mov":
                    S = "1"
                else:
                    if "BYTE" in operand1:
                        S = "0"
                        changeData(0, operand2)
                    else:
                        changeData(1, operand2)
                        while Data.endswith("0000"):
                            Data = Data[: len(Data) - 4]
                        if "-" in operand2:
                            if "x" in operand2:
                                u = operand2[3:]

                            elif "b" in operand2:
                                u = operand2[3:]
                                u = hex(int(operand2, 2))
                                u = u[2:]

                            else:
                                u = operand2[1:]
                                u = hex(int(operand2, 10))
                                u = u[2:]

                        else:
                            if "x" in operand2:
                                u = operand2[2:]

                            elif "b" in operand2:
                                u = operand2[2:]
                                u = hex(int(operand2, 2))
                                u = u[2:]

                            else:
                                u = hex(int(operand2, 10))
                                u = u[2:]

                        if len(u) <= 2:
                            S = "1"
                        else:
                            S = "0"

                if isitrex(operand1, operand1):
                    machineCode = Prefix + Rex + Rex_W + Rex_R + Rex_X + Rex_B + OpCode + S + W + MOD + Reg_Op + R_M + Scale + Index + Base + Displacement + Data
                else:
                    machineCode = Prefix + OpCode + S + W + MOD + Reg_Op + R_M + Scale + Index + Base + Displacement + Data


    elif instruction == "and" or instruction == "or" or instruction == "xor":
        if denoteoperand(operand1) == 1 and denoteoperand(operand2) == 1:
            Rex_X = "0"
            D = "0"
            MOD = "11"

            if instruction == "and":
                OpCode = "001000"
            elif instruction == "or":
                OpCode = "000010"
            else:
                OpCode = "001100"

            if operand1 in reg8:
                Rex_W = "0"
                Rex_R = reg8[operand2][0]
                Rex_B = reg8[operand1][0]
                W = "0"
                Reg_Op = reg8[operand2][1]
                R_M = reg8[operand1][1]

            elif operand1 in reg16:
                Prefix = Prefix + "01100110"
                Rex_W = "0"
                Rex_R = reg16[operand2][0]
                Rex_B = reg16[operand1][0]
                W = "1"
                Reg_Op = reg16[operand2][1]
                R_M = reg16[operand1][1]

            elif operand1 in reg32:
                Rex_W = "0"
                Rex_R = reg32[operand2][0]
                Rex_B = reg32[operand1][0]
                W = "1"
                Reg_Op = reg32[operand2][1]
                R_M = reg32[operand1][1]

            else:
                Rex_W = "1"
                Rex_R = reg64[operand2][0]
                Rex_B = reg64[operand1][0]
                W = "1"
                Reg_Op = reg64[operand2][1]
                R_M = reg64[operand1][1]

            if isitrex(operand1, operand2):
                machineCode = Prefix + Rex + Rex_W + Rex_R + Rex_X + Rex_B + OpCode + D + W + MOD + Reg_Op + R_M
            else:
                machineCode = Prefix + OpCode + D + W + MOD + Reg_Op + R_M

        elif denoteoperand(operand2) == 2:
            if denoteoperand(operand1) == 1:
                pass
            else:
                pass

        else:

            if instruction == "and":
                OpCode = "001000"
            elif instruction == "or":
                OpCode = "000010"
            else:
                OpCode = "001100"

            if denoteoperand(operand1) == 1:
                memory(operand2)
                D = "1"

                if operand1 in reg8:
                    Rex_W = "0"
                    Rex_R = reg8[operand1][0]
                    W = "0"
                    Reg_Op = reg8[operand1][1]

                elif operand1 in reg16:
                    Prefix = Prefix + "01100110"
                    Rex_W = "0"
                    Rex_R = reg16[operand1][0]
                    W = "1"
                    Reg_Op = reg16[operand1][1]

                elif operand1 in reg32:
                    Rex_W = "0"
                    Rex_R = reg32[operand1][0]
                    W = "1"
                    Reg_Op = reg32[operand1][1]

                else:
                    Rex_W = "1"
                    Rex_R = reg64[operand1][0]
                    W = "1"
                    Reg_Op = reg64[operand1][1]


            else:
                memory(operand1)
                D = "0"

                if operand2 in reg8:
                    Rex_W = "0"
                    Rex_R = reg8[operand2][0]
                    W = "0"
                    Reg_Op = reg8[operand2][1]

                elif operand2 in reg16:
                    Prefix = Prefix + "01100110"
                    Rex_W = "0"
                    Rex_R = reg16[operand2][0]
                    W = "1"
                    Reg_Op = reg16[operand2][1]

                elif operand2 in reg32:
                    Rex_W = "0"
                    Rex_R = reg32[operand2][0]
                    W = "1"
                    Reg_Op = reg32[operand2][1]

                else:
                    Rex_W = "1"
                    Rex_R = reg64[operand2][0]
                    W = "1"
                    Reg_Op = reg64[operand2][1]

            if isitrex(operand1, operand2):
                machineCode = Prefix + Rex + Rex_W + Rex_R + Rex_X + Rex_B + OpCode + D + W + MOD + Reg_Op + R_M + Scale + Index + Base + Displacement
            else:
                machineCode = Prefix + OpCode + D + W + MOD + Reg_Op + R_M + Scale + Index + Base + Displacement


    elif instruction == "inc" or instruction == "dec":
        if denoteoperand(operand1) == 1:
            if isitrex(operand1, operand1):
                Rex_X = "0"
                Rex_R = "0"
                if operand1 in reg64:
                    Rex_W = "1"
                else:
                    Rex_W = "0"

                if operand1 in reg8:
                    Rex_B = reg8[operand1][0]
                elif operand1 in reg16:
                    Rex_B = reg16[operand1][0]
                elif operand1 in reg32:
                    Rex_B = reg32[operand1][0]
                else:
                    Rex_B = reg64[operand1][0]

            if operand1 in reg16:
                Prefix = "01100110"

            OpCode = "1111111"
            if operand1 in reg8:
                W = "0"
            else:
                W = "1"
            if operand1 in reg8:
                Reg_Op = reg8[operand1][1]

            elif operand1 in reg16:
                Reg_Op = reg16[operand1][1]

            elif operand1 in reg32:
                Reg_Op = reg32[operand1][1]
            else:
                Reg_Op = reg64[operand1][1]

            if instruction == "inc":
                if isitrex(operand1, operand1):
                    machineCode = Prefix + Rex + Rex_W + Rex_R + Rex_X + Rex_B + OpCode + W + "11000" + Reg_Op
                else:
                    machineCode = Prefix + OpCode + W + "11000" + Reg_Op

            else:
                if isitrex(operand1, operand1):
                    machineCode = Prefix + Rex + Rex_W + Rex_R + Rex_X + Rex_B + OpCode + W + "11001" + Reg_Op
                else:
                    machineCode = Prefix + OpCode + W + "11001" + Reg_Op
        else:
            memory(operand1)

            if "WORD" in operand1 and "QWORD" not in operand1 and "DWORD" not in operand1:
                Prefix = Prefix + "01100110"

            OpCode = "1111111"
            if "BYTE" in operand1:
                W = "0"
            else:
                W = "1"

            if instruction == "inc":
                if isitrex(operand1, operand1):
                    Rex_R = "0"
                    if "QWORD" in operand1:
                        Rex_W = "1"
                    else:
                        Rex_W = "0"
                    machineCode = Prefix + Rex + Rex_W + Rex_R + Rex_X + Rex_B + OpCode + W + MOD + "000" + R_M + Scale + Index + Base + Displacement

                else:
                    machineCode = Prefix + OpCode + W + MOD + "000" + R_M + Scale + Index + Base + Displacement

            else:
                if isitrex(operand1, operand1):
                    Rex_R = "0"
                    if "QWORD" in operand1:
                        Rex_W = "1"
                    else:
                        Rex_W = "0"
                    machineCode = Prefix + Rex + Rex_W + Rex_R + Rex_X + Rex_B + OpCode + W + MOD + "001" + R_M + Scale + Index + Base + Displacement

                else:
                    machineCode = Prefix + OpCode + W + MOD + "001" + R_M + Scale + Index + Base + Displacement

    elif instruction == "cmp":
        if denoteoperand(operand1) == 1 and denoteoperand(operand2) == 1:
            Rex_X = "0"
            OpCode = "001110"
            D = "0"
            MOD = "11"

            if operand1 in reg8:
                Rex_W = "0"
                Rex_R = reg8[operand2][0]
                Rex_B = reg8[operand1][0]
                W = "0"
                Reg_Op = reg8[operand2][1]
                R_M = reg8[operand1][1]

            elif operand1 in reg16:
                Prefix = Prefix + "01100110"
                Rex_W = "0"
                Rex_R = reg16[operand2][0]
                Rex_B = reg16[operand1][0]
                W = "1"
                Reg_Op = reg16[operand2][1]
                R_M = reg16[operand1][1]

            elif operand1 in reg32:
                Rex_W = "0"
                Rex_R = reg32[operand2][0]
                Rex_B = reg32[operand1][0]
                W = "1"
                Reg_Op = reg32[operand2][1]
                R_M = reg32[operand1][1]

            else:
                Rex_W = "1"
                Rex_R = reg64[operand2][0]
                Rex_B = reg64[operand1][0]
                W = "1"
                Reg_Op = reg64[operand2][1]
                R_M = reg64[operand1][1]

            if isitrex(operand1, operand2):
                machineCode = Prefix + Rex + Rex_W + Rex_R + Rex_X + Rex_B + OpCode + D + W + MOD + Reg_Op + R_M
            else:
                machineCode = Prefix + OpCode + D + W + MOD + Reg_Op + R_M

        elif denoteoperand(operand2) == 2:
            if denoteoperand(operand1) == 1:
                pass
            else:
                pass

        else:
            OpCode = "001110"

            if denoteoperand(operand1) == 1:
                memory(operand2)
                D = "1"

                if operand1 in reg8:
                    Rex_W = "0"
                    Rex_R = reg8[operand1][0]
                    W = "0"
                    Reg_Op = reg8[operand1][1]

                elif operand1 in reg16:
                    Prefix = Prefix + "01100110"
                    Rex_W = "0"
                    Rex_R = reg16[operand1][0]
                    W = "1"
                    Reg_Op = reg16[operand1][1]

                elif operand1 in reg32:
                    Rex_W = "0"
                    Rex_R = reg32[operand1][0]
                    W = "1"
                    Reg_Op = reg32[operand1][1]

                else:
                    Rex_W = "1"
                    Rex_R = reg64[operand1][0]
                    W = "1"
                    Reg_Op = reg64[operand1][1]


            else:
                memory(operand1)
                D = "0"

                if operand1 in reg8:
                    Rex_W = "0"
                    Rex_R = reg8[operand2][0]
                    W = "0"
                    Reg_Op = reg8[operand2][1]

                elif operand1 in reg16:
                    Prefix = Prefix + "01100110"
                    Rex_W = "0"
                    Rex_R = reg16[operand2][0]
                    W = "1"
                    Reg_Op = reg16[operand2][1]

                elif operand1 in reg32:
                    Rex_W = "0"
                    Rex_R = reg32[operand2][0]
                    W = "1"
                    Reg_Op = reg32[operand2][1]

                else:
                    Rex_W = "1"
                    Rex_R = reg64[operand2][0]
                    W = "1"
                    Reg_Op = reg64[operand2][1]

            if isitrex(operand1, operand2):
                machineCode = Prefix + Rex + Rex_W + Rex_R + Rex_X + Rex_B + OpCode + D + W + MOD + Reg_Op + R_M + Scale + Index + Base + Displacement
            else:
                machineCode = Prefix + OpCode + D + W + MOD + Reg_Op + R_M + Scale + Index + Base + Displacement



    elif instruction == "test":
        if denoteoperand(operand1) == 1 and denoteoperand(operand2) == 1:
            Rex_X = "0"
            OpCode = "1000010"
            MOD = "11"
            if operand1 in reg8:
                Rex_W = "0"
                Rex_R = reg8[operand2][0]
                Rex_B = reg8[operand1][0]
                W = "0"
                Reg_Op = reg8[operand2][1]
                R_M = reg8[operand1][1]
            elif operand1 in reg16:
                Prefix = Prefix + "01100110"
                Rex_W = "0"
                Rex_R = reg16[operand2][0]
                Rex_B = reg16[operand1][0]
                W = "1"
                Reg_Op = reg16[operand2][1]
                R_M = reg16[operand1][1]
            elif operand1 in reg32:
                Rex_W = "0"
                Rex_R = reg32[operand2][0]
                Rex_B = reg32[operand1][0]
                W = "1"
                Reg_Op = reg32[operand2][1]
                R_M = reg32[operand1][1]
            else:
                Rex_W = "1"
                Rex_R = reg64[operand2][0]
                Rex_B = reg64[operand1][0]
                W = "1"
                Reg_Op = reg64[operand2][1]
                R_M = reg64[operand1][1]

            if isitrex(operand1, operand2):
                machineCode = Prefix + Rex + Rex_W + Rex_R + Rex_X + Rex_B + OpCode + W + MOD + Reg_Op + R_M
            else:
                machineCode = Prefix + OpCode + W + MOD + Reg_Op + R_M

        elif denoteoperand(operand1) == 1 and denoteoperand(operand2) == 2:
            if operand1 == "al" or operand1 == "ax" or operand1 == "eax" or operand1 == "rax":
                OpCode = "1010100"
                Rex_R = "0"
                Rex_X = "0"
                Rex_B = "0"
                if operand1 == "al":
                    changeData(0, operand2)
                    Rex_W = "0"
                    W = "0"


                elif operand1 == "ax":
                    changeData(1, operand2)
                    Prefix = Prefix + "01100110"
                    Rex_W = "0"
                    W = "1"

                elif operand1 == "eax":
                    changeData(1, operand2)
                    Rex_W = "0"
                    W = "1"
                else:
                    changeData(1, operand2)
                    Rex_W = "1"
                    W = "1"

                if operand1 == "rax":
                    machineCode = Prefix + Rex + Rex_W + Rex_R + Rex_X + Rex_B + OpCode + W + Data
                else:
                    machineCode = Prefix + OpCode + W + Data


            else:
                Rex_X = "0"
                Rex_R = "0"
                OpCode = "1111011"
                if operand1 in reg8:
                    changeData(0, operand2)
                    Rex_W = "0"
                    Rex_B = reg8[operand1][0]
                    W = "0"
                    Reg_Op = reg8[operand1][1]
                elif operand1 in reg16:
                    changeData(1, operand2)
                    Prefix = Prefix + "01100110"
                    Rex_W = "0"
                    Rex_B = reg16[operand1][0]
                    W = "1"
                    Reg_Op = reg16[operand1][1]
                elif operand1 in reg32:
                    changeData(1, operand2)
                    Rex_W = "0"
                    Rex_B = reg32[operand1][0]
                    W = "1"
                    Reg_Op = reg32[operand1][1]
                else:
                    changeData(1, operand2)
                    Rex_W = "1"
                    Rex_B = reg64[operand1][0]
                    W = "1"
                    Reg_Op = reg64[operand1][1]

                if isitrex(operand1, operand1):
                    machineCode = Prefix + Rex + Rex_W + Rex_R + Rex_X + Rex_B + OpCode + W + "11000" + Reg_Op + Data
                else:
                    machineCode = Prefix + OpCode + W + "11000" + Reg_Op + Data

        elif denoteoperand(operand2) == 2 and denoteoperand(operand1) != 1:
            memory(operand1)
            if "BYTE" in operand1:
                changeData(0, operand2)
            else:
                changeData(1, operand2)

            if "WORD" in operand1 and "DWORD" not in operand1 and "QWORD" not in operand1:
                Prefix = Prefix + "01100110"

            if "QWORD" in operand1:
                Rex_W = "1"
            else:
                Rex_W = "0"

            Rex_R = "0"

            if "BYTE" in operand1:
                W = "0"
            else:
                W = "1"

            OpCode = "1111011"
            Reg_Op = "000"

            if isitrex(operand1, operand1):
                machineCode = Prefix + Rex + Rex_W + Rex_R + Rex_X + Rex_B + OpCode + W + MOD + Reg_Op + R_M + Scale + Index + Base + Displacement + Data
            else:
                machineCode = Prefix + OpCode + W + MOD + Reg_Op + R_M + Scale + Index + Base + Displacement + Data

        else:
            OpCode = "1000010"
            if denoteoperand(operand1) == 1:
                memory(operand2)
                if operand1 in reg8:
                    Rex_W = "0"
                    Rex_R = reg8[operand1][0]
                    W = "0"
                    Reg_Op = reg8[operand1][1]
                elif operand1 in reg16:
                    Prefix = Prefix + "01100110"
                    Rex_W = "0"
                    Rex_R = reg16[operand1][0]
                    W = "1"
                    Reg_Op = reg16[operand1][1]
                elif operand1 in reg32:
                    Rex_W = "0"
                    Rex_R = reg32[operand1][0]
                    W = "1"
                    Reg_Op = reg32[operand1][1]
                else:
                    Rex_W = "1"
                    Rex_R = reg64[operand1][0]
                    W = "1"
                    Reg_Op = reg64[operand1][1]
            else:
                memory(operand1)
                if operand2 in reg8:
                    Rex_W = "0"
                    Rex_R = reg8[operand2][0]
                    W = "0"
                    Reg_Op = reg8[operand2][1]
                elif operand2 in reg16:
                    Prefix = Prefix + "01100110"
                    Rex_W = "0"
                    Rex_R = reg16[operand2][0]
                    W = "1"
                    Reg_Op = reg16[operand2][1]
                elif operand2 in reg32:
                    Rex_W = "0"
                    Rex_R = reg32[operand2][0]
                    W = "1"
                    Reg_Op = reg32[operand2][1]
                else:
                    Rex_W = "1"
                    Rex_R = reg64[operand2][0]
                    W = "1"
                    Reg_Op = reg64[operand2][1]

            if isitrex(operand1, operand2):
                machineCode = Prefix + Rex + Rex_W + Rex_R + Rex_X + Rex_B + OpCode + W + MOD + Reg_Op + R_M + Scale + Index + Base + Displacement
            else:
                machineCode = Prefix + OpCode + W + MOD + Reg_Op + R_M + Scale + Index + Base + Displacement

    elif instruction == "xchg":
        if denoteoperand(operand1) == 1 and denoteoperand(operand2) == 1:
            if operand1 == "ax" or operand1 == "eax" or operand1 == "rax":
                if operand1 == "ax":
                    Prefix = Prefix + "01100110"
                    Reg_Op = reg16[operand2][1]
                    Rex_W = "0"
                    Rex_B = reg16[operand2][0]
                elif operand1 == "eax":
                    Rex_W = "0"
                    Rex_B = reg32[operand2][0]
                    Reg_Op = reg32[operand2][1]
                else:
                    Rex_W = "1"
                    Rex_B = reg64[operand2][0]
                    Reg_Op = reg64[operand2][1]

                OpCode = "10010"
                Rex_R = "0"
                Rex_X = "0"

                if isitrex(operand1, operand2):
                    machineCode = Prefix + Rex + Rex_W + Rex_R + Rex_X + Rex_B + OpCode + Reg_Op
                else:
                    machineCode = Prefix + OpCode + Reg_Op

            elif operand2 == "ax" or operand2 == "eax" or operand2 == "rax":
                if operand2 == "ax":
                    Prefix = Prefix + "01100110"
                    Reg_Op = reg16[operand1][1]
                    Rex_W = "0"
                    Rex_B = reg16[operand1][0]
                elif operand2 == "eax":
                    Rex_W = "0"
                    Rex_B = reg32[operand1][0]
                    Reg_Op = reg32[operand1][1]
                else:
                    Rex_W = "1"
                    Rex_B = reg64[operand1][0]
                    Reg_Op = reg64[operand1][1]

                OpCode = "10010"
                Rex_R = "0"
                Rex_X = "0"

                if isitrex(operand1, operand2):
                    machineCode = Prefix + Rex + Rex_W + Rex_R + Rex_X + Rex_B + OpCode + Reg_Op
                else:
                    machineCode = Prefix + OpCode + Reg_Op
            else:
                MOD = "11"
                OpCode = "1000011"
                Rex_X = "0"
                if operand1 in reg8:
                    Reg_Op = reg8[operand2][1]
                    R_M = reg8[operand1][1]
                    W = "0"
                    Rex_W = "0"
                    Rex_R = reg8[operand2][0]
                    Rex_B = reg8[operand1][0]
                elif operand1 in reg16:
                    Prefix = Prefix + "01100110"
                    Reg_Op = reg16[operand2][1]
                    R_M = reg16[operand1][1]
                    W = "1"
                    Rex_W = "0"
                    Rex_R = reg16[operand2][0]
                    Rex_B = reg16[operand1][0]
                elif operand1 in reg32:
                    Reg_Op = reg32[operand2][1]
                    R_M = reg32[operand1][1]
                    W = "1"
                    Rex_W = "0"
                    Rex_R = reg32[operand2][0]
                    Rex_B = reg32[operand1][0]
                else:
                    Reg_Op = reg64[operand2][1]
                    R_M = reg64[operand1][1]
                    W = "1"
                    Rex_W = "1"
                    Rex_R = reg64[operand2][0]
                    Rex_B = reg64[operand1][0]

                if isitrex(operand1, operand2):
                    machineCode = Prefix + Rex + Rex_W + Rex_R + Rex_X + Rex_B + OpCode + W + MOD + Reg_Op + R_M
                else:
                    machineCode = Prefix + OpCode + W + MOD + Reg_Op + R_M
        else:
            if denoteoperand(operand1) == 1:
                memory(operand2)
                if operand1 in reg16:
                    Prefix = Prefix + "01100110"
                if operand1 in reg64:
                    Rex_W = "1"
                else:
                    Rex_W = "0"

                if operand1 in reg8:
                    Rex_R = reg8[operand1][0]
                    Reg_Op = reg8[operand1][1]
                elif operand1 in reg16:
                    Rex_R = reg16[operand1][0]
                    Reg_Op = reg16[operand1][1]
                elif operand1 in reg32:
                    Rex_R = reg32[operand1][0]
                    Reg_Op = reg32[operand1][1]
                else:
                    Rex_R = reg64[operand1][0]
                    Reg_Op = reg64[operand1][1]

                if operand1 in reg8:
                    W = "0"
                else:
                    W = "1"

            else:
                memory(operand1)
                if operand2 in reg16:
                    Prefix = Prefix + "01100110"
                if operand2 in reg64:
                    Rex_W = "1"
                else:
                    Rex_W = "0"
                if operand2 in reg8:
                    Rex_R = reg8[operand2][0]
                    Reg_Op = reg8[operand2][1]
                elif operand2 in reg16:
                    Rex_R = reg16[operand2][0]
                    Reg_Op = reg16[operand2][1]
                elif operand2 in reg32:
                    Rex_R = reg32[operand2][0]
                    Reg_Op = reg32[operand2][1]
                else:
                    Rex_R = reg64[operand2][0]
                    Reg_Op = reg64[operand2][1]

                if operand2 in reg8:
                    W = "0"
                else:
                    W = "1"

            OpCode = "1000011"

            if isitrex(operand1, operand2):
                machineCode = Prefix + Rex + Rex_W + Rex_R + Rex_X + Rex_B + OpCode + W + MOD + Reg_Op + R_M + Scale + Index + Base + Displacement
            else:
                machineCode = Prefix + OpCode + W + MOD + Reg_Op + R_M + Scale + Index + Base + Displacement







    elif instruction == "xadd":
        if denoteoperand(operand1) == 1 and denoteoperand(operand2) == 1:
            Rex_X = "0"
            OpCode = "00001111110000"
            D = "0"
            MOD = "11"
            if operand1 in reg8:
                Rex_W = "0"
                Rex_R = reg8[operand2][0]
                Rex_B = reg8[operand1][0]
                W = "0"
                Reg_Op = reg8[operand2][1]
                R_M = reg8[operand1][1]

            elif operand1 in reg16:
                Prefix = Prefix + "01100110"
                Rex_W = "0"
                Rex_R = reg16[operand2][0]
                Rex_B = reg16[operand1][0]
                W = "1"
                Reg_Op = reg16[operand2][1]
                R_M = reg16[operand1][1]

            elif operand1 in reg32:
                Rex_W = "0"
                Rex_R = reg32[operand2][0]
                Rex_B = reg32[operand1][0]
                W = "1"
                Reg_Op = reg32[operand2][1]
                R_M = reg32[operand1][1]

            else:
                Rex_W = "1"
                Rex_R = reg64[operand2][0]
                Rex_B = reg64[operand1][0]
                W = "1"
                Reg_Op = reg64[operand2][1]
                R_M = reg64[operand1][1]

            if isitrex(operand1, operand2):
                machineCode = Prefix + Rex + Rex_W + Rex_R + Rex_X + Rex_B + OpCode + D + W + MOD + Reg_Op + R_M
            else:
                machineCode = Prefix + OpCode + D + W + MOD + Reg_Op + R_M

        else:
            memory(operand1)
            OpCode = "00001111110000"
            D = "0"

            if operand2 in reg8:
                Rex_W = "0"
                Rex_R = reg8[operand2][0]
                Reg_Op = reg8[operand2][1]
                W = "0"

            elif operand2 in reg16:
                Prefix = Prefix + "01100110"
                Rex_W = "0"
                Rex_R = reg16[operand2][0]
                Reg_Op = reg16[operand2][1]
                W = "1"


            elif operand2 in reg32:
                Rex_W = "0"
                Rex_R = reg32[operand2][0]
                Reg_Op = reg32[operand2][1]
                W = "1"


            else:
                Rex_W = "1"
                Rex_R = reg64[operand2][0]
                Reg_Op = reg64[operand2][1]
                W = "1"

            if isitrex(operand1, operand2):
                machineCode = Prefix + Rex + Rex_W + Rex_R + Rex_X + Rex_B + OpCode + D + W + MOD + Reg_Op + R_M + Scale + Index + Base + Displacement
            else:
                machineCode = Prefix + OpCode + D + W + MOD + Reg_Op + R_M + Scale + Index + Base + Displacement


    elif instruction == "imul":
        if operand2 == "":
            if denoteoperand(operand1) == 1:
                Rex_R = "0"
                Rex_X = "0"
                OpCode = "1111011"
                MOD = "11"
                Reg_Op = "101"

                if operand1 in reg8:
                    Rex_W = "0"
                    Rex_B = reg8[operand1][0]
                    W = "0"
                    R_M = reg8[operand1][1]

                elif operand1 in reg16:
                    Prefix = Prefix + "01100110"
                    Rex_W = "0"
                    Rex_B = reg16[operand1][0]
                    W = "1"
                    R_M = reg16[operand1][1]

                elif operand1 in reg32:
                    Rex_W = "0"
                    Rex_B = reg32[operand1][0]
                    W = "1"
                    R_M = reg32[operand1][1]

                else:
                    Rex_W = "1"
                    Rex_B = reg64[operand1][0]
                    W = "1"
                    R_M = reg64[operand1][1]

                if isitrex(operand1, operand1):
                    machineCode = Prefix + Rex + Rex_W + Rex_R + Rex_X + Rex_B + OpCode + W + MOD + Reg_Op + R_M
                else:
                    machineCode = Prefix + OpCode + W + MOD + Reg_Op + R_M


            else:
                memory(operand1)
                Rex_R = "0"
                OpCode = "1111011"
                Reg_Op = "101"

                if "BYTE" in operand1:
                    Rex_W = "0"
                    W = "0"

                elif "WORD" in operand1 and "DWORD" not in operand1 and "QWORD" not in operand1:
                    Prefix = Prefix + "01100110"
                    Rex_W = "0"
                    W = "1"

                elif "DWORD" in operand1:
                    Rex_W = "0"
                    W = "1"

                else:
                    Rex_W = "1"
                    W = "1"

                if isitrex(operand1, operand1):
                    machineCode = Prefix + Rex + Rex_W + Rex_R + Rex_X + Rex_B + OpCode + W + MOD + Reg_Op + R_M + Scale + Index + Base + Displacement
                else:
                    machineCode = Prefix + OpCode + W + MOD + Reg_Op + R_M + Scale + Index + Base + Displacement

        elif thirdOperand == "":
            if denoteoperand(operand1) == 1 and denoteoperand(operand2) == 1:
                Rex_X = "0"
                D = "0"
                OpCode = "00001111101011"
                MOD = "11"

                if operand1 in reg8:
                    Rex_W = "0"
                    Rex_R = reg8[operand2][0]
                    Rex_B = reg8[operand1][0]
                    W = "0"
                    Reg_Op = reg8[operand2][1]
                    R_M = reg8[operand1][1]

                elif operand1 in reg16:
                    Prefix = Prefix + "01100110"
                    Rex_W = "0"
                    Rex_R = reg16[operand2][0]
                    Rex_B = reg16[operand1][0]
                    W = "1"
                    Reg_Op = reg16[operand2][1]
                    R_M = reg16[operand1][1]

                elif operand1 in reg32:
                    Rex_W = "0"
                    Rex_R = reg32[operand2][0]
                    Rex_B = reg32[operand1][0]
                    W = "1"
                    Reg_Op = reg32[operand2][1]
                    R_M = reg32[operand1][1]

                else:
                    Rex_W = "1"
                    Rex_R = reg64[operand2][0]
                    Rex_B = reg64[operand1][0]
                    W = "1"
                    Reg_Op = reg64[operand2][1]
                    R_M = reg64[operand1][1]

                if isitrex(operand1, operand2):
                    machineCode = Prefix + Rex + Rex_W + Rex_R + Rex_X + Rex_B + OpCode + D + W + MOD + Reg_Op + R_M
                else:
                    machineCode = Prefix + OpCode + D + W + MOD + Reg_Op + R_M


            elif denoteoperand(operand1) == 1 and denoteoperand(operand2) == 2:
                pass

            else:
                memory(operand2)
                OpCode = "00001111101011"
                D = "1"

                if operand1 in reg8:
                    Rex_W = "0"
                    Rex_R = reg8[operand1][0]
                    W = "0"
                    Reg_Op = reg8[operand1][1]

                elif operand1 in reg16:
                    Prefix = Prefix + "01100110"
                    Rex_W = "0"
                    Rex_R = reg16[operand1][0]
                    W = "1"
                    Reg_Op = reg16[operand1][1]

                elif operand1 in reg32:
                    Rex_W = "0"
                    Rex_R = reg32[operand1][0]
                    W = "1"
                    Reg_Op = reg32[operand1][1]

                else:
                    Rex_W = "1"
                    Rex_R = reg64[operand1][0]
                    W = "1"
                    Reg_Op = reg64[operand1][1]

                if isitrex(operand1, operand2):
                    machineCode = Prefix + Rex + Rex_W + Rex_R + Rex_X + Rex_B + OpCode + D + W + MOD + Reg_Op + R_M + Scale + Index + Base + Displacement
                else:
                    machineCode = Prefix + OpCode + D + W + MOD + Reg_Op + R_M + Scale + Index + Base + Displacement

        else:
            if denoteoperand(operand2) == 1:
                Rex_X = "0"

                if operand1 in reg8:
                    Rex_W = "0"
                    Rex_R = reg8[operand1][0]
                    Rex_B = reg8[operand2][0]

                elif operand1 in reg16:
                    Prefix = Prefix + "01100110"
                    Rex_W = "0"
                    Rex_R = reg16[operand1][0]
                    Rex_B = reg16[operand2][0]

                elif operand1 in reg32:
                    Rex_W = "0"
                    Rex_R = reg32[operand1][0]
                    Rex_B = reg32[operand2][0]

                else:
                    Rex_W = "1"
                    Rex_R = reg64[operand1][0]
                    Rex_B = reg64[operand2][0]

            else:
                memory(operand2)
                Rex_R = "0"

                if operand1 in reg8:
                    Rex_W = "0"

                elif operand1 in reg16:
                    Prefix = Prefix + "01100110"
                    Rex_W = "0"

                elif operand1 in reg32:
                    Rex_W = "0"

                else:
                    Rex_W = "1"

    elif instruction == "idiv":
        if denoteoperand(operand1) == 1:
            Rex_R = "0"
            Rex_X = "0"
            OpCode = "111101"
            D = "1"
            MOD = "11"
            Reg_Op = "111"

            if operand1 in reg8:
                Rex_W = "0"
                Rex_B = reg8[operand1][0]
                W = "0"
                R_M = reg8[operand1][1]


            elif operand1 in reg16:
                Prefix = Prefix + "01100110"
                Rex_W = "0"
                Rex_B = reg16[operand1][0]
                W = "1"
                R_M = reg16[operand1][1]


            elif operand1 in reg32:
                Rex_W = "0"
                Rex_B = reg32[operand1][0]
                W = "1"
                R_M = reg32[operand1][1]


            else:
                Rex_W = "1"
                Rex_B = reg64[operand1][0]
                W = "1"
                R_M = reg64[operand1][1]

            if isitrex(operand1, operand1):
                machineCode = Prefix + Rex + Rex_W + Rex_R + Rex_X + Rex_B + OpCode + D + W + MOD + Reg_Op + R_M
            else:
                machineCode = Prefix + OpCode + D + W + MOD + Reg_Op + R_M

        else:
            memory(operand1)
            Rex_R = "0"
            D = "1"
            OpCode = "111101"
            Reg_Op = "111"

            if "BYTE" in operand1:
                Rex_W = "0"
                W = "0"

            elif "WORD" in operand1 and "DWORD" not in operand1 and "QWORD" not in operand1:
                Prefix = Prefix + "01100110"
                Rex_W = "0"
                W = "1"

            elif "DWORD" in operand1:
                Rex_W = "0"
                W = "1"

            else:
                Rex_W = "1"
                W = "1"

            if isitrex(operand1, operand1):
                machineCode = Prefix + Rex + Rex_W + Rex_R + Rex_X + Rex_B + OpCode + D + W + MOD + Reg_Op + R_M + Scale + Index + Base + Displacement
            else:
                machineCode = Prefix + OpCode + D + W + MOD + Reg_Op + R_M + Scale + Index + Base + Displacement

    elif instruction == "bsf" or instruction == "bsr":
        if denoteoperand(operand1) == 1 and denoteoperand(operand2) == 1:
            if operand1 in reg16:
                Prefix = Prefix + "01100110"

            if operand1 in reg64:
                Rex_W = "1"
            else:
                Rex_W = "0"

            Rex_X = "0"
            if operand1 in reg16:
                Rex_R = reg16[operand1][0]
                Rex_B = reg16[operand2][0]

            elif operand1 in reg32:
                Rex_R = reg32[operand1][0]
                Rex_B = reg32[operand2][0]

            else:
                Rex_R = reg64[operand1][0]
                Rex_B = reg64[operand2][0]

            if instruction == "bsf":
                OpCode = "0000111110111100"
            else:
                OpCode = "0000111110111101"

            MOD = "11"
            if operand1 in reg16:
                Reg_Op = reg16[operand1][1]
                R_M = reg16[operand2][1]

            elif operand1 in reg32:
                Reg_Op = reg32[operand1][1]
                R_M = reg32[operand2][1]

            else:
                Reg_Op = reg64[operand1][1]
                R_M = reg64[operand2][1]

            if isitrex(operand1, operand2):
                machineCode = Prefix + Rex + Rex_W + Rex_R + Rex_X + Rex_B + OpCode + MOD + Reg_Op + R_M
            else:
                machineCode = Prefix + OpCode + MOD + Reg_Op + R_M

        else:
            memory(operand2)

            if operand1 in reg16:
                Prefix = Prefix + "01100110"

            if operand1 in reg64:
                Rex_W = "1"
            else:
                Rex_W = "0"

            if operand1 in reg16:
                Rex_R = reg16[operand1][0]
                Reg_Op = reg16[operand1][1]

            elif operand1 in reg32:
                Rex_R = reg32[operand1][0]
                Reg_Op = reg32[operand1][1]
            else:
                Rex_R = reg64[operand1][0]
                Reg_Op = reg64[operand1][1]

            if instruction == "bsf":
                OpCode = "0000111110111100"
            else:
                OpCode = "0000111110111101"

            if isitrex(operand1, operand2):
                machineCode = Prefix + Rex + Rex_W + Rex_R + Rex_X + Rex_B + OpCode + MOD + Reg_Op + R_M + Scale + Index + Base + Displacement
            else:
                machineCode = Prefix + OpCode + MOD + Reg_Op + R_M + Scale + Index + Base + Displacement

    elif instruction == "stc":
        machineCode = "11111001"

    elif instruction == "clc":
        machineCode = "11111000"

    elif instruction == "std":
        machineCode = "11111101"

    elif instruction == "cld":
        machineCode = "11111100"

    elif instruction == "jmp":
        if denoteoperand(operand1) == 1:
            Rex_W = 0
            Rex_R = 0
            Rex_X = 0
            OpCode = "11111111"
            MOD = "11"
            Reg_Op = "100"
            if operand1 in reg16:
                Prefix = Prefix + "01100110"
                Rex_B = reg16[operand1][0]
                R_M = reg16[operand1][1]
            else:
                Rex_B = reg64[operand1][0]
                R_M = reg64[operand1][1]

            if operand1 in regr:
                machineCode = Prefix + Rex + Rex_W + Rex_R + Rex_X + Rex_B + OpCode + MOD + Reg_Op + R_M
            else:
                machineCode = Prefix + OpCode + MOD + Reg_Op + R_M

        elif denoteoperand(operand1) == 15 or denoteoperand(operand1) == 2:
            machineCode = "1110100100000000000000000000000000000000"
        else:
            memory(operand1)
            Rex_W = "0"
            Rex_R = "0"
            OpCode = "11111111"
            Reg_Op = "100"
            if "WORD" in operand1 and "DWORD" not in operand1 and "QWORD" not in operand1:
                Prefix = Prefix + "01100110"

            if isitrex(operand1, operand1):
                machineCode = Prefix + Rex + Rex_W + Rex_R + Rex_X + Rex_B + OpCode + MOD + Reg_Op + R_M + Scale + Index + Base + Displacement
            else:
                machineCode = Prefix + OpCode + MOD + Reg_Op + R_M + Scale + Index + Base + Displacement

    elif instruction in jump:  # Jcc
        machineCode = "000011111000" + jump[instruction] + "00000000000000000000000000000000"
        print(jump[instruction])
    elif instruction == "jrcxz":
        machineCode = "1110001100000000"

    elif instruction == "shl" or instruction == "shr":
        if operand2 == "":

            if denoteoperand(operand1) == 1:

                if operand1 in reg8:
                    Rex_W = "0"
                    Rex_R = reg8[operand1][0]
                    W = "0"
                    Reg_Op = reg8[operand1][1]

                elif operand1 in reg16:
                    Prefix = Prefix + "01100110"
                    Rex_W = "0"
                    Rex_R = reg16[operand1][0]
                    W = "1"
                    Reg_Op = reg16[operand1][1]

                elif operand1 in reg32:
                    Rex_W = "0"
                    Rex_R = reg32[operand1][0]
                    W = "1"
                    Reg_Op = reg32[operand1][1]

                else:
                    Rex_W = "1"
                    Rex_R = reg64[operand1][0]
                    W = "1"
                    reg64[operand1][1]

                Rex_B = "0"
                Rex_X = "0"

                OpCode = "1101000"

                if isitrex(operand1, operand1):
                    if instruction == "shl":
                        machineCode = Prefix + Rex + Rex_W + Rex_R + Rex_X + Rex_B + OpCode + W + "11100" + Reg_Op
                    else:
                        machineCode = Prefix + Rex + Rex_W + Rex_R + Rex_X + Rex_B + OpCode + W + "11101" + Reg_Op
                else:
                    if instruction == "shl":
                        machineCode = Prefix + OpCode + W + "11100" + Reg_Op
                    else:
                        machineCode = Prefix + OpCode + W + "11101" + Reg_Op

            else:
                memory(operand1)

                if "WORD" in operand1 and "DWORD" not in operand1 and "QWORD" not in operand1:
                    Prefix = Prefix + "01100110"

                Rex_R = "0"

                if "QWORD" in operand1:
                    Rex_W = "1"
                else:
                    Rex_W = "0"

                OpCode = "1101000"

                if "BYTE" in operand1:
                    W = "0"
                else:
                    W = "1"

                if isitrex(operand1, operand1):
                    if instruction == "shl":
                        machineCode = Prefix + Rex + Rex_W + Rex_R + Rex_X + Rex_B + OpCode + W + "100" + R_M + Scale + Index + Base + Displacement
                    else:
                        machineCode = Prefix + Rex + Rex_W + Rex_R + Rex_X + Rex_B + OpCode + W + MOD + "101" + R_M + Scale + Index + Base + Displacement
                else:
                    if instruction == "shl":
                        machineCode = Prefix + OpCode + W + "100" + R_M + Scale + Index + Base + Displacement
                    else:
                        machineCode = Prefix + OpCode + W + "101" + R_M + Scale + Index + Base + Displacement

        else:
            if denoteoperand(operand1) == 1:
                changeData(0, operand2)
                if operand1 in reg8:
                    Rex_W = "0"
                    Rex_R = reg8[operand1][0]
                    W = "0"
                    Reg_Op = reg8[operand1][1]

                elif operand1 in reg16:
                    Prefix = Prefix + "01100110"
                    Rex_W = "0"
                    Rex_R = reg16[operand1][0]
                    W = "1"
                    Reg_Op = reg16[operand1][1]

                elif operand1 in reg32:
                    Rex_W = "0"
                    Rex_R = reg32[operand1][0]
                    W = "1"
                    Reg_Op = reg32[operand1][1]

                else:
                    Rex_W = "1"
                    Rex_R = reg64[operand1][0]
                    W = "1"
                    reg64[operand1][1]

                Rex_B = "0"
                Rex_X = "0"

                OpCode = "1100000"

                if isitrex(operand1, operand1):
                    if instruction == "shl":
                        machineCode = Prefix + Rex + Rex_W + Rex_R + Rex_X + Rex_B + OpCode + W + "11100" + Reg_Op + Data
                    else:
                        machineCode = Prefix + Rex + Rex_W + Rex_R + Rex_X + Rex_B + OpCode + W + "11101" + Reg_Op + Data
                else:
                    if instruction == "shl":
                        machineCode = Prefix + OpCode + W + "11100" + Reg_Op + Data
                    else:
                        machineCode = Prefix + OpCode + W + "11101" + Reg_Op + Data
            else:
                memory(operand1)
                changeData(0, operand2)
                if "WORD" in operand1 and "DWORD" not in operand1 and "QWORD" not in operand1:
                    Prefix = Prefix + "01100110"

                Rex_R = "0"

                if "QWORD" in operand1:
                    Rex_W = "1"
                else:
                    Rex_W = "0"

                OpCode = "1100000"

                if "BYTE" in operand1:
                    W = "0"
                else:
                    W = "1"

                if isitrex(operand1, operand1):
                    if instruction == "shl":
                        machineCode = Prefix + Rex + Rex_W + Rex_R + Rex_X + Rex_B + OpCode + W + "100" + R_M + Scale + Index + Base + Displacement + Data
                    else:
                        machineCode = Prefix + Rex + Rex_W + Rex_R + Rex_X + Rex_B + OpCode + W + MOD + "101" + R_M + Scale + Index + Base + Displacement + Data
                else:
                    if instruction == "shl":
                        machineCode = Prefix + OpCode + W + "100" + R_M + Scale + Index + Base + Displacement + Data
                    else:
                        machineCode = Prefix + OpCode + W + "101" + R_M + Scale + Index + Base + Displacement + Data


    elif instruction == "neg" or instruction == "not":
        if denoteoperand(operand1) == 1:
            if operand1 in reg16:
                Prefix = Prefix + "01100110"

            OpCode = "1111011"

            if operand1 in reg8:
                W = "0"
            else:
                W = "1"

            MOD = "11"

            if operand1 in reg8:
                Reg_Op = reg8[operand1][1]
                Rex_B = reg8[operand1][0]

            elif operand1 in reg16:
                Reg_Op = reg16[operand1][1]
                Rex_B = reg16[operand1][0]

            elif operand1 in reg32:
                Reg_Op = reg32[operand1][1]
                Rex_B = reg32[operand1][0]

            else:
                Reg_Op = reg64[operand1][1]
                Rex_B = reg64[operand1][0]

            Rex_R = "0"
            Rex_X = "0"

            if operand1 in reg64:
                Rex_W = "1"
            else:
                Rex_W = "0"

            if isitrex(operand1, operand1):
                if instruction == "not":
                    machineCode = Prefix + Rex + Rex_W + Rex_R + Rex_X + Rex_B + OpCode + W + MOD + "010" + Reg_Op
                else:
                    machineCode = Prefix + Rex + Rex_W + Rex_R + Rex_X + Rex_B + OpCode + W + MOD + "011" + Reg_Op

            else:
                if instruction == "not":
                    machineCode = Prefix + OpCode + W + MOD + "010" + Reg_Op
                else:
                    machineCode = Prefix + OpCode + W + MOD + "011" + Reg_Op

        else:
            memory(operand1)
            if "WORD" in operand1 and "QWORD" not in operand1 and "DWORD" not in operand1:
                Prefix = Prefix + "01100110"

            if "QWORD" in operand1:
                Rex_W = "1"
            else:
                Rex_W = "0"

            Rex_R = "0"

            OpCode = "1111011"

            if "BYTE" in operand1:
                W = "0"
            else:
                W = "1"

            if isitrex(operand1, operand1):
                if instruction == "not":
                    machineCode = Prefix + Rex + Rex_W + Rex_R + Rex_X + Rex_B + OpCode + W + MOD + "010" + R_M + Scale + Index + Base + Displacement
                else:
                    machineCode = Prefix + Rex + Rex_W + Rex_R + Rex_X + Rex_B + OpCode + W + MOD + "011" + R_M + Scale + Index + Base + Displacement

            else:
                if instruction == "not":
                    machineCode = Prefix + OpCode + W + MOD + "010" + R_M + Scale + Index + Base + Displacement
                else:
                    machineCode = Prefix + OpCode + W + MOD + "011" + R_M + Scale + Index + Base + Displacement


    elif instruction == "call":
        if denoteoperand(operand1) == 2:
            machineCode = "1110100000000000000000000000000000000000"
        elif denoteoperand(operand1) == 15:
            machineCode = "1110100000000000000000000000000000000000"

        elif denoteoperand(operand1) == 1:
            Rex_W = 0
            Rex_R = 0
            Rex_X = 0
            OpCode = "11111111"
            MOD = "11"
            Reg_Op = "010"
            if operand1 in reg16:
                Prefix = Prefix + "01100110"
                Rex_B = reg16[operand1][0]
                R_M = reg16[operand1][1]
            else:
                Rex_B = reg64[operand1][0]
                R_M = reg64[operand1][1]

            if operand1 in regr:
                machineCode = Prefix + Rex + Rex_W + Rex_R + Rex_X + Rex_B + OpCode + MOD + Reg_Op + R_M
            else:
                machineCode = Prefix + OpCode + MOD + Reg_Op + R_M
        else:
            memory(operand1)
            Rex_W = "0"
            Rex_R = "0"
            OpCode = "11111111"
            Reg_Op = "010"
            if "WORD" in operand1 and "DWORD" not in operand1 and "QWORD" not in operand1:
                Prefix = Prefix + "01100110"

            if isitrex(operand1, operand1):
                machineCode = Prefix + Rex + Rex_W + Rex_R + Rex_X + Rex_B + OpCode + MOD + Reg_Op + R_M + Scale + Index + Base + Displacement
            else:
                machineCode = Prefix + OpCode + MOD + Reg_Op + R_M + Scale + Index + Base + Displacement

    elif instruction == "ret":
        if operand1 == "":
            machineCode = "11000011"
        else:
            machineCode = "11000010"
            changeData(1, operand1)
            Data = Data[: 16]
            machineCode = machineCode + Data

    elif instruction == "syscall":
        machineCode = "0000111100000101"

    elif instruction == "push":
        if denoteoperand(operand1) == 1:
            Rex_R = "0"
            Rex_X = "0"
            OpCode = "01010"
            if operand1 in reg16:
                Prefix = Prefix + "01100110"
                Rex_W = "0"
                Rex_B = reg16[operand1][0]
                Reg_Op = reg16[operand1][1]
            else:
                Rex_W = "1"
                Rex_B = reg64[operand1][0]
                Reg_Op = reg64[operand1][1]

            if isitrex(operand1, operand1):
                machineCode = Prefix + Rex + Rex_W + Rex_R + Rex_X + Rex_B + OpCode + Reg_Op
            else:
                machineCode = Prefix + OpCode + Reg_Op


        elif denoteoperand(operand1) == 2:
            if "-" in operand2:
                if "x" in operand2:
                    u = operand2[3:]

                elif "b" in operand2:
                    u = operand2[3:]
                    u = hex(int(operand2, 2))
                    u = u[2:]

                else:
                    u = operand2[1:]
                    u = hex(int(operand2, 10))
                    u = u[2:]

            else:
                if "x" in operand2:
                    u = operand2[2:]

                elif "b" in operand2:
                    u = operand2[2:]
                    u = hex(int(operand2, 2))
                    u = u[2:]

                else:
                    u = hex(int(operand2, 10))
                    u = u[2:]

            if len(u) <= 2:
                OpCode = "01101010"
                changeData(0, operand1)
                machineCode = OpCode + Data
            else:
                OpCode = "01101000"
                changeData(1, operand1)
                machineCode = OpCode + Data


        else:
            Rex_R = "0"
            OpCode = "11111111"
            Reg_Op = "110"
            memory(operand1)
            if "WORD" in operand1 and "QWORD" not in operand1:
                Rex_W = "0"
                Prefix = Prefix + "01100110"
            else:
                Rex_W = "1"

            if isitrex(operand1, operand1):
                machineCode = Prefix + Rex + Rex_W + Rex_R + Rex_X + Rex_B + OpCode + MOD + Reg_Op + R_M + Scale + Index + Base + Displacement
            else:
                machineCode = Prefix + OpCode + MOD + Reg_Op + R_M + Scale + Index + Base + Displacement

    elif instruction == "pop":
        if denoteoperand(operand1) == 1:
            if operand1 in regr:
                if operand1 in reg16:
                    OpCode = "01011"
                    Prefix = "01100110"
                    Reg_Op = reg16[operand1][1]
                    Rex_W = "0"
                    Rex_R = "0"
                    Rex_X = "0"
                    Rex_B = reg16[operand1][0]
                    machineCode = Prefix + Rex + Rex_W + Rex_R + Rex_X + Rex_B + OpCode + Reg_Op
                else:
                    OpCode = "01011"
                    Reg_Op = reg64[operand1][1]
                    Rex_W = "0"
                    Rex_R = "0"
                    Rex_X = "0"
                    Rex_B = reg64[operand1][0]
                    machineCode = Rex + Rex_W + Rex_R + Rex_X + Rex_B + OpCode + Reg_Op
            else:
                if operand1 in reg16:
                    OpCode = "01011"
                    Prefix = "01100110"
                    Reg_Op = reg16[operand1][1]
                    machineCode = Prefix + OpCode + Reg_Op
                else:
                    OpCode = "01011"
                    Reg_Op = reg64[operand1][1]
                    machineCode = OpCode + Reg_Op
        else:
            OpCode = "10001111"
            memory(operand1)

            if isitrex(operand1, operand1):
                if "WORD" in operand1:
                    Prefix = Prefix + "01100110"

                Rex_W = "0"
                Rex_R = "0"

                machineCode = Prefix + Rex + Rex_W + Rex_R + Rex_X + Rex_B + OpCode + MOD + "000" + R_M + Scale + Index + Base + Displacement

            else:
                if "WORD" in operand1 and "QWORD" not in operand1 and "DWORD" not in operand1:
                    Prefix = Prefix + "01100110"

                machineCode = Prefix + OpCode + MOD + "000" + R_M + Scale + Index + Base + Displacement

    else:
        machineCode = "Error: no such instruction: `" + asmcode + "\'"

    return machineCode


assemblycode = input()
binarycode = convert(assemblycode)
#print(binarycode)
print(hex(int(binarycode, 2))[2:])
