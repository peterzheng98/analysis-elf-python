from capstone import *
import re

asmEngine = Cs(CS_ARCH_ARM64, CS_MODE_ARM + CS_MODE_LITTLE_ENDIAN)
asmEngine.detail = True
MemoryAccessRegex = r'#(\d+): MemoryAccess: @([0-9xA-Fa-f]*) ([0-9xA-Fa-f]*) size=(\d+) is_write=(\d+) shadow_mem=([0-9xA-Fa-f]*) {([0-9xA-Fa-f]*), ([0-9xA-Fa-f]*), ([0-9xA-Fa-f]*), ([0-9xA-Fa-f]*)}'
FunctionExitRegex = r'#(\d+): FuncExit'
FunctionEntryRegex = r'#(\d+): FuncEntry ([0-9xA-Fa-f]*)'
ELFFunctionHeaderRegex = r'([a-f0-9A-F]{16}) <(.*)>:'
ELFInstructionRegex = r'([a-f0-9A-F]*):	([a-f0-9A-F]{8}) 	(.*)'

def load_objdump_elf(elf_objdump):
    Blocklist = []
    BlockDict = {}
    InstDict = {}
    InstRevDict = {}
    function_header_pattern = re.compile(ELFFunctionHeaderRegex)
    instruction_pattern = re.compile(ELFInstructionRegex)
    current_block = None
    objdump_elf_file = elf_objdump
    inst_lines = open(objdump_elf_file).readlines()
    for line in inst_lines:
        function_header = function_header_pattern.findall(line)
        instruction = instruction_pattern.findall(line)
        if len(function_header) != 0:
            pc, func = function_header[0]
            current_block = Block(int(pc, 16), func)
            Blocklist.append(current_block)
            BlockDict[int(pc, 16)] = current_block
            # print('\033[35m', 'Now we are entering block at pc 0x{:X}, name: {}\033[0m'.format(int(pc, 16), func))
            continue
        if len(instruction) != 0:
            if current_block is None:
                raise NotImplementedError()
            pc, inst, sup_inst = instruction[0]
            current_inst = (int(inst, 16)).to_bytes(4, byteorder="little")
            disassemble = asmEngine.disasm(current_inst, int(pc, 16))
            current_inst = (int(pc, 16), [j for j in disassemble][0])
            current_block.addInst(current_inst)
            InstDict[int(pc, 16)] = current_inst[1]
            InstRevDict[int(pc, 16)] = current_block
            continue
    print('ELF Loaded')
    return BlockDict, InstDict, InstRevDict