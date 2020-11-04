
/*! @file
 *  This is an example of the PIN tool that demonstrates some basic PIN APIs 
 *  and could serve as the starting point for developing your first PIN tool
 */

#include "pin.H"
#include <iostream>
#include <fstream>
#include <stdlib.h>
#include <string.h>
#include <string>

#define NUM_INSTR_DESTINATIONS 4
#define NUM_INSTR_SOURCES 4

//FILE *fptr1,*fptr2;
typedef struct m
{
    void* addr;
    void* ip;
    int valid;
} memory_struct;

memory_struct memory_write[NUM_INSTR_DESTINATIONS];
int start_tracing = 0;

typedef struct trace_instr_format {
    uint64_t encode_key;
    uint64_t ip;  // instruction pointer (program counter) value

    uint32_t is_branch;    // is this branch
    uint32_t branch_taken; // if so, is this taken

    uint8_t destination_registers[NUM_INSTR_DESTINATIONS]; // output registers
    uint8_t source_registers[NUM_INSTR_SOURCES];           // input registers

    uint64_t destination_memory[NUM_INSTR_DESTINATIONS]; // output memory
    uint64_t source_memory[NUM_INSTR_SOURCES];           // input memory

    uint8_t d_valid[NUM_INSTR_DESTINATIONS];
    uint8_t d_value[NUM_INSTR_DESTINATIONS][64];

    uint8_t s_valid[NUM_INSTR_SOURCES];
    uint8_t s_value[NUM_INSTR_SOURCES][64];

} trace_instr_format_t;

/* ================================================================== */
// Global variables 
/* ================================================================== */

UINT64 instrCount = 0;

FILE* out;

bool output_file_closed = false;
bool tracing_on = false;

trace_instr_format_t curr_instr;
trace_instr_format_t prev_insn;

/* ===================================================================== */
// Command line switches
/* ===================================================================== */
KNOB<std::string> KnobOutputFile(KNOB_MODE_WRITEONCE,  "pintool", "o", "champsim.trace", 
        "specify file name for Champsim tracer output");

KNOB<UINT64> KnobSkipInstructions(KNOB_MODE_WRITEONCE, "pintool", "s", "0", 
        "How many instructions to skip before tracing begins");

KNOB<UINT64> KnobTraceInstructions(KNOB_MODE_WRITEONCE, "pintool", "t", "1000000", 
        "How many instructions to trace");

/* ===================================================================== */
// Utilities
/* ===================================================================== */

/*!
 *  Print out help message.
 */
INT32 Usage()
{
    std::cerr << "This tool creates a register and memory access trace" << std::endl 
        << "Specify the output trace file with -o" << std::endl 
        << "Specify the number of instructions to skip before tracing with -s" << std::endl
        << "Specify the number of instructions to trace with -t" << std::endl << std::endl;

    std::cerr << KNOB_BASE::StringKnobSummary() << std::endl;

    return -1;
}

/* ===================================================================== */
// Analysis routines
/* ===================================================================== */

void BeginInstruction(VOID *ip, UINT32 op_code, VOID *opstring)
{
    if(start_tracing > 0)
    {
        for(int i=0; i < NUM_INSTR_DESTINATIONS; i++)
        {
            if(memory_write[i].valid == 1)
            {
                uint8_t value;
                prev_insn.destination_memory[i] = (unsigned long long int)(memory_write[i].addr);
		prev_insn.d_valid[i] = 1;
                for(int j = 0; j < 64; j++)
                {
                    PIN_SafeCopy(&value, (VOID*)((char*)(memory_write[i].addr) + j), 1);
                    prev_insn.d_value[i][j] = value;
                }   
            }
            else
            {
                break;
            }
        }
    }
    start_tracing++;

    bzero(memory_write, sizeof(memory_struct)*NUM_INSTR_DESTINATIONS);

    instrCount++;

    if(instrCount > KnobSkipInstructions.Value()) 
    {
        tracing_on = true;

        if(instrCount > (KnobTraceInstructions.Value()+KnobSkipInstructions.Value()))
            tracing_on = false;
    }

    if(!tracing_on) 
        return;

    // reset the current instruction
    curr_instr.ip = (unsigned long long int)ip;

    curr_instr.is_branch = 0;
    curr_instr.branch_taken = 0;

    for(int i=0; i<NUM_INSTR_DESTINATIONS; i++) 
    {
        curr_instr.destination_registers[i] = 0;
        curr_instr.destination_memory[i] = 0;
        curr_instr.d_valid[i] = 0;
        for (int j=0; j<64;j++)
        {
            curr_instr.d_value[i][j] = 0;
        }
    }

    for(int i=0; i<NUM_INSTR_SOURCES; i++) 
    {
        curr_instr.source_registers[i] = 0;
        curr_instr.source_memory[i] = 0;
	curr_instr.s_valid[i] = 0;
        for (int j=0; j<64;j++)
        {
            curr_instr.s_value[i][j]=0;
        }
    }
}

void EndInstruction()
{
    if(start_tracing > 1)
    {
        if(instrCount > KnobSkipInstructions.Value())
        {
            tracing_on = true;

            if(instrCount <= (KnobTraceInstructions.Value()+KnobSkipInstructions.Value()))
            {
                // keep tracing
                if (prev_insn.ip != 0){
		    uint8_t buffer[1152];
		    uint32_t index = 0;
		    prev_insn.encode_key = 0;
		    memcpy(buffer+index, &prev_insn, 32);
		    index += 32;
	    	    for (int i = 0; i < 4; i++){
			if (prev_insn.d_valid[i]){
			    memcpy(buffer+index, &prev_insn.destination_memory[i], 8);
			    index += 8;
			    memcpy(buffer+index, &prev_insn.d_value[i], 64);
			    index += 64;
			    prev_insn.encode_key += ((0xfULL) << (32 + 4*i));
			}
		    }
	    	    for (int i = 0; i < 4; i++){
			if (prev_insn.s_valid[i]){
			    memcpy(buffer+index, &prev_insn.source_memory[i], 8);
			    index += 8;
			    memcpy(buffer+index, &prev_insn.s_value[i], 64);
			    index += 64;
			    prev_insn.encode_key += ((0xfULL) << (48 + 4*i));
			}
		    }
		    prev_insn.encode_key = (((index - 8) & 0xffffffffULL) | prev_insn.encode_key);
		    memcpy(buffer, &prev_insn.encode_key, 8);
		    fwrite(buffer, 1, index, out);
		}
                prev_insn = curr_instr;
            }
            else
            {
                tracing_on = false;
                // close down the file, we're done tracing
                if(!output_file_closed)
                {
                    fclose(out);
                    output_file_closed = true;
                }
		PIN_Detach();
                //exit(0);
            }
        }
    }
}

void BranchOrNot(UINT32 taken)
{
    //printf("[%d] ", taken);

    curr_instr.is_branch = 1;
    if(taken != 0)
    {
        curr_instr.branch_taken = 1;
    }
}

void RegRead(UINT32 i, UINT32 index)
{
    if(!tracing_on) return;

    REG r = (REG)i;

    int already_found = 0;
    for(int i=0; i<NUM_INSTR_SOURCES; i++)
    {
        if(curr_instr.source_registers[i] == ((unsigned char)r))
        {
            already_found = 1;
            break;
        }
    }
    if(already_found == 0)
    {
        for(int i=0; i<NUM_INSTR_SOURCES; i++)
        {
            if(curr_instr.source_registers[i] == 0)
            {
                curr_instr.source_registers[i] = (unsigned char)r;
                break;
            }
        }
    }
}

void RegWrite(REG i, UINT32 index)
{
    if(!tracing_on) return;

    REG r = (REG)i;

    int already_found = 0;
    for(int i=0; i<NUM_INSTR_DESTINATIONS; i++)
    {
        if(curr_instr.destination_registers[i] == ((unsigned char)r))
        {
            already_found = 1;
            break;
        }
    }
    if(already_found == 0)
    {
        for(int i=0; i<NUM_INSTR_DESTINATIONS; i++)
        {
            if(curr_instr.destination_registers[i] == 0)
            {
                curr_instr.destination_registers[i] = (unsigned char)r;
                break;
            }
        }
    }
}

void MemoryRead(VOID* addr, VOID* ip)
{
    if(!tracing_on) return;

    uint8_t value;
    //addr = (VOID*)(((uint64_t)addr >> 6) << 6);
    int already_found = 0;

    for(int i=0; i<NUM_INSTR_SOURCES; i++)
    {
        if(curr_instr.source_memory[i] == ((unsigned long long int)addr))
        {
            already_found = 1;
            break;
        }
    }
    if(already_found == 0)
    {
        for(int i=0; i<NUM_INSTR_SOURCES; i++)
        {
            if(curr_instr.source_memory[i] == 0)
            {
                curr_instr.source_memory[i] = (unsigned long long int)addr;
                curr_instr.s_valid[i] = 1;
                for(int j=0; j < 64; j++)
                {
                    PIN_SafeCopy(&value, (VOID*)((char*)addr + j), 1);
                    curr_instr.s_value[i][j] = value;
                }
                break;
            }
        }
    }
}

void MemoryWrite(VOID* addr, VOID* ip)
{
    if(!tracing_on) return;

    int already_found = 0;
    //addr = (VOID*)(((uint64_t)addr >> 6) << 6);

    for(int i=0; i<NUM_INSTR_DESTINATIONS; i++)
    {
        if(memory_write[i].addr == addr && memory_write[i].valid == 1)
        {
            already_found = 1;
            break;
        }
    }
    if(already_found == 0)
    {
        for(int i=0; i < NUM_INSTR_DESTINATIONS; i++)
        {
            if(memory_write[i].valid == 0)
            {
                memory_write[i].valid = 1;
                memory_write[i].addr = addr;
                memory_write[i].ip = ip;
                break;
            }
        }
    }
}


/* ===================================================================== */
// Instrumentation callbacks
/* ===================================================================== */

// Is called for every instruction and instruments reads and writes
VOID Instruction(INS ins, VOID *v)
{
    // begin each instruction with this function
    UINT32 opcode = INS_Opcode(ins);
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)BeginInstruction, IARG_INST_PTR, IARG_UINT32, opcode, IARG_END);

    // instrument branch instructions
    if(INS_IsBranch(ins))
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)BranchOrNot, IARG_BRANCH_TAKEN, IARG_END);

    // instrument register reads
    UINT32 readRegCount = INS_MaxNumRRegs(ins);
    for(UINT32 i=0; i<readRegCount; i++) 
    {
        UINT32 regNum = INS_RegR(ins, i);

        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)RegRead,
                IARG_UINT32, regNum, IARG_UINT32, i,
                IARG_END);
    }

    // instrument register writes
    UINT32 writeRegCount = INS_MaxNumWRegs(ins);
    for(UINT32 i=0; i<writeRegCount; i++) 
    {
        UINT32 regNum = INS_RegW(ins, i);

        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)RegWrite,
                IARG_UINT32, regNum, IARG_UINT32, i,
                IARG_END);
    }

    // instrument memory reads and writes
    UINT32 memOperands = INS_MemoryOperandCount(ins);

    // Iterate over each memory operand of the instruction.
    for (UINT32 memOp = 0; memOp < memOperands; memOp++) 
    {
        if (INS_MemoryOperandIsRead(ins, memOp)) 
        {
            // UINT32 read_size = INS_MemoryReadSize(ins);

            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)MemoryRead,
                    IARG_MEMORYOP_EA, memOp, IARG_INST_PTR,
                    IARG_END);
        }
        if (INS_MemoryOperandIsWritten(ins, memOp)) 
        {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)MemoryWrite,
                    IARG_MEMORYOP_EA, memOp, IARG_INST_PTR,
                    IARG_END);
        }
    }
  

    // finalize each instruction with this function
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)EndInstruction, IARG_END);
}

/*!
 * Print out analysis results.
 * This function is called when the application exits.
 * @param[in]   code            exit code of the application
 * @param[in]   v               value specified by the tool in the 
 *                              PIN_AddFiniFunction function call
 */
VOID Fini(INT32 code, VOID *v)
{
    // close the file if it hasn't already been closed
    if(!output_file_closed) 
    {
        fclose(out);
        output_file_closed = true;
    }
}

VOID LastWords(VOID *v)
{
    std::cout << "Bye!" << std::endl;
    return;
}

/*!
 * The main procedure of the tool.
 * This function is called when the application image is loaded but not yet started.
 * @param[in]   argc            total number of elements in the argv array
 * @param[in]   argv            array of command line arguments, 
 *                              including pin -t <toolname> -- ...
 */

int main(int argc, char *argv[])
{
    // Initialize PIN library. Print help message if -h(elp) is specified
    // in the command line or the command line is invalid 
    if( PIN_Init(argc,argv) )
        return Usage();

    const char* fileName = KnobOutputFile.Value().c_str();

    out = fopen(fileName, "ab");
    std::cout << sizeof(trace_instr_format_t) << std::endl;

    // char* command = (char*)malloc(32 + strlen(fileName));
    // sprintf(command, "gzip > %s", fileName);
    // out= popen(command, "w");

    if (!out) 
    {
        std::cout << "Couldn't open output trace file. Exiting." << std::endl;
        exit(1);
    }

    // Register function to be called to instrument instructions
    INS_AddInstrumentFunction(Instruction, 0);
    PIN_AddDetachFunction(LastWords, 0);
    // Register function to be called when the application exits
    PIN_AddFiniFunction(Fini, 0);

    //std::cerr <<  "===============================================" << std::endl;
    //std::cerr <<  "This application is instrumented by the Champsim Trace Generator" << std::endl;
    //std::cerr <<  "Trace saved in " << KnobOutputFile.Value() << std::endl;
    //std::cerr <<  "===============================================" << std::endl;

    // Start the program, never returns
    PIN_StartProgram();

    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
