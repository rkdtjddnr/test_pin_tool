
/*
==============================================================================================
User Defined Pin Tool



==============================================================================================
*/

#include "pin.H"
#include <iostream>
#include <fstream>

#include <fcntl.h> /* open */
#include <stdint.h> /* uint64_t */
#include <stdio.h> /* printf */
#include <stdlib.h> /* size_t */
#include <unistd.h> /* pread, sysconf */
#include <errno.h>

#define PAGE_SHIFT 12
#define PAGEMAP_LENGTH 8

using std::cerr;
using std::endl;
using std::string;

/* ================================================================== */
// Global variables
/* ================================================================== */

FILE* trace;
FILE* memoryaddrtrace;
std::ostream* out = &cerr;

/* ===================================================================== */
// Command line switches
/* ===================================================================== */
KNOB< string > KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "", "specify file name for MyPinTool output");

KNOB< BOOL > KnobCount(KNOB_MODE_WRITEONCE, "pintool", "count", "1",
    "count instructions, basic blocks and threads in the application");

/* ===================================================================== */
// Utilities
/* ===================================================================== */

/* ===================================================================== */
/* Convert virtual to physical */
/* ===================================================================== */

int virt_to_phys_user(unsigned long* paddr, pid_t pid, unsigned long vaddr)
{
    unsigned long offset;
    FILE* pagemap;
    char filename[1024] = { 0 };
    int ret = -1;
    int page_size, page_shift = -1;

    page_size = getpagesize();
    
    sprintf(filename, "/proc/%jd/pagemap", (uintmax_t)pid);

    //printf("opening pagemap %s\n", filename);
    pagemap = fopen(filename, "rb");
    if (!pagemap) {
        perror("can't open file. ");
        goto err;
    }

    offset = (vaddr / page_size) * PAGEMAP_LENGTH;
    if (fseek(pagemap, (unsigned long)offset, SEEK_SET) != 0) {
        perror("fseek failed. ");
        goto err;
    }

    if (fread(paddr, 1, (PAGEMAP_LENGTH - 1), pagemap) < (PAGEMAP_LENGTH - 1)) {
        perror("fread fails. ");
        goto err;
    }
    *paddr = *paddr & 0x7fffffffffffff;

    offset = vaddr % page_size;

    /* PAGE_SIZE = 1U << PAGE_SHIFT */
    while (!((1UL << ++page_shift) & page_size));

    *paddr = (unsigned long)((unsigned long)*paddr << page_shift) + offset;

    ret = 0;
err:
    fclose(pagemap);
    return ret;
}

/* ===================================================================== */
// Analysis routines
/* ===================================================================== */



// Print a memory read record
VOID RecordMemRead(VOID* ip, VOID* addr)
{
    unsigned long paddr = 0;
    virt_to_phys_user(&paddr, getpid(), (unsigned long)addr);
    fprintf(trace, "%p: R vad %p pad %p\n", ip, addr, (VOID*)paddr);
    fprintf(memoryaddrtrace, "0x%lx READ \n", paddr);
}

// Print a memory write record
VOID RecordMemWrite(VOID* ip, VOID* addr)
{
    unsigned long paddr = 0;
    virt_to_phys_user(&paddr, getpid(), (unsigned long)addr);
    fprintf(trace, "%p: W vad %p pad %p\n", ip, addr, (VOID*)paddr);
    fprintf(memoryaddrtrace, "0x%lx WRITE\n", paddr);
}

// Is called for every instruction and instruments reads and writes
VOID Instruction(INS ins, VOID* v)
{
    // Instruments memory accesses using a predicated call, i.e.
    // the instrumentation is called iff the instruction will actually be executed.
    //
    // On the IA-32 and Intel(R) 64 architectures conditional moves and REP
    // prefixed instructions appear as predicated instructions in Pin.
    UINT32 memOperands = INS_MemoryOperandCount(ins);

    // Iterate over each memory operand of the instruction.
    for (UINT32 memOp = 0; memOp < memOperands; memOp++)
    {
        if (INS_MemoryOperandIsRead(ins, memOp))
        {
            INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordMemRead, IARG_INST_PTR, IARG_MEMORYOP_EA, memOp,
                IARG_END);

        }
        // Note that in some architectures a single memory operand can be
        // both read and written (for instance incl (%eax) on IA-32)
        // In that case we instrument it once for read and once for write.
        if (INS_MemoryOperandIsWritten(ins, memOp))
        {
            INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordMemWrite, IARG_INST_PTR, IARG_MEMORYOP_EA, memOp,
                IARG_END);
        }
    }
}


/*!
 * Print out analysis results.
 * This function is called when the application exits.
 * @param[in]   code            exit code of the application
 * @param[in]   v               value specified by the tool in the
 *                              PIN_AddFiniFunction function call
 */
VOID Fini(INT32 code, VOID* v)
{
    fprintf(trace, "#eof\n");
    fclose(trace);
    fprintf(memoryaddrtrace, "#eof\n");
    fclose(memoryaddrtrace);

}

INT32 Usage()
{
    PIN_ERROR("This Pintool prints a trace of memory addresses\n" + KNOB_BASE::StringKnobSummary() + "\n");
    return -1;
}




/*!
 * The main procedure of the tool.
 * This function is called when the application image is loaded but not yet started.
 * @param[in]   argc            total number of elements in the argv array
 * @param[in]   argv            array of command line arguments,
 *                              including pin -t <toolname> -- ...
 */
int main(int argc, char* argv[])
{
    // Initialize PIN library. Print help message if -h(elp) is specified
    // in the command line or the command line is invalid
    if (PIN_Init(argc, argv))
    {
        return Usage();
    }


    trace = fopen("./traces/pinatrace.out", "w");
    memoryaddrtrace = fopen("./traces/mase_pin.trc", "w");

    INS_AddInstrumentFunction(Instruction, 0);

    PIN_AddFiniFunction(Fini, 0);

    cerr << "===============================================" << endl;
    cerr << "This application is instrumented by MyPinTool" << endl;


    // Start the program, never returns
    PIN_StartProgram();

    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */