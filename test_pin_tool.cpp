
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

using std::cerr;
using std::endl;
using std::string;

/* ================================================================== */
// Global variables
/* ================================================================== */

FILE* trace;
FILE* memoryaddrtrace;
FILE* memoryinstrace;
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

typedef struct {
    uint64_t pfn : 54;
    unsigned int soft_dirty : 1;
    unsigned int file_page : 1;
    unsigned int swapped : 1;
    unsigned int present : 1;
} PagemapEntry;
/* Parse the pagemap entry for the given virtual address.
*
* @param[out] entry the parsed entry
* @param[in] pagemap_fd file descriptor to an open /proc/pid/pagemap file
* @param[in] vaddr virtual address to get entry for
* @return 0 for success, 1 for failure
*/
int pagemap_get_entry(PagemapEntry* entry, int pagemap_fd, uintptr_t vaddr)
{
    size_t nread;
    ssize_t ret;
    uint64_t data;
    uintptr_t vpn;
    vpn = vaddr / sysconf(_SC_PAGE_SIZE);
    nread = 0;
    while (nread < sizeof(data)) {
        /*
        ret = pread(pagemap_fd, &data, sizeof(data) - nread,
            vpn * sizeof(data) + nread);
        */
        lseek(pagemap_fd, vpn * sizeof(data) + nread, SEEK_CUR);
        ret = read(pagemap_fd, &data, sizeof(data) - nread);
        nread += ret;
        if (ret <= 0) {
            return 1;
        }
    }
    entry->pfn = data & (((uint64_t)1 << 54) - 1);
    entry->soft_dirty = (data >> 54) & 1;
    entry->file_page = (data >> 61) & 1;
    entry->swapped = (data >> 62) & 1;
    entry->present = (data >> 63) & 1;
    return 0;
}
/* Convert the given virtual address to physical using /proc/PID/pagemap.
*
* @param[out] paddr physical address
* @param[in] pid process to convert for
* @param[in] vaddr virtual address to get entry for
* @return 0 for success, 1 for failure
*/
int virt_to_phys_user(uintptr_t* paddr, pid_t pid, uintptr_t vaddr)
{
    char pagemap_file[BUFSIZ];
    int pagemap_fd;
    snprintf(pagemap_file, sizeof(pagemap_file), "/proc/%ju/pagemap", (uintmax_t)pid);
    pagemap_fd = open(pagemap_file, O_RDONLY);
    if (pagemap_fd < 0) {
        return 1;
    }
    PagemapEntry entry;
    if (pagemap_get_entry(&entry, pagemap_fd, vaddr)) {
        return 1;
    }
    close(pagemap_fd);
    *paddr = (entry.pfn * sysconf(_SC_PAGE_SIZE)) + (vaddr % sysconf(_SC_PAGE_SIZE));
    return 0;
}

/* ===================================================================== */
// Analysis routines
/* ===================================================================== */



// Print a memory read record
VOID RecordMemRead(VOID* ip, VOID* addr) 
{ 
    uintptr_t paddr = 0;
    virt_to_phys_user(&paddr, getpid(), (uintptr_t)addr);
    fprintf(trace, "%p: R vad %p pad %p\n", ip, addr, (VOID*)paddr);
    fprintf(memoryaddrtrace, "%p READ \n", (VOID*)paddr);
    fprintf(memoryinstrace, "%p\n", ip);
}

// Print a memory write record
VOID RecordMemWrite(VOID* ip, VOID* addr) 
{ 
    uintptr_t paddr = 0;
    virt_to_phys_user(&paddr, getpid(), (uintptr_t)addr);
    fprintf(trace, "%p: W vad %p pad %p\n", ip, addr, (VOID*)paddr);
    fprintf(memoryaddrtrace, "%p WRITE\n", (VOID*)paddr);
    fprintf(memoryinstrace, "%p\n", ip);
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
    fprintf(memoryinstrace, "#eof\n");
    fclose(memoryinstrace);
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
    memoryinstrace = fopen("./traces/memoryinstrace.trc", "w");

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