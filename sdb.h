#include <capstone/capstone.h>
#include <errno.h>
#include <fcntl.h>
#include <gelf.h>
#include <libelf.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

void run(char* filename);
void run_debugger(int pid);
void disassemble_instructions(int child_pid, long addr, int num_instructions);
long set_breakpoint(pid_t pid, long addr);
void remove_breakpoint(pid_t pid, long addr, long original_data);
void print_reg(int pid);
long get_breakpoint_original_data(long addr);
void read_elf_code_section(const char* filename);