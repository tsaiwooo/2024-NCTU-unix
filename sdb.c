#include "sdb.h"

int break_points_count = 0;
long break_points_original_data[16];
long break_points_addr[16];
long code_start, code_end;

int main(int argc, char** argv)
{
    int load = 0;
    char file[128];
    char cmd[128];
    char* token;
    if (argc == 2) {
        strcpy(file, argv[1]);
        load = 1;
    }

    while (!load) {
        printf("(sdb) ");
        scanf("%s", cmd);
        // fgets(cmd, 128, stdin);
        token = strtok(cmd, " ");
        if (!strcmp(token, "load")) {
            // scanf("%s", file);
            fgets(file, 128, stdin);
            token = strtok(file, " \n");
            // printf("%s\n", token);
            strcpy(file, token);
            // fflush(stdin);
            load = 1;
        } else {
            printf("** please load a program first.\n");
        }
    }

    if (load) {
        pid_t child_pid = fork();
        // parent run program
        if (child_pid == 0) {
            run(file);
        }
        // child run ptrace
        else {
            printf("** program '%s' loaded. entry point ", file);
            read_elf_code_section(file);
            run_debugger(child_pid);
        }
    }
    return 0;
}

void run(char* filename)
{
    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
        perror("ptrace");
        exit(1);
    }
    execl(filename, filename, NULL);
}

void run_debugger(int pid)
{
    int in_syscall = 0;
    char cmd[128];
    char* ins;
    int status;
    // int wait_status_;
    waitpid(pid, &status, 0);
    if (WIFEXITED(status)) {
        // printf("** the target program terminated.\n");
        return;
    }
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, pid, NULL, &regs);
    // printf("** loaded. entry point 0x%llx.\n", regs.rip);
    unsigned long long int addr = regs.rip;
    printf("0x%llx.\n", addr);
    unsigned long long int cur_addr = addr;
    disassemble_instructions(pid, (long)addr, 5);
    // ptrace(PTRACE_POKETEXT, pid, (void*)addr, (void*)trap);
    char* token;
    // ptrace(PTRACE_CONT, pid, NULL, NULL);
    // wait(&status);
    while (1) {
        // stop tracing if child terminated successfully

        if (WIFEXITED(status))
            break;
        printf("(sdb) ");
        fgets(cmd, sizeof(cmd), stdin);
        // sscanf(cmd, "%s", ins);
        // scanf("%s", cmd);
        strtok(cmd, "\n");
        ins = strtok(cmd, " ");
        if (!strcmp(ins, "cont")) {
            in_syscall = 0;
            // long addr = 0x401000;
            // long data = ptrace(PTRACE_PEEKTEXT, pid, (void*)addr, NULL);
            // long trap = (data & 0xFFFFFFFFFFFFFF00) | 0xCC;
            // ptrace(PTRACE_POKETEXT, pid, (void*)addr, (void*)trap);
            // printf("data = %ld\n", data);
            // for(int i=0; i<break_points_count; ++i){
            //     // if(cur_addr != break_points_addr[i]){
            //         set_breakpoint(pid,break_points_addr[i]);
            //     // }
            // }
            ptrace(PTRACE_CONT, pid, NULL, NULL);
            wait(&status);
            if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
                ptrace(PTRACE_GETREGS, pid, NULL, &regs);
                cur_addr = regs.rip - 1; // Adjust for the int3 instruction
                printf("** hit a breakpoint at 0x%llx.\n", cur_addr);
                long original_data = get_breakpoint_original_data(cur_addr);
                remove_breakpoint(pid, cur_addr, original_data);
                regs.rip = cur_addr;
                ptrace(PTRACE_SETREGS, pid, NULL, &regs);
                disassemble_instructions(pid, cur_addr, 5);
                /* new add */
                // ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
                // wait(&status);
                // for(int i=0; i<break_points_count; ++i){
                //     // if(cur_addr != break_points_addr[i]){
                //         set_breakpoint(pid,break_points_addr[i]);
                //     // }
                // }
            }
            // disassemble_instructions(pid, cur_addr, 5);
        } else if (!strcmp(ins, "quit")) {
            ptrace(PTRACE_KILL, pid, NULL, NULL);
            break;
        } else if (!strcmp(ins, "si")) {
            for(int i=0; i<break_points_count; ++i){
                // if(cur_addr != break_points_addr[i]){
                    set_breakpoint(pid,break_points_addr[i]);
                // }
            }
            in_syscall = 0;
            ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
            wait(&status);
            ptrace(PTRACE_GETREGS, pid, NULL, &regs);
            cur_addr = regs.rip;
            if (WIFSTOPPED(status)) {
                for (int i = 0; i < break_points_count; ++i) {
                    if (break_points_addr[i] == cur_addr) {
                        printf("** hit a breakpoint at 0x%llx.\n", cur_addr);
                        long original_data = get_breakpoint_original_data(cur_addr);
                        remove_breakpoint(pid, cur_addr, original_data);
                        break;
                    }
                }
                // long original_data = get_breakpoint_original_data(cur_addr);
                // remove_breakpoint(pid, cur_addr, original_data);
                // regs.rip = cur_addr;
                // ptrace(PTRACE_SETREGS, pid, NULL, &regs);
            }
            disassemble_instructions(pid, cur_addr, 5);
        } else if (!strcmp(ins, "break")) {
            token = strtok(NULL, " ");
            long addr;
            sscanf(token, "%lx", &addr);
            ptrace(PTRACE_GETREGS, pid, NULL, &regs);
            if (addr != regs.rip) {
                break_points_addr[break_points_count] = addr;
                long original_data = set_breakpoint(pid, addr);
                break_points_original_data[break_points_count++] = original_data;
            }
            printf("** set a breakpoint at 0x%lx.\n", addr);
        } else if (!strcmp(ins, "info")) {
            token = strtok(NULL, " ");
            if (!strcmp(token, "reg"))
                print_reg(pid);
            if (!strcmp(token, "break")) {
                int have_breaks = 0;
                for (int i = 0; i < break_points_count; ++i) {
                    if (break_points_addr[i]) {
                        have_breaks = 1;
                        break;
                    }
                }
                if (have_breaks) {
                    printf("Num\t\tAddress\n");
                    for (int i = 0; i < break_points_count; ++i) {
                        if (break_points_addr[i]) {
                            printf("%d\t\t0x%lx\n", i, break_points_addr[i]);
                        }
                    }
                } else {
                    printf("** no breakpoints.\n");
                }
            }
        } else if (!strcmp(ins, "delete")) {
            token = strtok(NULL, " ");
            int id;
            sscanf(token, "%d", &id);
            if (break_points_addr[id] == 0) {
                printf("** breakpoint %d does not exist.\n", id);
            } else {
                remove_breakpoint(pid, break_points_addr[id], break_points_original_data[id]);
                break_points_addr[id] = 0;
                break_points_original_data[id] = 0;
                printf("** delete breakpoint %d.\n", id);
            }
        } else if (!strcmp(ins, "patch")) {
            long addr, hex_val;
            int len;
            token = strtok(NULL, " ");
            sscanf(token, "%lx", &addr);
            token = strtok(NULL, " ");
            sscanf(token, "%lx", &hex_val);
            token = strtok(NULL, " ");
            sscanf(token, "%d", &len);
            // update breakpoint data
            // printf("%lx %lx %d\n", addr, hex_val, len);
            for (int i = 0; i < break_points_count; ++i) {
                if (break_points_addr[i] == addr) {
                    break_points_original_data[i] = hex_val;
                    break;
                }
            }
            // Poke data
            // Apply patch
            long original_data = ptrace(PTRACE_PEEKDATA, pid, (void*)addr, NULL);
            // unsigned char* val_ptr = (unsigned char*)&hex_val;
            for (int i = 0; i < len; ++i) {
                // long data = ptrace(PTRACE_PEEKTEXT, pid, (void*)(addr & ~(sizeof(long) - 1)), NULL);
                // ((unsigned char*)&data)[addr % sizeof(long) + i] = val_ptr[i];
                // unsigned char new_byte = val_ptr[i] & 0xFF;
                unsigned char new_byte = (hex_val >> (8 * i)) & 0xFF;
                original_data &= ~(0xFFUL << (8 * i));
                original_data |= (unsigned long)new_byte << (8 * i);
            }
            ptrace(PTRACE_POKEDATA, pid, (void*)addr, (void*)original_data);
            printf("** patch memory at address 0x%lx.\n", addr);

        } else if (!strcmp(ins, "syscall")) {
            // for(int i=0; i<break_points_count; ++i){
            //     // if(cur_addr != break_points_addr[i]){
            //         set_breakpoint(pid,break_points_addr[i]);
            //     // }
            // }
            ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
            waitpid(pid, &status, 0);
            if (WIFEXITED(status)) {
                break;
            }
            if (WIFSTOPPED(status)) {
                int hit_break = 0;
                ptrace(PTRACE_GETREGS, pid, NULL, &regs);
                for (int i = 0; i < break_points_count; ++i) {
                    if (regs.rip == break_points_addr[i] + 1) {
                        printf("** hit a breakpoint at 0x%lx.\n", break_points_addr[i]);
                        long original_data = get_breakpoint_original_data(break_points_addr[i]);
                        remove_breakpoint(pid, break_points_addr[i], original_data);
                        regs.rip = break_points_addr[i];
                        // printf("cur rip = %llx\n",regs.rip);
                        ptrace(PTRACE_SETREGS, pid, NULL, &regs);
                        hit_break = 1;
                        disassemble_instructions(pid, regs.rip , 5);
                        /* new add */
                        // ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
                        // wait(&status);
                        // for(int i=0; i<break_points_count; ++i){
                        //     // if(cur_addr != break_points_addr[i]){
                        //         set_breakpoint(pid,break_points_addr[i]);
                        //     // }
                        // }
                        break;
                    }
                }
                if (!hit_break) {
                    if (WSTOPSIG(status) == SIGTRAP) {
                        if (in_syscall == 0) {
                            printf("** enter a syscall(%lld) at 0x%llx.\n", regs.orig_rax, regs.rip - 2);
                            disassemble_instructions(pid, regs.rip - 2, 5);
                            in_syscall = 1;
                        } else {
                            printf("** leave a syscall(%lld) = %lld at 0x%llx.\n", regs.orig_rax, regs.rax, regs.rip - 2);
                            disassemble_instructions(pid, regs.rip - 2, 5);
                            in_syscall = 0;
                        }
                    }
                }
            }
        } else {
            printf("Unknown command\n");
        }
    }
    printf("** the target program terminated.\n");
}

void disassemble_instructions(int child_pid, long addr, int num_instructions)
{
    csh handle;
    cs_insn* insn;
    size_t count;

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        printf("Failed to initialize Capstone\n");
        return;
    }

    for (int i = 0; i < num_instructions; ++i) {
        if (addr < code_start || addr >= code_end) {
            printf("** the address is out of the range of the text section.\n");
            break;
        }
        uint8_t code[16];
        for (int j = 0; j < 16; j += sizeof(long)) {
            long instruction = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)(addr + j), NULL);
            memcpy(code + j, &instruction, sizeof(long));
        }

        // Check if the code contains an int3 instruction and replace it with the original data
        for (int k = 0; k < 16; ++k) {
            if (code[k] == 0xCC) {
                long original_data = get_breakpoint_original_data(addr + k);
                if (original_data) {
                    memcpy(&code[k], &original_data, sizeof(long));
                }
            }
        }
        int total_bytes = 0;

        count = cs_disasm(handle, code, sizeof(code), addr, 1, &insn);
        if (count > 0) {
            total_bytes = 0;
            printf("%06lx: ", insn[0].address);
            // for (int k = 0; k < insn[0].size; k++) {
            //     total_bytes += insn[0].bytes[k];
            // }
            // if (!total_bytes) {
            //     printf("** the address is out of the range of the text section.\n");
            //     break;
            // }
            for (int k = 0; k < insn[0].size; k++) {
                printf("%02x ", insn[0].bytes[k]);
                total_bytes += insn[0].bytes[k];
            }
            int padding = 30 - (insn[0].size * 3); // need extra spaces
            printf("%-*s %-7s %-20s\n", padding, "", insn[0].mnemonic, insn[0].op_str);

            addr += insn[0].size;
            cs_free(insn, count);
        } else {
            printf("** the address is out of the range of the text section.\n");
            break;
        }
    }

    cs_close(&handle);
}

long set_breakpoint(pid_t pid, long addr)
{
    long data = ptrace(PTRACE_PEEKTEXT, pid, (void*)addr, NULL);
    long trap = (data & 0xFFFFFFFFFFFFFF00) | 0xCC; // int3
    ptrace(PTRACE_POKETEXT, pid, (void*)addr, (void*)trap);
    return data;
}

void remove_breakpoint(pid_t pid, long addr, long original_data)
{
    // for (int i = 0; i < break_points_count; ++i) {
    //     if (original_data == break_points_original_data[i]) {
    //         break_points_original_data[i] = 0;
    //         break_points_addr[i] = 0;
    //         break;
    //     }
    // }
    ptrace(PTRACE_POKETEXT, pid, (void*)addr, (void*)original_data);
}

void print_reg(int pid)
{
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, pid, NULL, &regs);
    printf("$rax 0x%016llx\t$rbx 0x%016llx\t$rcx 0x%016llx\n", regs.rax, regs.rbx, regs.rcx);
    printf("$rdx 0x%016llx\t$rsi 0x%016llx\t$rdi 0x%016llx\n", regs.rdx, regs.rsi, regs.rdi);
    printf("$rbp 0x%016llx\t$rsp 0x%016llx\t$r8  0x%016llx\n", regs.rbp, regs.rsp, regs.r8);
    printf("$r9  0x%016llx\t$r10 0x%016llx\t$r11 0x%016llx\n", regs.r9, regs.r10, regs.r11);
    printf("$r12 0x%016llx\t$r13 0x%016llx\t$r14 0x%016llx\n", regs.r12, regs.r13, regs.r14);
    printf("$r15 0x%016llx\t$rip 0x%016llx\t$eflags 0x%016llx\n", regs.r15, regs.rip, regs.eflags);
    fflush(stdout);
}

long get_breakpoint_original_data(long addr)
{
    for (int i = 0; i < break_points_count; ++i) {
        if (break_points_addr[i] == addr) {
            return break_points_original_data[i];
        }
    }
    return 0;
}

void read_elf_code_section(const char* filename)
{
    if (elf_version(EV_CURRENT) == EV_NONE) {
        fprintf(stderr, "ELF library initialization failed: %s\n", elf_errmsg(-1));
        exit(EXIT_FAILURE);
    }

    int fd = open(filename, O_RDONLY, 0);
    if (fd < 0) {
        perror("open");
        exit(EXIT_FAILURE);
    }

    Elf* elf = elf_begin(fd, ELF_C_READ, NULL);
    if (elf == NULL) {
        fprintf(stderr, "elf_begin failed: %s\n", elf_errmsg(-1));
        close(fd);
        exit(EXIT_FAILURE);
    }

    GElf_Ehdr ehdr;
    if (gelf_getehdr(elf, &ehdr) == NULL) {
        fprintf(stderr, "gelf_getehdr failed: %s\n", elf_errmsg(-1));
        elf_end(elf);
        close(fd);
        exit(EXIT_FAILURE);
    }

    size_t n;
    if (elf_getphdrnum(elf, &n) != 0) {
        fprintf(stderr, "elf_getphdrnum failed: %s\n", elf_errmsg(-1));
        elf_end(elf);
        close(fd);
        exit(EXIT_FAILURE);
    }

    for (size_t i = 0; i < n; ++i) {
        GElf_Phdr phdr;
        if (gelf_getphdr(elf, i, &phdr) != &phdr) {
            fprintf(stderr, "gelf_getphdr failed: %s\n", elf_errmsg(-1));
            elf_end(elf);
            close(fd);
            exit(EXIT_FAILURE);
        }

        if (phdr.p_type == PT_LOAD && phdr.p_flags & PF_X) {
            code_start = phdr.p_vaddr;
            code_end = phdr.p_vaddr + phdr.p_memsz;
            break;
        }
    }

    elf_end(elf);
    close(fd);
}
