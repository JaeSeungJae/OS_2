#include <linux/module.h>
#include <linux/highmem.h>
#include <linux/kallsyms.h>
#include <linux/syscalls.h>
#include <asm/syscall_wrapper.h>
#include <linux/sched.h>
#include <linux/init_task.h>
#include <linux/init.h>
#include <linux/pid.h>
#include "ftracehooking.h"


extern int open_count;
extern int read_count;
extern int write_count;
extern int lseek_count;
extern int close_count;
extern size_t read_bytes;
extern size_t write_bytes;
extern char file_name[100];

char *sym_name = "sys_call_table";
typedef asmlinkage long (*sys_call_ptr_t)(const struct pt_regs *);
static sys_call_ptr_t *sys_call_table;
sys_call_ptr_t old_open;
sys_call_ptr_t old_read;
sys_call_ptr_t old_write;
sys_call_ptr_t old_lseek;
sys_call_ptr_t old_close;

static asmlinkage long ftrace_open(const struct pt_regs *regs) {
    copy_from_user(file_name, (char*)regs->di, sizeof(file_name));
    open_count++;
    return old_open(regs);
}

static asmlinkage long ftrace_read(const struct pt_regs *regs) {
    read_bytes += regs->dx;
    read_count++;
    return old_read(regs);
}

static asmlinkage long ftrace_write(const struct pt_regs *regs) {
    write_bytes += regs->dx;
    write_count++;
    return old_write(regs);
}

static asmlinkage long ftrace_lseek(const struct pt_regs *regs) {
    lseek_count++;
    return old_lseek(regs);
}

static asmlinkage long ftrace_close(const struct pt_regs *regs) {
    close_count++;
    return old_close(regs);
}

void make_ro(void *addr) {
    unsigned int level;
    pte_t *pte = lookup_address((u64)addr, &level);

    pte->pte = pte->pte &~ _PAGE_RW;
}

void make_rw(void *addr) {
    unsigned int level;
    pte_t *pte = lookup_address((u64)addr, &level);
    if (pte->pte &~ _PAGE_RW)
        pte->pte |= _PAGE_RW;
}

static int __init iotracehooking_init(void) {
    // Find the addresses of the original open, read, write, lseek, and close system calls
    sys_call_table = (sys_call_ptr_t *)kallsyms_lookup_name(sym_name);
    write_cr0(read_cr0() & (~0x10000));
    old_open = sys_call_table[__NR_open];
    old_read = sys_call_table[__NR_read];
    old_write = sys_call_table[__NR_write];
    old_lseek = sys_call_table[__NR_lseek];
    old_close = sys_call_table[__NR_close];
    sys_call_table[__NR_open] = ftrace_open;
    sys_call_table[__NR_read] = ftrace_read;
    sys_call_table[__NR_write] = ftrace_write;
    sys_call_table[__NR_lseek] = ftrace_lseek;
    sys_call_table[__NR_close] = ftrace_close;
    write_cr0(read_cr0() | 0x10000);
    
    return 0;
}

static void __exit iotracehooking_exit(void) {
    write_cr0(read_cr0() & (~0x10000));
    sys_call_table[__NR_open] = old_open;
    sys_call_table[__NR_read] = old_read;
    sys_call_table[__NR_write] = old_write;
    sys_call_table[__NR_lseek] = old_lseek;
    sys_call_table[__NR_close] = old_close;
    write_cr0(read_cr0() | 0x10000);
    //make_ro(syscall_table);
}

module_init(iotracehooking_init);
module_exit(iotracehooking_exit);
MODULE_LICENSE("GPL");