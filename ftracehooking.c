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
//#include <include/asm-generic/current.h>

#define __NR_ftrace 336

int open_count = 0;
int read_count = 0;
int write_count = 0;
int lseek_count = 0;
int close_count = 0;

size_t read_bytes = 0;
size_t write_bytes = 0;
char file_name[100] = {0};

void **syscall_table;
void *real_ftrace;

pid_t pid_temp = 0;
static asmlinkage int my_ftrace(const struct pt_regs *regs)
{
    pid_t pid = (pid_t)regs->di;
    struct task_struct *task;
    task = current;
    if (pid == 0) {
        printk("OS Assignment2 ftrace [%d] Start", pid_temp);
        printk("[2018202018] %s file[%s] stats [x] read - %ld / written - %ld", task->comm, file_name, read_bytes, write_bytes);
        printk("open[%d] close[%d] read[%d] write[%d] lseek[%d]", open_count, close_count, read_count, write_count, lseek_count);
        printk("OS Assignment2 ftrace [%d] End\n", pid_temp);
    }
    else {
        pid_temp = pid;
        open_count = 0;
        read_count = 0;
        write_count = 0;
        lseek_count = 0;
        close_count = 0;
        read_bytes = 0;
        write_bytes = 0;
        file_name[0] = '\0';
    }
    return 0;
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

static int __init ftracehooking_init(void) {
    syscall_table = (void**) kallsyms_lookup_name("sys_call_table");
    make_rw(syscall_table);
    real_ftrace = syscall_table[__NR_ftrace];
    //syscall_table[__NR_ftrace] = __x64_sysftrace;
    syscall_table[__NR_ftrace] = my_ftrace;

    return 0;
}

static void __exit ftracehooking_exit(void) {
    syscall_table[__NR_ftrace] = real_ftrace;
    make_ro(syscall_table);
}

// EXPORT_SYMBOL(my_ftrace);
EXPORT_SYMBOL(open_count);
EXPORT_SYMBOL(read_count);
EXPORT_SYMBOL(write_count);
EXPORT_SYMBOL(lseek_count);
EXPORT_SYMBOL(close_count);
EXPORT_SYMBOL(read_bytes);
EXPORT_SYMBOL(write_bytes);
EXPORT_SYMBOL(file_name);
module_init(ftracehooking_init);
module_exit(ftracehooking_exit);
MODULE_LICENSE("GPL");