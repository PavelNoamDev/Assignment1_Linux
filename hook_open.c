#include <linux/module.h>
#include <linux/init.h>
#include <linux/types.h>
//#include <asm/cacheflush.h>
#include <linux/syscalls.h>
#include <linux/delay.h>
#include <linux/sched.h>
#include <linux/version.h>
#include<linux/slab.h>



// Write Protect Bit (CR0:16)
#define CR0_WP 0x00010000

MODULE_LICENSE("GPL");

void **syscall_table;

unsigned long **find_sys_call_table(void);

long (*orig_sys_open)(const char __user *filename, int flags, umode_t mode);

/**
 * /boot/System.map-3.13.0-43-generic:
 *
 * ffffffff811bb230 T sys_close
 * ffffffff81801400 R sys_call_table
 * ffffffff81c15020 D loops_per_jiffy
 *
 */
unsigned long **find_sys_call_table()
{
    unsigned long ptr;
    unsigned long *p;

    for (ptr = (unsigned long) sys_close; ptr < (unsigned long) &loops_per_jiffy; ptr += sizeof(void *))
    {

        p = (unsigned long *) ptr;

        if (p[__NR_close] == (unsigned long) sys_close)
        {
            return (unsigned long **) p;
        }
    }

    return NULL;
}

int my_sys_open(const char __user *filename, int flags, umode_t mode)
{
    char *pathname,*p = NULL;
    struct mm_struct *mm = current->mm;
    if (mm) {
        down_read(&mm->mmap_sem);
        if (mm->exe_file) {
            pathname = kmalloc(PATH_MAX, GFP_ATOMIC);
            if (pathname) {
                p = d_path(&mm->exe_file->f_path, pathname, PATH_MAX);
                /*Now you have the path name of exe in p*/
                }
            }
        up_read(&mm->mmap_sem);
    }
    printk("%s\" (pid %i) is opening : %s\n",
    p, current->pid, filename);
    return orig_sys_open(filename, flags, mode);
}

static int __init syscall_init(void)
{
    unsigned long cr0;

    printk(KERN_DEBUG "Let's do some magic!\n");

    syscall_table = (void **) find_sys_call_table();

    if (!syscall_table) {
        printk(KERN_DEBUG "ERROR: Cannot find the system call table address.\n");
        return -1;
    }

    printk(KERN_DEBUG "Found the sys_call_table at %16lx.\n", (unsigned long) syscall_table);

    cr0 = read_cr0();
    write_cr0(cr0 & ~CR0_WP);

    printk(KERN_DEBUG "Read only disabled. Proceeding...\n");
    orig_sys_open = syscall_table[__NR_open];
    syscall_table[__NR_open] = my_sys_open;

    write_cr0(cr0);

    return 0;
}

static void __exit syscall_release(void)
{
    unsigned long cr0;

    printk(KERN_DEBUG "Stopping KMonitor module!\n");

    cr0 = read_cr0();
    write_cr0(cr0 & ~CR0_WP);

    syscall_table[__NR_open] = orig_sys_open;

    write_cr0(cr0);
}

module_init(syscall_init);
module_exit(syscall_release);