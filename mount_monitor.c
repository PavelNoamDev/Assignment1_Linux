#include <linux/module.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/syscalls.h>
#include <linux/delay.h>
#include <linux/sched.h>
#include <linux/version.h>
#include<linux/slab.h>
#include <linux/times.h>
#include <linux/timekeeping.h>
#include <linux/rtc.h>
#include <linux/list.h>

#define CR0_WP 0x00010000   // Write  Protect Bit (CR0:16)
#define MAX_HISTORY 10  // Maximum history list size
#define MAX_HISTORY_LINE (PATH_MAX*3 + 100)  //The maximum message line contains 3 file path + extra const words

MODULE_LICENSE("GPL");

int is_mount_monitor_enabled = 1;   // Used by KMonitor to control this module
int curr_num_of_history_lines = 0;

struct history_node mount_mon_history;  // History of events

// Node in tne list of mount monitor messages
struct history_node {
    struct list_head node;
    char msg[MAX_HISTORY_LINE];
    long time_in_sec;
};

void **syscall_table;

unsigned long **find_sys_call_table(void);

long (*orig_sys_mount)( char __user *source, char __user *target,
                        char __user *filesystemtype, unsigned long flags, void __user *data);

/**
 * Dynamically discover sys call table address.
 *
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

/*
 * sys_mount hook. Also registers system call info to history.
 */
long my_sys_mount(  char __user *source, char __user *target, char __user *filesystemtype,
                    unsigned long flags, void __user *data)
{
    struct timeval time;
    unsigned long local_time;
    struct rtc_time tm;
    struct history_node *line_to_add = NULL, *last_history_node = NULL;
    char *pathname = NULL, *p = NULL;
    struct mm_struct *mm = current->mm;
    int result = orig_sys_mount(source, target, filesystemtype, flags, data);

    // Check if the module is enabled and there was no error in the original sys_mount
    if(is_mount_monitor_enabled && result == 0)
    {
        // Get full path to the current process executable
        if (mm) {
            down_read(&mm->mmap_sem);
            if (mm->exe_file) {
                pathname = kmalloc(PATH_MAX, GFP_ATOMIC);
                if(unlikely(!pathname))
                {
                    printk(KERN_ERR "Not enough memory for pathname! \n");
                    return result;
                }
                p = d_path(&mm->exe_file->f_path, pathname, PATH_MAX);
            }
            up_read(&mm->mmap_sem);
        }

        // Get current time
        do_gettimeofday(&time);
        local_time = (u32)(time.tv_sec - (sys_tz.tz_minuteswest * 60));
        rtc_time_to_tm(local_time, &tm);

        // Write to dmesg
        printk(KERN_INFO
        "%s (pid: %i) mounted %s to %s using %s file system\n", p, current->pid, source, target, filesystemtype);


        // Save to history
        line_to_add = (struct history_node *)kmalloc(sizeof(struct history_node), GFP_KERNEL);
        if(unlikely(!line_to_add))
        {
            printk(KERN_ERR "Not enough memory for history_node!\n");
            return result;
        }

        snprintf(line_to_add->msg, MAX_HISTORY_LINE,
        "%02d/%02d/%04d %02d:%02d:%02d, %s (pid: %i) mounted %s to %s using %s file system\n",
        tm.tm_mday, tm.tm_mon + 1, tm.tm_year + 1900, tm.tm_hour, tm.tm_min, tm.tm_sec,
        p, current->pid, source, target, filesystemtype);
        line_to_add->time_in_sec = (u32)time.tv_sec;

        list_add(&(line_to_add->node), &(mount_mon_history.node));
        curr_num_of_history_lines++;

        // If more then 10 lines delete the oldest one
        if(curr_num_of_history_lines > MAX_HISTORY)
        {
            last_history_node = list_last_entry(&(mount_mon_history.node), struct history_node, node);
            list_del(&(last_history_node->node));
            kfree(last_history_node);
            curr_num_of_history_lines--;
        }
        kfree(pathname);
    }
    return result;
}

// Init module
static int __init mount_monitor_init(void)
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

    orig_sys_mount = syscall_table[__NR_mount];
    syscall_table[__NR_mount] = my_sys_mount;

    write_cr0(cr0);

    // Init seen history list
    INIT_LIST_HEAD(&mount_mon_history.node);

    return 0;
}

// Release module
static void __exit mount_monitor_release(void)
{
    unsigned long cr0;
    struct history_node *curr_his_node = NULL;
    struct list_head *tmp_node = NULL, *pos = NULL;

    // Free memory of history
    list_for_each_safe(pos, tmp_node, &mount_mon_history.node)
    {
        curr_his_node = list_entry(pos, struct history_node, node);
        printk(KERN_DEBUG "Freeing node with msg: %s \n", curr_his_node->msg);
        kfree(curr_his_node);
    }

    printk(KERN_DEBUG "Stopping mount_monitor module!\n");

    cr0 = read_cr0();
    write_cr0(cr0 & ~CR0_WP);

    /*hooking sys_mount*/
    syscall_table[__NR_mount] = orig_sys_mount;

    write_cr0(cr0);
}

module_init(mount_monitor_init);
module_exit(mount_monitor_release);

// Make it available to KMonitor
EXPORT_SYMBOL_GPL(is_mount_monitor_enabled);
EXPORT_SYMBOL_GPL(mount_mon_history);