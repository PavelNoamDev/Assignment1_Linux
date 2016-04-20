#include <linux/module.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/syscalls.h>
#include <linux/delay.h>
#include <linux/sched.h>
#include <linux/version.h>
#include <linux/slab.h>
#include <linux/times.h>
#include <linux/timekeeping.h>
#include <linux/rtc.h>
#include <linux/list.h>
#include <linux/mutex.h>

#define CR0_WP 0x00010000	// Write  Protect Bit (CR0:16)
#define MAX_HISTORY 10	// Maximum history list size
#define MAX_HISTORY_LINE (PATH_MAX*3 + 100)	//The maximum message line contains 3 file path + extra const words

MODULE_LICENSE("GPL");

int is_file_monitor_enabled = 1;	// Used by KMonitor to control this module
int curr_num_of_history_lines = 0;

struct history_node file_mon_history;	// History of events
//struct mutex m;

// Node in tne list of file monitor messages
struct history_node {
	struct list_head node;
	char msg[MAX_HISTORY_LINE];
	long time_in_sec;
};

void **syscall_table;

unsigned long **find_sys_call_table(void);
long (*orig_sys_open)(const char __user *filename, int flags, umode_t mode);
long (*orig_sys_read)(unsigned int fd, char __user *buf, size_t count);
long (*orig_sys_write)(unsigned int fd, const char __user *buf, size_t count);

/**
 * Dynamically discover sys call table address
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
 * sys_open hook. Also registers system call info to history.
 */
 int my_sys_open(const char __user *filename, int flags, umode_t mode)
 {
	struct timeval time;
	unsigned long local_time;
	struct rtc_time tm;
	struct history_node *line_to_add = NULL, *last_history_node = NULL;
	char *pathname = NULL,*p = NULL;
	struct mm_struct *mm = current->mm;

	// Check if the module is enabled
	if(is_file_monitor_enabled)
	{
//		mutex_lock_killable(&m);
		// Get full path to the current process executable
		if (mm) {
			down_read(&mm->mmap_sem);
			if (mm->exe_file) {
				pathname = kmalloc(PATH_MAX, GFP_ATOMIC);
				if(unlikely(!pathname))
				{
					printk(KERN_ERR "Not enough memory for pathname! \n");
					return orig_sys_open(filename, flags, mode);
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
		printk("%s (pid %i) is opening %s\n", p, current->pid, filename);
		// Save to history
		line_to_add = (struct history_node *)kmalloc(sizeof(struct history_node), GFP_KERNEL);
		if(unlikely(!line_to_add))
		{
			printk(KERN_ERR "Not enough memory for history_node!\n");
			return orig_sys_open(filename, flags, mode);
		}

		snprintf(line_to_add->msg, MAX_HISTORY_LINE,
		"%02d/%02d/%04d %02d:%02d:%02d, %s (pid %i) is opening %s\n",
		tm.tm_mday, tm.tm_mon + 1, tm.tm_year + 1900, tm.tm_hour, tm.tm_min, tm.tm_sec,
		p, current->pid, filename);
		line_to_add->time_in_sec = (u32)time.tv_sec;

		list_add(&(line_to_add->node), &(file_mon_history.node));
		curr_num_of_history_lines++;

		// If more then 10 lines delete the oldest one
		if(curr_num_of_history_lines > MAX_HISTORY)
		{
			last_history_node = list_last_entry(&(file_mon_history.node), struct history_node, node);
			list_del(&(last_history_node->node));
			kfree(last_history_node);
			curr_num_of_history_lines--;
		}
		kfree(pathname);
//		mutex_unlock(&m);
	}
 	return orig_sys_open(filename, flags, mode);
 }

/*
 * sys_read hook. Also registers system call info to history.
 */
 int my_sys_read(unsigned int fd, char __user *buf, size_t count)
 {
	struct timeval time;
	unsigned long local_time;
	struct rtc_time tm;
	struct history_node *line_to_add = NULL, *last_history_node = NULL;
 	char *pathname = NULL,*p = NULL;
 	struct mm_struct *mm = current->mm;

	// Check if the module is enabled
	if(is_file_monitor_enabled)
	{
//		mutex_lock_killable(&m);
		// Get full path to the current process executable
		if (mm)
		{
			down_read(&mm->mmap_sem);
			if (mm->exe_file) {
				pathname = kmalloc(PATH_MAX, GFP_ATOMIC);
				if(unlikely(!pathname))
				{
					printk(KERN_ERR "Not enough memory for pathname! \n");
					return orig_sys_read(fd, buf, count);
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
		printk("%s (pid %i) is reading %d bytes from TODO\n", p, current->pid, (int)count);
		// Save to history
		line_to_add = (struct history_node *)kmalloc(sizeof(struct history_node), GFP_KERNEL);
		if(unlikely(!line_to_add))
		{
			printk(KERN_ERR "Not enough memory for history_node!\n");
			return orig_sys_read(fd, buf, count);
		}

		snprintf(line_to_add->msg, MAX_HISTORY_LINE,
		"%02d/%02d/%04d %02d:%02d:%02d, %s (pid %i) is reading %d bytes from TODO\n",
		tm.tm_mday, tm.tm_mon + 1, tm.tm_year + 1900, tm.tm_hour, tm.tm_min, tm.tm_sec,
		p, current->pid, (int)count);
		line_to_add->time_in_sec = (u32)time.tv_sec;

		list_add(&(line_to_add->node), &(file_mon_history.node));
		curr_num_of_history_lines++;

		// If more then 10 lines delete the oldest one
		if(curr_num_of_history_lines > MAX_HISTORY)
		{
			last_history_node = list_last_entry(&(file_mon_history.node), struct history_node, node);
			list_del(&(last_history_node->node));
			kfree(last_history_node);
			curr_num_of_history_lines--;
		}
		kfree(pathname);
//		mutex_unlock(&m);
	}
 	return orig_sys_read(fd, buf, count);
 }

/*
 * sys_write hook. Also registers system call info to history.
 */
 int my_sys_write(unsigned int fd, const char __user *buf, size_t count)
 {
	struct timeval time;
	unsigned long local_time;
	struct rtc_time tm;
	struct history_node *line_to_add = NULL, *last_history_node = NULL;
 	char *pathname = NULL,*p = NULL;
 	struct mm_struct *mm = current->mm;

	// Check if the module is enabled
	if(is_file_monitor_enabled)
	{
//		mutex_lock_killable(&m);
		// Get full path to the current process executable
		if (mm)
		{
			down_read(&mm->mmap_sem);
			if (mm->exe_file) {
				pathname = kmalloc(PATH_MAX, GFP_ATOMIC);
				if(unlikely(!pathname))
				{
					printk(KERN_ERR "Not enough memory for pathname! \n");
					return orig_sys_write(fd, buf, count);
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
		printk("%s (pid %i) is writing %d bytes to TODO\n", p, current->pid, (int)count);
		// Save to history
		line_to_add = (struct history_node *)kmalloc(sizeof(struct history_node), GFP_KERNEL);
		if(unlikely(!line_to_add))
		{
			printk(KERN_ERR "Not enough memory for history_node!\n");
			return orig_sys_write(fd, buf, count);
		}

		snprintf(line_to_add->msg, MAX_HISTORY_LINE,
		"%02d/%02d/%04d %02d:%02d:%02d, %s (pid %i) is writing %d bytes to TODO\n",
		tm.tm_mday, tm.tm_mon + 1, tm.tm_year + 1900, tm.tm_hour, tm.tm_min, tm.tm_sec,
		p, current->pid, (int)count);
		line_to_add->time_in_sec = (u32)time.tv_sec;

		list_add(&(line_to_add->node), &(file_mon_history.node));
		curr_num_of_history_lines++;

		// If more then 10 lines delete the oldest one
		if(curr_num_of_history_lines > MAX_HISTORY)
		{
			last_history_node = list_last_entry(&(file_mon_history.node), struct history_node, node);
			list_del(&(last_history_node->node));
			kfree(last_history_node);
			curr_num_of_history_lines--;
		}
		kfree(pathname);
//		mutex_unlock(&m);
	}
 	return orig_sys_write(fd, buf, count);
 }

// Init module
 static int __init file_monitor_init(void)
 {
 	unsigned long cr0;

//	 mutex_init(&m);

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

    /*hooking sys_open*/
 	orig_sys_open = syscall_table[__NR_open];
 	syscall_table[__NR_open] = my_sys_open;

    /*hooking sys_read*/
 	orig_sys_read = syscall_table[__NR_read];
 	syscall_table[__NR_read] = my_sys_read;

    /*hooking sys_write*/
 	orig_sys_write = syscall_table[__NR_write];
 	syscall_table[__NR_write] = my_sys_write;

 	write_cr0(cr0);

	 // Init seen history list
	 INIT_LIST_HEAD(&file_mon_history.node);

 	return 0;
 }

// Release module
 static void __exit file_monitor_release(void)
 {
 	 unsigned long cr0;
	 struct history_node *curr_his_node = NULL;
	 struct list_head *tmp_node = NULL, *pos = NULL;

	 // Free memory of history
	 list_for_each_safe(pos, tmp_node, &file_mon_history.node)
	 {
		 curr_his_node = list_entry(pos, struct history_node, node);
		 printk(KERN_DEBUG "Freeing node with msg: %s \n", curr_his_node->msg);
		 kfree(curr_his_node);
	 }

 	 printk(KERN_DEBUG "Stopping KMonitor module!\n");

 	 cr0 = read_cr0();
 	 write_cr0(cr0 & ~CR0_WP);

     /*reinstating open, read and write*/
 	 syscall_table[__NR_open] = orig_sys_open;

 	 syscall_table[__NR_read] = orig_sys_read;

 	 syscall_table[__NR_write] = orig_sys_write;

 	 write_cr0(cr0);
 }

 module_init(file_monitor_init);
 module_exit(file_monitor_release);

// Make it available to KMonitor
EXPORT_SYMBOL_GPL(is_file_monitor_enabled);
EXPORT_SYMBOL_GPL(file_mon_history);