#include <linux/module.h>
#include <linux/init.h>
#include <linux/types.h>
//#include <asm/cacheflush.h>
#include <linux/syscalls.h>
#include <linux/delay.h>
#include <linux/sched.h>
#include <linux/version.h>
#include <linux/fdtable.h>

#include <linux/fcntl.h>

#include<linux/slab.h>



// Write Protect Bit (CR0:16)
#define CR0_WP 0x00010000

MODULE_LICENSE("GPL");

void **syscall_table;

unsigned long **find_sys_call_table(void);

long (*orig_sys_read)(unsigned int fd, char __user *buf, size_t count);


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

int my_sys_read(unsigned int fd, char __user *buf, size_t count)
{
    /*char *pathname,*p = NULL;
    struct mm_struct *mm = current->mm;
    if (mm)
    {
        down_read(&mm->mmap_sem);
        if (mm->exe_file) {
            pathname = kmalloc(PATH_MAX, GFP_ATOMIC);
            if (pathname) {
                p = d_path(&mm->exe_file->f_path, pathname, PATH_MAX);
                printk("%s (pid %i) is reading\n", p, current->pid);
            }
        }
        up_read(&mm->mmap_sem);
    }*/

    /*char *tmp;
    char *pathname;
    struct file *file;
    struct path *path;

    spin_lock(&current->files->file_lock);
    file = fcheck(fd);
    if (!file) {
        spin_unlock(&current->files->file_lock);
        return -ENOENT;
    }

    path = &file->f_path;
    path_get(path);
    spin_unlock(&current->files->file_lock);

    tmp = (char *)__get_free_page(GFP_TEMPORARY);

    if (!tmp) {
        path_put(path);
        return -ENOMEM;
    }

    pathname = d_path(path, tmp, PAGE_SIZE);
    path_put(&path);

    if (IS_ERR(pathname)) {
        free_page((unsigned long)tmp);
        return PTR_ERR(pathname);
    }


    printk("filename: %s\n", pathname);

    free_page((unsigned long)tmp);*/
    char *tmp;
    char *pathname;
    struct file *file;
    const struct path *path;
    struct files_struct *files = current->files;

    spin_lock(&files->file_lock);
    file = fcheck_files(files, fd);
    if (!file) {
        spin_unlock(&files->file_lock);
        return -ENOENT;
    }

    path = &file->f_path;
    path_get(path);
    spin_unlock(&files->file_lock);

    tmp = (char *)__get_free_page(GFP_TEMPORARY);

    if (!tmp) {
        path_put(path);
        return -ENOMEM;
    }

    pathname = d_path(path, tmp, PAGE_SIZE);
    path_put(/*(const struct path *)*/&path);

    if (IS_ERR(pathname)) {
        free_page((unsigned long)tmp);
        return PTR_ERR(pathname);
    }

    /* do something here with pathname */
    printk("filename: %s\n", pathname);



    free_page((unsigned long)tmp);

    
    return orig_sys_read(fd, buf, count);
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
    orig_sys_read = syscall_table[__NR_read];
    syscall_table[__NR_read] = my_sys_read;

    write_cr0(cr0);

    return 0;
}

static void __exit syscall_release(void)
{
    unsigned long cr0;

    printk(KERN_DEBUG "Stopping KMonitor module!\n");

    cr0 = read_cr0();
    write_cr0(cr0 & ~CR0_WP);

    syscall_table[__NR_read] = orig_sys_read;

    write_cr0(cr0);
}

module_init(syscall_init);
module_exit(syscall_release);