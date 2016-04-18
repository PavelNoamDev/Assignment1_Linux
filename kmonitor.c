#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <asm-generic/uaccess.h>
#include <linux/string.h>
#include <linux/slab.h>

//extern int is_file_monitor_enabled;
extern int is_network_monitor_enabled;
extern int is_mount_monitor_enabled;

static char *msg = NULL;
static char msg_read[150] = "";
//static char tmp_msg[100];
//static char msg2[] = "KMonitor - Last Events:\n";
//static char msg3[] = "KMonitor Current Configuration:\n";
static ssize_t len_check = 1;

MODULE_LICENSE("GPL");

int kmonitor_proc_open(struct inode * sp_inode, struct file *sp_file)
{
    printk(KERN_INFO "kmonitor proc called open\n");
    return 0;
}


int kmonitor_proc_release(struct inode *sp_indoe, struct file *sp_file)
{
    printk(KERN_INFO "kmonitor proc called release\n");
    return 0;
}


ssize_t kmonitor_proc_read(struct file *sp_file, char __user *buf, size_t size, loff_t *offset)
{
    int msg_len = 0;
    if (len_check)
        len_check = 0;
    else
    {
        len_check = 1;
        return 0;
    }
    printk(KERN_INFO "kmonitor proc called read %d\n", (int)size);
    strcpy(msg_read, "KMonitor Current Configuration:\n");
//    if(is_file_monitor_enabled)
//        strcat(msg_read, "File Monitoring - Enabled\n");
//    else
//        strcat(msg_read, "File Monitoring - Disabled\n");
    if(is_network_monitor_enabled)
        strcat(msg_read, "Network Monitoring - Enabled\n");
    else
        strcat(msg_read, "Network Monitoring - Disabled\n");
    if(is_mount_monitor_enabled)
        strcat(msg_read, "Mount Monitoring - Enabled\n");
    else
        strcat(msg_read, "Mount Monitoring - Disabled\n");
//    msg = (char *)kmalloc(sizeof(msg_read), GFP_KERNEL);
//    if(unlikely(!msg))
//    {
//        printk(KERN_ERR "Not enough memory for message! \n");
//        return -1;
//    }
//    strcpy(msg, msg_read);
//    printk(KERN_INFO "To read %s\n", msg_read);
    msg_len = strlen(msg_read) + 1;
    copy_to_user(buf, msg_read, msg_len);
    printk(KERN_INFO "Buffer %s\n", buf);
    return msg_len;
}


ssize_t kmonitor_proc_write(struct file *sp_file, const char __user *buf, size_t size, loff_t *offset)
{
    printk(KERN_INFO "kmonitor proc called write %d\n", (int)size);
    msg = (char *)kmalloc(size, GFP_KERNEL);
    if(unlikely(!msg))
    {
        printk(KERN_ERR "Not enough memory for message! \n");
        return -1;
    }
    copy_from_user(msg, buf, size);
    printk(KERN_INFO "Recived %s\n", msg);
    if(strstr(msg, "NetMon 0"))
        is_network_monitor_enabled = 0;
    else if(strstr(msg, "NetMon 1"))
        is_network_monitor_enabled = 1;
//    else if(strstr(msg, "FileMon 0"))
//        is_file_monitor_enabled = 0;
//    else if(strstr(msg, "FileMon 1"))
//        is_file_monitor_enabled = 1;
    else if(strstr(msg, "MountMon 0"))
        is_mount_monitor_enabled = 0;
    else if(strstr(msg, "MountMon 1"))
        is_mount_monitor_enabled = 1;
    kfree(msg);
    return size;
}


struct file_operations fops = {
        .open = kmonitor_proc_open,
        .read = kmonitor_proc_read,
        .write = kmonitor_proc_write,
        .release = kmonitor_proc_release
};


static int __init init_kmonitorproc (void)
{
    printk(KERN_INFO "init kmonitor proc\n");
    if (! proc_create("kmonitorproc",0666,NULL,&fops))
    {
        printk(KERN_INFO "ERROR! proc_create\n");
        remove_proc_entry("kmonitorproc",NULL);
        return -1;
    }
    return 0;
}

static void __exit exit_kmonitorproc(void)
{
    remove_proc_entry("kmonitorproc",NULL);
    printk(KERN_INFO "exit simple proc\n");
}

module_init(init_kmonitorproc);
module_exit(exit_kmonitorproc);

