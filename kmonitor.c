#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <asm-generic/uaccess.h>
#include <linux/string.h>
#include <linux/slab.h>

#define MAX_HISTORY 10  // Maximum history list size
#define MAX_HISTORY_LINE (PATH_MAX*3 + 100) //The maximum message line contains 3 file path + extra const words

extern int is_file_monitor_enabled;
extern int is_network_monitor_enabled;
extern int is_mount_monitor_enabled;

extern struct history_node file_mon_history;    // History of filemon events
extern struct history_node net_mon_history;     // History of netmon events
extern struct history_node mount_mon_history;   // History of mountmon events

static char *msg = NULL;
static char msg_read[150] = "";
static char first_must_line[] = "KMonitor - Last Events:\n";
static char second_must_line[] = "KMonitor Current Configuration:\n";
static ssize_t len_check = 1;

// Node in the list of messages
struct history_node {
    struct list_head node;
    char msg[MAX_HISTORY_LINE];
    long time_in_sec;
};

MODULE_LICENSE("GPL");

/**
* This function is called then the kmonitorproc file is read
*
*/
ssize_t kmonitor_proc_read(struct file *sp_file, char __user *buf, size_t size, loff_t *offset)
{
    int msg_len = 0, i;
    long max_time;
    struct history_node *net_line = NULL, *mount_line = NULL, *file_line = NULL, *max_line = NULL;
    struct list_head *net_pos = net_mon_history.node.next, *mount_pos = mount_mon_history.node.next;
    struct list_head *file_pos = file_mon_history.node.next;
    size_t curr_size = strlen(first_must_line)+1;
    size_t curr_tmp_size = 0;
    char *tmp_msg = NULL, *tmp_msg2 = NULL;
    if(len_check)
        len_check = 0;
    else
    {
        len_check = 1;
        return 0;
    }

    // Start building KMonitor report
    msg = (char *)kmalloc(sizeof(char) * size, GFP_KERNEL);
    if(unlikely(!msg))
    {
        printk(KERN_ERR "Not enough memory for message! \n");
        return -1;
    }
    strcpy(msg, first_must_line);

    // Init lines with first line
    if(net_pos != &net_mon_history.node)
    {
        net_line = list_entry(net_pos, struct history_node, node);
    }
    if(mount_pos != &mount_mon_history.node)
    {
        mount_line = list_entry(mount_pos, struct history_node, node);
    }
    if(file_pos != &file_mon_history.node)
    {
        file_line = list_entry(file_pos, struct history_node, node);
    }

    // Find last 10 history messages.
    for(i = 0; i < MAX_HISTORY && (net_pos != &net_mon_history.node || mount_pos != &mount_mon_history.node
        || file_pos != &file_mon_history.node); i++)
    {
        // Find maximum time between 3 history sorted lists
        max_time = -1;
        if(net_line != NULL && net_line->time_in_sec > max_time)
        {
            max_time = net_line->time_in_sec;
        }
        if(mount_line != NULL && mount_line->time_in_sec > max_time)
        {
            max_time = mount_line->time_in_sec;
        }
        if (file_line != NULL && file_line->time_in_sec > max_time)
        {
            max_time = file_line->time_in_sec;
        }

        // Get the message with the maximum time and advance to the next line
        if(net_line != NULL && max_time == net_line->time_in_sec)
        {
            max_line = net_line;
            net_pos = net_pos->next;
            if(net_pos != &net_mon_history.node)
            {
                net_line = list_entry(net_pos, struct history_node, node);
            }
            else
            {
                net_line = NULL;
            }
        }
        else if(mount_line != NULL && max_time == mount_line->time_in_sec)
        {
            max_line = mount_line;
            mount_pos = mount_pos->next;
            if(mount_pos != &mount_mon_history.node)
            {
                mount_line = list_entry(mount_pos, struct history_node, node);
            }
            else
            {
                mount_line = NULL;
            }
        }
        else if(file_line != NULL && max_time == file_line->time_in_sec)
        {
            max_line = file_line;
            file_pos = file_pos->next;
            if(file_pos != &file_mon_history.node)
            {
                file_line = list_entry(file_pos, struct history_node, node);
            }
            else
            {
                file_line = NULL;
            }
        }

        curr_tmp_size += strlen(max_line->msg)+1;
        tmp_msg = (char *)kmalloc((size_t)(sizeof(char)*curr_tmp_size), GFP_KERNEL);
        if(unlikely(!tmp_msg))
        {
            printk(KERN_ERR "Not enough memory for message! \n");
            return -1;
        }
        // Some string manipulation to insert the message to the start of the report
        strcpy(tmp_msg, max_line->msg);
        if(tmp_msg2)
        {
            strcat(tmp_msg, tmp_msg2);
            kfree(tmp_msg2);
        }
        tmp_msg2 = tmp_msg;
    }
    // Add last 10 history messages to the KMonitor report
    if(tmp_msg2)
    {
        curr_size += strlen(tmp_msg2)+1;
        msg = (char *)krealloc(msg, (size_t)(sizeof(char)*curr_size), GFP_KERNEL);
        if(unlikely(!msg))
        {
            printk(KERN_ERR "Not enough memory for message! \n");
            return -1;
        }
        strcat(msg, tmp_msg2);
    }
    // Add configuration info to the KMonitor report.
    strcpy(msg_read, second_must_line);
    if(is_file_monitor_enabled)
        strcat(msg_read, "File Monitoring - Enabled\n");
    else
        strcat(msg_read, "File Monitoring - Disabled\n");
    if(is_network_monitor_enabled)
        strcat(msg_read, "Network Monitoring - Enabled\n");
    else
        strcat(msg_read, "Network Monitoring - Disabled\n");
    if(is_mount_monitor_enabled)
        strcat(msg_read, "Mount Monitoring - Enabled\n");
    else
        strcat(msg_read, "Mount Monitoring - Disabled\n");
    curr_size += strlen(msg_read)+1;
    msg = (char *)krealloc(msg, (size_t)(sizeof(char)*curr_size), GFP_KERNEL);
    if(unlikely(!msg))
    {
        printk(KERN_ERR "Not enough memory for message! \n");
        return -1;
    }
    strcat(msg, msg_read);
    msg_len = strlen(msg) + 1;
    copy_to_user(buf, msg, msg_len);
    kfree(msg);
    return msg_len;
}

/**
* This function is called then the kmonitorproc file is read
*
*/
ssize_t kmonitor_proc_write(struct file *sp_file, const char __user *buf, size_t size, loff_t *offset)
{
    msg = (char *)kmalloc(size, GFP_KERNEL);
    if(unlikely(!msg))
    {
        printk(KERN_ERR "Not enough memory for message! \n");
        return -1;
    }
    copy_from_user(msg, buf, size);
    // Enable or Disable some monitor
    if(strstr(msg, "NetMon 0"))
        is_network_monitor_enabled = 0;
    else if(strstr(msg, "NetMon 1"))
        is_network_monitor_enabled = 1;
    else if(strstr(msg, "FileMon 0"))
        is_file_monitor_enabled = 0;
    else if(strstr(msg, "FileMon 1"))
        is_file_monitor_enabled = 1;
    else if(strstr(msg, "MountMon 0"))
        is_mount_monitor_enabled = 0;
    else if(strstr(msg, "MountMon 1"))
        is_mount_monitor_enabled = 1;
    kfree(msg);
    return size;
}


// Point proc read and write to our functions
struct file_operations fops = {
        .read = kmonitor_proc_read,
        .write = kmonitor_proc_write,
};

// Init module
static int __init init_kmonitorproc (void)
{
    printk(KERN_INFO "Started kmonitorproc\n");
    if (!proc_create("kmonitorproc",0666,NULL,&fops))
    {
        printk(KERN_INFO "ERROR! proc_create\n");
        remove_proc_entry("kmonitorproc",NULL);
        return -1;
    }
    return 0;
}

// Release module
static void __exit exit_kmonitorproc(void)
{
    remove_proc_entry("kmonitorproc",NULL);
    printk(KERN_INFO "Exit kmonitorproc\n");
}

module_init(init_kmonitorproc);
module_exit(exit_kmonitorproc);

