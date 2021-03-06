#include <linux/module.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/syscalls.h>
#include <linux/delay.h>
#include <linux/sched.h>
#include <linux/version.h>
#include <linux/slab.h>
#include <linux/inet.h>
#include <linux/socket.h>
#include <linux/list.h>
#include <linux/times.h>
#include <linux/timekeeping.h>
#include <linux/rtc.h>
#include <linux/byteorder/generic.h>
#include <linux/mutex.h>

#define CR0_WP 0x00010000   // Write  Protect Bit (CR0:16)
#define SOCK_STREAM 1
#define MAX_HISTORY 10  // Maximum history list size
#define MAX_HISTORY_LINE (PATH_MAX*3 + 100) //The maximum message line contains 3 file path + extra const words

MODULE_LICENSE("GPL");

int is_network_monitor_enabled = 1; // Used by KMonitor to control this module
int curr_num_of_history_lines = 0;

struct mutex network_enabled_mutex;
struct mutex network_history_mutex;

struct socket_node sockets_lst; // Previously seen sockets

struct history_node net_mon_history;    // History of events

void **syscall_table;

// Used by sockaddr_in struct
struct in_addr {
    unsigned long s_addr;          // load with inet_pton()
};

// Socket
struct sockaddr_in {
    short            sin_family;   // e.g. AF_INET, AF_INET6
    unsigned short   sin_port;     // e.g. htons(3490)
    struct in_addr   sin_addr;     // see struct in_addr, below
    char             sin_zero[8];  // zero this if you want to
};

// Node in the list of seen TCP sockets
struct socket_node {
    struct list_head node;
    int sockfd;
    struct in_addr ip;
    unsigned short port;
};

// Node in tne list of network monitor messages
struct history_node {
    struct list_head node;
    char msg[MAX_HISTORY_LINE];
    long time_in_sec;
};

// Used for IPv4 parsing
#define NIPQUAD(addr) \
    ((unsigned char *)&addr)[0], \
    ((unsigned char *)&addr)[1], \
    ((unsigned char *)&addr)[2], \
    ((unsigned char *)&addr)[3]

unsigned long **find_sys_call_table(void);
long (*orig_sys_socket)(int domain, int type, int protocol);
long (*orig_sys_bind)(int sockfd, struct sockaddr __user *addr, int addrlen);
long (*orig_sys_listen)(int sockfd, int backlog);
long (*orig_sys_accept)(int sockfd, struct sockaddr __user *addr, int __user *addrlen);


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
 * sys_socket hook. Also registers socket fd to sockets_lst
 */
long my_sys_socket(int domain, int type, int protocol)
{
    int sockfd = orig_sys_socket(domain, type, protocol);
    struct socket_node *node_to_add = NULL;
    struct list_head *tmp_node = NULL, *pos = NULL;

    // Check if original sys_socket call was successful
    if (sockfd < 0) {
        printk(KERN_ERR "ERROR opening socket!\n");
        return sockfd;
    }

    mutex_lock_killable(&network_enabled_mutex);
    // Check if TCP and IPv4 socket and monitoring enabled
    if(type != SOCK_STREAM || domain != AF_INET || !is_network_monitor_enabled){
        mutex_unlock(&network_enabled_mutex);
        return sockfd;
    }
    mutex_unlock(&network_enabled_mutex);

    // Check if there is already node with this fd (because we can replace it)
    list_for_each_safe(pos, tmp_node, &sockets_lst.node)
    {
        node_to_add = list_entry(pos, struct socket_node, node);
        // Replace existing socket fd
        if(node_to_add->sockfd == sockfd)
        {
            node_to_add->port = 0;
            node_to_add->ip.s_addr = 0;
            return sockfd;
        }
    }

    // If we here then this fd was not in the list so lets add it
    node_to_add = (struct socket_node *)kmalloc(sizeof(struct socket_node), GFP_KERNEL);
    if(unlikely(!node_to_add))
    {
        printk(KERN_ERR "Not enough memory for socket_node! \n");
        return sockfd;
    }
    node_to_add->sockfd = sockfd;
    node_to_add->port = 0;
    node_to_add->ip.s_addr = 0;
    list_add(&(node_to_add->node), &(sockets_lst.node));
    return sockfd;
}

/*
 * sys_bind hook. Also registers ip and port to the relevant socket fd in sockets_lst.
 */
long my_sys_bind(int sockfd, struct sockaddr __user *addr, int addrlen)
{
    struct socket_node *curr_node = NULL;
    struct list_head *tmp_node = NULL, *pos = NULL;
    unsigned short port = ntohs(((struct sockaddr_in *)addr)->sin_port);
    struct in_addr ip = ((struct sockaddr_in *)addr)->sin_addr;

    mutex_lock_killable(&network_enabled_mutex);
    // Check if the module is enabled
    if(is_network_monitor_enabled)
    {
        // Search for node with this fd
        list_for_each_safe(pos, tmp_node, &sockets_lst.node)
        {
            curr_node = list_entry(pos, struct socket_node, node);
            if(curr_node->sockfd == sockfd)
            {
                curr_node->port = port;
                curr_node->ip = ip;
                mutex_unlock(&network_enabled_mutex);
                return orig_sys_bind(sockfd, addr, addrlen);
            }
        }
    }
    mutex_unlock(&network_enabled_mutex);
    return orig_sys_bind(sockfd, addr, addrlen);
}

/*
 * sys_listen hook. Also registers system call info to history.
 */
int my_sys_listen(int sockfd, int backlog)
{
    struct timeval time;
    unsigned long local_time;
    struct rtc_time tm;
    struct socket_node *curr_node = NULL;
    struct list_head *tmp_node = NULL, *pos = NULL;
    char *pathname = NULL, *p = NULL;
    struct mm_struct *mm = current->mm;
    struct history_node *line_to_add = NULL, *last_history_node = NULL;

    mutex_lock_killable(&network_enabled_mutex);
    // Check if the module is enabled
    if(is_network_monitor_enabled) {
        // Get full path to the current process executable
        if (mm) {
            down_read(&mm->mmap_sem);
            if (mm->exe_file) {
                pathname = kmalloc(PATH_MAX, GFP_ATOMIC);
                if(unlikely(!pathname))
                {
                    printk(KERN_ERR "Not enough memory for pathname! \n");
                    mutex_unlock(&network_enabled_mutex);
                    return orig_sys_listen(sockfd, backlog);
                }
                p = d_path(&mm->exe_file->f_path, pathname, PATH_MAX);
            }
            up_read(&mm->mmap_sem);
        }

        // Get current time
        do_gettimeofday(&time);
        local_time = (u32)(time.tv_sec - (sys_tz.tz_minuteswest * 60));
        rtc_time_to_tm(local_time, &tm);

        // Search for node with this fd
        list_for_each_safe(pos, tmp_node, &sockets_lst.node)
        {
            curr_node = list_entry(pos, struct socket_node, node);
            if (curr_node->sockfd == sockfd) {
                // Write to dmesg
                printk(KERN_INFO
                "%s (pid: %i) is listening on %d.%d.%d.%d:%d\n", p, current->pid, NIPQUAD(
                        curr_node->ip), curr_node->port);
                // Save to history
                line_to_add = (struct history_node *)kmalloc(sizeof(struct history_node), GFP_KERNEL);
                if(unlikely(!line_to_add))
                {
                    printk(KERN_ERR "Not enough memory for history_node! \n");
                    mutex_unlock(&network_enabled_mutex);
                    return orig_sys_listen(sockfd, backlog);
                }
                snprintf(line_to_add->msg, MAX_HISTORY_LINE,
                         "%02d/%02d/%04d %02d:%02d:%02d, %s (pid: %i) is listening on %d.%d.%d.%d:%d\n",
                         tm.tm_mday, tm.tm_mon + 1, tm.tm_year + 1900, tm.tm_hour, tm.tm_min, tm.tm_sec,
                         p, current->pid, NIPQUAD(curr_node->ip), curr_node->port);
                line_to_add->time_in_sec = (u32)time.tv_sec;
                mutex_lock_killable(&network_history_mutex);
                list_add(&(line_to_add->node), &(net_mon_history.node));
                curr_num_of_history_lines++;

                // If more then 10 lines delete the oldest one
                if(curr_num_of_history_lines > MAX_HISTORY)
                {
                    last_history_node = list_last_entry(&(net_mon_history.node), struct history_node, node);
                    list_del(&(last_history_node->node));
                    kfree(last_history_node);
                    curr_num_of_history_lines--;
                }
                mutex_unlock(&network_history_mutex);
                mutex_unlock(&network_enabled_mutex);
                kfree(pathname);
                return orig_sys_listen(sockfd, backlog);
            }
        }
        kfree(pathname);
    }
    mutex_unlock(&network_enabled_mutex);
    return orig_sys_listen(sockfd, backlog);
}

/*
 * sys_accept hook. Also registers system call info to history.
 */
long my_sys_accept(int sockfd, struct sockaddr __user *addr, int __user *addrlen)
{
    struct timeval time;
    unsigned long local_time;
    struct rtc_time tm;
    struct history_node *line_to_add = NULL, *last_history_node = NULL;
    int new_sockfd = orig_sys_accept(sockfd, addr, addrlen); // Wait for connection
    unsigned short port = ntohs(((struct sockaddr_in *)addr)->sin_port);
    struct in_addr ip = ((struct sockaddr_in *)addr)->sin_addr;
    char *pathname = NULL, *p = NULL;
    struct mm_struct *mm = current->mm;

    mutex_lock_killable(&network_enabled_mutex);
    // Check if client with IPv4 and network monitoring is enabled and that there was no error in the original accept
    if(((struct sockaddr_in *)addr)->sin_family != AF_INET || !is_network_monitor_enabled || new_sockfd < 0){
        mutex_unlock(&network_enabled_mutex);
        return new_sockfd;
    }
    mutex_unlock(&network_enabled_mutex);

    // Get current time
    do_gettimeofday(&time);
    local_time = (u32)(time.tv_sec - (sys_tz.tz_minuteswest * 60));
    rtc_time_to_tm(local_time, &tm);

    // Get full path to the current process executable
    if (mm) {
        down_read(&mm->mmap_sem);
        if (mm->exe_file) {
            pathname = kmalloc(PATH_MAX, GFP_ATOMIC);
            if(unlikely(!pathname))
            {
                printk(KERN_ERR "Not enough memory for pathname! \n");
                return new_sockfd;
            }
            p = d_path(&mm->exe_file->f_path, pathname, PATH_MAX);
        }
        up_read(&mm->mmap_sem);
    }
    // Write to dmesg
    printk(KERN_INFO
    "%s (pid: %i) received a connection from  %d.%d.%d.%d:%d \n", p, current->pid, NIPQUAD(ip), port);

    // Save to history
    line_to_add = (struct history_node *)kmalloc(sizeof(struct history_node), GFP_KERNEL);
    if(unlikely(!line_to_add))
    {
        printk(KERN_ERR "Not enough memory for history_node! \n");
        return new_sockfd;
    }
    snprintf(line_to_add->msg, MAX_HISTORY_LINE,
    "%02d/%02d/%04d %02d:%02d:%02d, %s (pid: %i) received a connection from %d.%d.%d.%d:%d\n",
    tm.tm_mday, tm.tm_mon + 1, tm.tm_year + 1900, tm.tm_hour, tm.tm_min, tm.tm_sec,
    p, current->pid, NIPQUAD(ip), port);
    line_to_add->time_in_sec = (u32)time.tv_sec;

    mutex_lock_killable(&network_history_mutex);
    list_add(&(line_to_add->node), &(net_mon_history.node));
    curr_num_of_history_lines++;

    // If more then 10 lines delete the oldest one
    if(curr_num_of_history_lines > MAX_HISTORY)
    {
        last_history_node = list_last_entry(&(net_mon_history.node), struct history_node, node);
        list_del(&(last_history_node->node));
        kfree(last_history_node);
        curr_num_of_history_lines--;
    }
    mutex_unlock(&network_history_mutex);
    kfree(pathname);
    return new_sockfd;
}

// Init module
static int __init network_monitor_init(void)
{
    unsigned long cr0;

    mutex_init(&network_enabled_mutex);
    mutex_init(&network_history_mutex);

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

    /*hooking sys_socket*/
    orig_sys_socket = syscall_table[__NR_socket];
    syscall_table[__NR_socket] = my_sys_socket;
    /*hooking sys_bind*/
    orig_sys_bind = syscall_table[__NR_bind];
    syscall_table[__NR_bind] = my_sys_bind;
    /*hooking sys_listen*/
    orig_sys_listen = syscall_table[__NR_listen];
    syscall_table[__NR_listen] = my_sys_listen;
    /*hooking sys_accept*/
    orig_sys_accept = syscall_table[__NR_accept];
    syscall_table[__NR_accept] = my_sys_accept;

    write_cr0(cr0);

    // Init seen TCP sockets list
    INIT_LIST_HEAD(&sockets_lst.node);

    // Init seen history list
    INIT_LIST_HEAD(&net_mon_history.node);

    return 0;
}

// Release module
static void __exit network_monitor_release(void)
{
    unsigned long cr0;
    struct socket_node *curr_node = NULL;
    struct history_node *curr_his_node = NULL;
    struct list_head *tmp_node = NULL, *pos = NULL;

    // Free memory of sockets list
    list_for_each_safe(pos, tmp_node, &sockets_lst.node)
    {
        curr_node = list_entry(pos, struct socket_node, node);
        printk(KERN_DEBUG "Freeing node with fd %d \n", curr_node->sockfd);
        kfree(curr_node);
    }

    mutex_lock_killable(&network_history_mutex);
    // Free memory of history
    list_for_each_safe(pos, tmp_node, &net_mon_history.node)
    {
        curr_his_node = list_entry(pos, struct history_node, node);
        printk(KERN_DEBUG "Freeing node with msg: %s \n", curr_his_node->msg);
        kfree(curr_his_node);
    }
    mutex_unlock(&network_history_mutex);

    printk(KERN_DEBUG "Stopping network_monitor module!\n");

    cr0 = read_cr0();
    write_cr0(cr0 & ~CR0_WP);

    syscall_table[__NR_socket] = orig_sys_socket;
    syscall_table[__NR_bind] = orig_sys_bind;
    syscall_table[__NR_listen] = orig_sys_listen;
    syscall_table[__NR_accept] = orig_sys_accept;

    write_cr0(cr0);
}

module_init(network_monitor_init);
module_exit(network_monitor_release);

// Make it available to KMonitor
EXPORT_SYMBOL_GPL(is_network_monitor_enabled);
EXPORT_SYMBOL_GPL(net_mon_history);
EXPORT_SYMBOL_GPL(network_enabled_mutex);
EXPORT_SYMBOL_GPL(network_history_mutex);