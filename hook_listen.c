#include <linux/module.h>
#include <linux/init.h>
#include <linux/types.h>
//#include <asm/cacheflush.h>
#include <linux/syscalls.h>
#include <linux/delay.h>
#include <linux/sched.h>
#include <linux/version.h>
#include <linux/slab.h>
#include <linux/inet.h>
#include <linux/socket.h>
#include <linux/list.h>
#include <linux/byteorder/generic.h>

// Write  Protect Bit (CR0:16)
#define CR0_WP 0x00010000
#define SOCK_STREAM 1

MODULE_LICENSE("GPL");

struct socket_node sockets_lst;

void **syscall_table;

struct in_addr {
    unsigned long s_addr;          // load with inet_pton()
};

// IPv4 AF_INET sockets:

struct sockaddr_in {
    short            sin_family;   // e.g. AF_INET, AF_INET6
    unsigned short   sin_port;     // e.g. htons(3490)
    struct in_addr   sin_addr;     // see struct in_addr, below
    char             sin_zero[8];  // zero this if you want to
};

// Node in list of seen TCP sockets
struct socket_node {
    struct list_head node;
    int sockfd;
    struct in_addr ip;
    unsigned short port;
};

#define NIPQUAD(addr) \
    ((unsigned char *)&addr)[0], \
    ((unsigned char *)&addr)[1], \
    ((unsigned char *)&addr)[2], \
    ((unsigned char *)&addr)[3]

unsigned long **find_sys_call_table(void);

long (*orig_sys_socket)(int domain, int type, int protocol);
long (*orig_sys_bind)(int sockfd, struct sockaddr __user *addr, int addrlen);
long (*orig_sys_listen)(int sockfd, int backlog);

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

long my_sys_socket(int domain, int type, int protocol)
{
    int sockfd = orig_sys_socket(domain, type, protocol);
    struct socket_node *node_to_add = NULL;
    struct list_head *tmp_node = NULL, *pos = NULL;

    if (sockfd < 0) {
        printk(KERN_ERR "ERROR opening socket!\n");
        return sockfd;
    }

    // Check if TCP and IPv4 socket
    if(type != SOCK_STREAM && domain != AF_INET)
        return sockfd;

    // Check if there is already node with this fd (because we can replace it)
    list_for_each_safe(pos, tmp_node, &sockets_lst.node)
    {
        node_to_add = list_entry(pos, struct socket_node, node);
        if(node_to_add->sockfd == sockfd)
        {
            node_to_add->port = 0;
            node_to_add->ip.s_addr = 0;
            return sockfd;
        }
    }

    // If we here then this fd is not in the list so lets add it
    node_to_add = (struct socket_node *)kmalloc(sizeof(struct socket_node), GFP_KERNEL);
    if(unlikely(!node_to_add))
    {
        printk(KERN_ERR "Not enough memory for socket_node! \n");
        return -1;
    }
    node_to_add->sockfd = sockfd;
    node_to_add->port = 0;
    node_to_add->ip.s_addr = 0;
    list_add(&(node_to_add->node), &(sockets_lst.node));
//    printk(KERN_INFO "Process (pid: %i) is socket on %d \n", current->pid, sockfd);
    return sockfd;
}

long my_sys_bind(int sockfd, struct sockaddr __user *addr, int addrlen)
{
    struct socket_node *curr_node = NULL;
    struct list_head *tmp_node = NULL, *pos = NULL;
    unsigned short port = ntohs(((struct sockaddr_in *)addr)->sin_port);
    struct in_addr ip = ((struct sockaddr_in *)addr)->sin_addr;

    // Search for node with this fd
    list_for_each_safe(pos, tmp_node, &sockets_lst.node)
    {
        curr_node = list_entry(pos, struct socket_node, node);
        if(curr_node->sockfd == sockfd)
        {
            curr_node->port = port;
            curr_node->ip = ip;
//            printk(KERN_INFO "Process (pid: %i) is binding on %d \n", current->pid, ntohs(((struct sockaddr_in *)addr)->sin_port));
//            printk(KERN_INFO "Process (pid: %i) is binding on %d.%d.%d.%d \n", current->pid, NIPQUAD(((struct sockaddr_in *)addr)->sin_addr));
            return orig_sys_bind(sockfd, addr, addrlen);
        }
    }
    return orig_sys_bind(sockfd, addr, addrlen);
}

int my_sys_listen(int sockfd, int backlog)
{
    struct socket_node *curr_node = NULL;
    struct list_head *tmp_node = NULL, *pos = NULL;
    char *pathname = NULL, *p = NULL;
    struct mm_struct *mm = current->mm;
    if (mm) {
        down_read(&mm->mmap_sem);
        if (mm->exe_file) {
            pathname = kmalloc(PATH_MAX, GFP_ATOMIC);
            if (pathname) {
                p = d_path(&mm->exe_file->f_path, pathname, PATH_MAX);
                }
            }
        up_read(&mm->mmap_sem);
    }

    // Search for node with this fd
    list_for_each_safe(pos, tmp_node, &sockets_lst.node)
    {
        curr_node = list_entry(pos,
        struct socket_node, node);
        if (curr_node->sockfd == sockfd) {
            printk(KERN_INFO
            "%s (pid: %i) is listening on %d.%d.%d.%d:%d \n", p, current->pid, NIPQUAD(curr_node->ip), curr_node->port);
        }
    }
    return orig_sys_listen(sockfd, backlog);
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


    orig_sys_socket = syscall_table[__NR_socket];
    syscall_table[__NR_socket] = my_sys_socket;

    orig_sys_bind = syscall_table[__NR_bind];
    syscall_table[__NR_bind] = my_sys_bind;

    orig_sys_listen = syscall_table[__NR_listen];
    syscall_table[__NR_listen] = my_sys_listen;

    write_cr0(cr0);

    // Init seen TCP sockets list
    INIT_LIST_HEAD(&sockets_lst.node);

    return 0;
}

static void __exit syscall_release(void)
{
    unsigned long cr0;
    struct socket_node *curr_node = NULL;
    struct list_head *tmp_node = NULL, *pos = NULL;

    // Free memory
    list_for_each_safe(pos, tmp_node, &sockets_lst.node)
    {
        curr_node = list_entry(pos, struct socket_node, node);
        printk(KERN_DEBUG "Freeing node with fd %d \n", curr_node->sockfd);
        kfree(curr_node);
    }

    printk(KERN_DEBUG "Stopping hook_listen module!\n");

    cr0 = read_cr0();
    write_cr0(cr0 & ~CR0_WP);

    syscall_table[__NR_socket] = orig_sys_socket;
    syscall_table[__NR_bind] = orig_sys_bind;
    syscall_table[__NR_listen] = orig_sys_listen;

    write_cr0(cr0);
}

module_init(syscall_init);
module_exit(syscall_release);