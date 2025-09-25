#ifndef THREAD_H
#define THREAD_H

#pragma once
#include <linux/sched.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 10, 0)
#include <linux/sched/signal.h>
#endif

static inline void hide_thread(pid_t tgid) {
  struct task_struct *task, *thread;

  // TODO
}

#endif
