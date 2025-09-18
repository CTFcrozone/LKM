#ifndef COMMON_H
#define COMMON_H

#pragma once
#include <linux/sched.h>
#include <linux/socket.h>

extern struct task_struct *thread;
extern struct socket *sock;

#endif
