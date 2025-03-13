# LKM Rootkit System Module Documentation

## Table of Contents

1. [Introduction](#introduction)
    - [Overview](#overview)
    - [Files](#files)
2. [lkm.c](#lkm-c)
    - [Initialization (`lkm_init`)](#initialization-lkm-init)
    - [Exit (`lkm_exit`)](#exit-lkm-exit)
3. [utils.h](#utils-h)
    - [`write_cr0_forced`](#write_cr0_forced)
    - [`protect_memory`](#protect_memory)
    - [`unprotect_memory`](#unprotect_memory)
4. [hooks.h](#hooks-h)
    - [`root`](#root)
    - [`hide_module`](#hide_module)
    - [`show_module`](#show_module)
    - [`hook_kill`](#hook_kill)
    - [`cleanup`](#cleanup)
    - [`store_syscalls`](#store_syscalls)
    - [`hook`](#hook)
5. [tcp.h](#tcp-h)
    - [`exec_cmd`](#exec_cmd)
    - [`tcp_send`](#tcp_send)
    - [`tcp_recv`](#tcp_recv)
    - [`socket_init`](#socket_init)
6. [Usage](#usage)
    - [Initialization](#initialization)
    - [Module Manipulation](#module-manipulation)
    - [Custom Signals](#custom-signals)
    - [Communication](#communication)
    - [Cleanup](#cleanup)


## Overview

This documentation provides an exhaustive insight into the functionalities, implementation, and usage of the LKM (Linux Kernel Module) System Module. The module enriches the Linux kernel's capabilities by offering advanced functionalities such as syscall manipulation, module hiding, and TCP socket communication.

## Files

### lkm.c

The primary module file `lkm.c` serves as the heart of the system module, encapsulating the initialization and exit routines, along with the kernel thread function responsible for TCP data reception.

#### Initialization (`lkm_init`):

The initialization routine performs a series of critical tasks to set up the module:

1. **Retrieving Syscall Table**: Acquires the address of the system call table, enabling further manipulation of system calls.
2. **Storing Original Syscalls**: Preserves the original system call functions to ensure seamless restoration after the module's operation.
3. **Hooking Syscalls**: Redirects relevant system calls, allowing the module to intercept and modify their behavior as needed.
4. **Initializing TCP Socket**: Establishes a TCP socket connection to facilitate communication with external entities, enhancing the module's functionality.
5. **Starting Kernel Thread**: Launches a kernel thread dedicated to receiving data over the established TCP connection, ensuring asynchronous operation.

#### Exit (`lkm_exit`):

The exit routine orchestrates the cleanup process to gracefully terminate the module and release associated resources:

1. **Restoring Original Syscalls**: Reverts any hooked system calls back to their original functions, restoring the integrity of the kernel.
2. **Releasing Resources**: Frees up allocated resources, such as the TCP socket, to prevent memory leaks and ensure optimal system performance.
3. **Stopping Kernel Thread**: Halts the execution of the kernel thread responsible for receiving data, ensuring proper shutdown and resource deallocation.

### utils.h

The `utils.h` header file houses essential utility functions vital for ensuring the robustness and reliability of the system module:

- **`write_cr0_forced`**: A versatile function allowing the module to forcefully modify Control Register 0 (CR0), enabling or disabling write protection on kernel memory as necessary.
- **`protect_memory`**: Safeguards kernel memory by enabling write protection, preventing unauthorized modification or corruption of critical data structures.
- **`unprotect_memory`**: Temporarily lifts write protection from kernel memory, allowing the module to make required modifications or updates before restoring protection.

### hooks.h

The `hooks.h` header file serves as the nerve center for syscall manipulation and module hiding, offering a comprehensive suite of functions to tailor the module's behavior to specific requirements:

- **`root`**: Empowers the module to elevate the current process's credentials to root privileges, granting access to restricted system resources and functionalities.
- **`hide_module`**: Conceals the presence of the LKM module within the kernel environment by removing it from the kernel module list, effectively rendering it invisible to standard inspection methods.
- **`show_module`**: Restores visibility of the hidden LKM module by re-adding it to the kernel module list, allowing for seamless management and interaction with the module.
- **`hook_kill`**: Custom hook function intercepting the `kill` syscall, enabling the module to implement custom behavior in response to specific signals, such as spawning a root shell or hiding/unhiding the module.
- **`cleanup`**: Orchestrates the cleanup process by restoring original syscalls, ensuring system stability and integrity after the module's operation.
- **`store_syscalls`**: Safeguards the original syscalls for subsequent restoration, preserving the kernel's default behavior and preventing unintended side effects.
- **`hook`**: Hooks the `kill` syscall with a custom function, seamlessly integrating the module's functionality into the kernel's execution flow.

### tcp.h

The `tcp.h` header file constitutes a crucial component of the system module, offering robust functionality for TCP socket communication:

- **`exec_cmd`**: Employs a sophisticated mechanism to execute shell commands in user mode, providing flexibility and versatility in interacting with the underlying system.
- **`tcp_send`**: Facilitates the transmission of data over a TCP socket, ensuring reliable and efficient communication between the module and external entities.
- **`tcp_recv`**: Enables the module to receive data from a TCP socket, empowering it to process incoming information and respond accordingly.
- **`socket_init`**: Initializes a TCP socket and establishes a connection to a specified IP address and port, laying the foundation for seamless communication and data exchange.

## Usage

### Initialization

1. Load the LKM module into the kernel environment using the `insmod` command, initializing critical components such as syscall manipulation, memory protection, TCP socket, and kernel thread for data reception.

```shell
insmod lkm.ko
```

### Module Manipulation

- **Hiding the Module**: Send signal `SIGINVIS` (63) to the process associated with the LKM module to conceal its presence within the kernel environment.
- **Unhiding the Module**: Send signal `SIGINVIS` (63) to the process associated with the LKM module again to restore its visibility within the kernel environment.

### Custom Signals

- **Signal 64 (`SIGROOT`) - Spawning a Root Shell**: Upon receiving signal 64 (`SIGROOT`), the module elevates the current process's privileges to root, granting unrestricted access to system resources and functionalities.

### Communication

- The module establishes a TCP connection to a predefined IP address and port, enabling seamless communication with external entities.
- It continuously receives data from the connected socket, leveraging a dedicated kernel thread to process incoming information and respond appropriately.

### Cleanup

1. Unload the LKM module from the kernel environment using the `rmmod` command, ensuring proper cleanup and release of associated resources.

```shell
rmmod lkm
```
