

<div align="center">
  
  # Linux Kernel Rootkit
  
  ![image](https://github.com/CTFcrozone/LinuxKernelRK/assets/138330732/a3c53989-1523-4510-bbaf-0b7ae5d024c0)
  
  ![GitHub](https://img.shields.io/github/license/RootkitWizzrds/LKM)
  ![GitHub last commit](https://img.shields.io/github/last-commit/RootkitWizzrds/LKM)

**Created**: 2024-06-04 <br>
**Developers**: oromos, void <br>
**Softwere**: rootkit <br>
**Access Level**: ring-0 (kernel) <br>

</div>

## Overview


This repository contains the source code for a Linux kernel rootkit designed to demonstrate various techniques for kernel manipulation and stealthy behavior. Below is a brief overview of the included files and their functionalities:


<img align="left" width="430" src="https://www.seekpng.com/png/full/296-2965253_anillos-png.png">

<br>

- **hook.h**: Defines functions and structures for hooking system calls, hiding the module, and granting root privileges.
- **tcp.h**: Contains functions for TCP socket communication, including sending and receiving data.
- **utils.h**: Provides utility functions for memory manipulation and system call interception.
- **lmk.c**: Implements the main logic of the rootkit, including initialization, system call hooking, socket initialization, and thread management.

<br>
<br>

## Techniques Used

- ### System Call Hooking
The rootkit hooks into the system call table to intercept specific system calls, allowing it to execute custom functionality before or instead of the original system call.
Kernel Module Hiding

- ### Kernel Module Hiding
The rootkit hides itself from the list of loaded kernel modules, making it harder to detect by standard inspection tools.
Privilege Escalation

- ### Privilege Escalation
It contains functionality to elevate the process privileges to root, enabling the execution of privileged operations.
TCP Communication

- ### TCP Communication
The rootkit establishes a TCP connection to a specified IP address and port, facilitating communication with a remote attacker-controlled server.
Kernel Thread Management

- ### Kernel Thread Management
The rootkit creates and manages a kernel thread for handling incoming data over the TCP connection asynchronously.

## Build Instructions

1. Clone the repository:
    ```bash
    git clone https://github.com/RootkitWizzrds/LKM
    ```

2. Navigate to the source directory:
    ```bash
    cd src
    ```

3. Build the rootkit:

    ```bash
    make
    ```

## Loading the Kernel Module

1. Navigate to the build directory:
    ```bash
    cd ../build
    ```

2. Load the rootkit:
    ```bash
    sudo insmod lkm.ko
    ```

3. Debug to see if its loaded:
    ```bash
    sudo dmesg
    ```

## Removing the Kernel Module

To remove the kernel module from the system, follow these steps:

1. Ensure you have root privileges.
2. Identify the name of the loaded module using lsmod | grep rootkit.
3. Unload the module using rmmod followed by the module name identified in the previous step. For example:
    ```bash
    sudo rmmod lkm
    ```

## Disclaimer
This rootkit is provided for educational purposes only. It demonstrates techniques that can be used for both legitimate and malicious purposes. Unauthorized or malicious use of such software may violate local laws and regulations. Use with caution and responsibility.
