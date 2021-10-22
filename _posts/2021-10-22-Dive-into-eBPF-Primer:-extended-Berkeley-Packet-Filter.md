---
layout: post
title:  "Dive into eBPF - extended Berkeley Packet Filter"
date:   2021-10-22 16:00:00 +0700
categories: research
author: Quang Vo
toc: true
description: Vulnerability Research 
tags: eBPF, research, linux, kernel
---

# Introduction
This is my first blog of the eBPF vulnerability research journey, the goal is to reproduce this amazing [exploit](https://www.graplsecurity.com/post/kernel-pwning-with-ebpf-a-love-story), 
First, I will dive into what is eBPF and program some simple eBPF program. Most of the content here is copied from various sources, mostly from this amazing [write-up](https://www.graplsecurity.com/post/kernel-pwning-with-ebpf-a-love-story)


Reference:
- https://www.graplsecurity.com/post/kernel-pwning-with-ebpf-a-love-story
- https://www.collabora.com/news-and-blog/blog/2019/04/05/an-ebpf-overview-part-1-introduction/
- https://github.com/torvalds/linux/blob/master/include/uapi/linux/bpf.h
- https://docs.cilium.io/en/latest/bpf/#instruction-set
- https://prototype-kernel.readthedocs.io/en/latest/bpf/ebpf_maps.html
- https://homepages.dcc.ufmg.br/~mmvieira/so/papers/Fast_Packet_Processing_with_eBPF_and_XDP.pdf


### 1. What is eBPF ?
eBPF provides a way for a user mode application to run code in kernel without needing to write a kernel module. The purported benefits of using eBPF versus a kernel module are ease of use, stability, and security. There are also performance improvements gained by doing certain tasks directly in the kernel compared to a pure user mode program. eBPF programs are used to do a myriad of things such as: tracing, instrumentation, hooking system calls, debugging, and of course, packet capturing/filtering.

eBPF programs are written in a high level language and compiled into eBPF bytecode. eBPF programs are run by the Kernel when events occur, so they can be viewed as a form of function hooking or event-driven programming. 

This allows to hook and inspect memory in any function at any instruction in both kernel and user processes, to intercept file operations, inspect specific network packets and so on.

Steps to run eBPF program:
- Userspaces send bytecode to the kernel together with a **program type** which determines what kernel areas can be accessed
- The kernel runs a **verifier** on the bytecode to make sure the program is "safe" to run. 
- The kernel **JIT compilers** compile the bytecode to native code and inserts it in ( or attach to ) the specified code location
- The inserted code writes data to ringbuffers or generic key-value maps
- Userspaces reads the result values from the shared map or ringbuffers

<img width="770" alt="image" src="https://user-images.githubusercontent.com/37280106/138434166-9702ffeb-e456-4dad-a202-ac6d3467f36c.png">


### 2. eBPF Virtual Machine  & Byte-code

- eBPF VM use **11 64 bit-registerers** , a program counter and a **512 byte fixed-size stack**
- 9 registers are general purpose read-write, one is a read-only stack pointer and the program counter is imcplicit, i.e , we can only jump to a certain offset from it.
- The VM registers are always 64-bit wide ( even when running on 32-bit ARM processor kernel), and support 32-bit subregister addressing if the most significant 32 bits are zeroed

```text
r0:

stores return values, both for function calls and the current program exit code
--------------------
r1-r5:

used as function call arguments, upon program start r1 contains the "context" argument pointer
--------------------
r6-r9:

these get preserved between kernel function calls
--------------------
r10:

read-only pointer to the per-eBPF program 512 byte stack
```

The eBPF [program type](https://github.com/torvalds/linux/blob/v4.20/include/uapi/linux/bpf.h#L136) supplied at load time determines exactly what subset of kernel functions are available for calling, as well as what "context" arguments gets supplied 	via `r1` at program startup. The meaning of the program exit value stored in `r0` is also determined by the program type.

Each function call can have at most 5 arguments in registers `r1-r5`; this applies to both **ebpf-to-ebpf calls and to kernel function calls**. Registers `r1-r5` can only store numbers or pointers to the stack (to be pased as arguments to functions), never direct pointers to arbitrary memory. All memory accesses must be done by first loading data to the eBPF stack before using it in the eBPF program. This restriction helps the eBPF verifier, it simplifies the memory model to enable easier corectness checking.

### 3. The eBPF Maps

<img width="767" alt="image" src="https://user-images.githubusercontent.com/37280106/138434196-d3def4e6-b02b-4af4-bc01-cdf4ff4ed537.png">


User mode processes can interact with a eBPF program in the kernel using eBPF maps. They can also be used by multiple eBPF programs to interact with each other. They are a generic key/value store with an arbitrary data structure [6](https://prototype-kernel.readthedocs.io/en/latest/bpf/ebpf_maps.html). There are various types of maps including: arrays, queues, and stacks.

A map is described by five different attributes:
-   `type` - the data structure of the map
    
-   `key_size` - the size in bytes of the key used to index an element (used in array maps)
    
-   `value_size` - the size in bytes of each element
    
-   `max_entries` - the maximum number of entries in the map
    
-   `map_flags` - describes special characteristics of the map, such as if the entire map memory should be preallocated or not.

eBPF maps can be created and altered from user space via the `bpf()` syscall using the `BPF_MAP_CREATE` command, updated using the `BPF_MAP_UPDATE_ELEM` command, and retrieve its contents using the `BPF_MAP_LOOKUP_ELEM` command. eBPF maps can accessed by eBPF programs using the file descriptor returned by `BPF_MAP_CREATE` and calling eBPF helper functions, which will return pointers to values within the map.

### 4. The eBPF Verifier

The verifier starts by building a control flow graph of the program. Then, it will verify each instruction is valid and all memory accesses are safe through each possible flow of control. 

Afterwards, it will add in runtime checks to the program. This process, called **ALU Sanitation**, inserts patches to the eBPF bytecode to ensure permitted memory ranges are not violated during runtime when performing pointer arithmetic

-   No back edges,  infinite loops, or unreachable instructions.
    
-   No pointer comparisons can be performed, and only scalar values can be added or subtracted to a pointer. A scalar value in the eBPF verifier is any value that is not derived from a pointer. The verifier keeps track of which registers contain pointers and which contain scalar values.
    
-   Pointer arithmetic can not leave the “safe” bounds of a map. Meaning, the program can not access anything outside the predefined map memory. To do so, verifier keeps track of the upper and lower bounds of the values for each register.
    
-   No pointers can be stored in maps or stored as a return value, in order to avoid leaking kernel addresses to user space.

#### 4.1 Range Tracking
The verifier stores the following bound values, for every register in each possible path of execution, to ensure there are no out-of-bound memory accesses:

-   `umin_value, umax_value` store the min/max value of the register when interpreted as an unsigned (64 bit) integer
    
-   `smin_value,smax_value` store the min/max value of the register when interpreted as a signed (64 bit) integer.
    
-   `u32_min_value,u32_max_value` store the min/max value of the register when interpreted as an unsigned (32 bit) integer.
    
-   `s32_min_value,s32_max_value` store the min/max value of the register when interpreted as a signed (32 bit) integer.
    
-   `var_off` contains information about the bits of the the register that are known. It is stored in a structure called tnum which contains two 64 bit fields: mask and value. Every bit that is set in mask means the value of that bit is **unknown.** The unset bits are known, and their true value are stored in value. For example, if `var_off = {mask = 0x0; value = 0x1}`, all bits of the register are known, and the register is known to have a value of 1. If `var_off = {mask = 0xFFFFFFFF00000000; value = 0x3}` it means that the lower 32 bits of the register are known to be `0x00000003` and the upper 32 bits are unknown.
    

These bounds are used to update each other. In particular, if `var_off` indicates the register is a known constant, the min/max bounds are updated to reflect the known value.

#### 4.2 ALU Sanitation

ALU Sanitation is a feature that was introduced to supplement the static range tracking of the verifier. The idea is to prevent OOB memory accesses if the value of registers do not fall within their expected range during runtime. This was added to help mitigate potential vulnerabilities in the verifier and protect against speculative attacks.

For every arithmetic operation that involves a pointer and a scalar register, an alu_limit is calculated. This represents the maximum absolute value that can be added to or subtracted from the pointer [[4]](https://www.zerodayinitiative.com/blog/2020/4/8/cve-2020-8835-linux-kernel-privilege-escalation-via-improper-ebpf-program-verification). Before each of these operations, the bytecode is patched with the following instructions:

```c
*patch++ = BPF_MOV32_IMM(BPF_REG_AX, aux->alu_limit);
*patch++ = BPF_ALU64_REG(BPF_SUB, BPF_REG_AX, off_reg);
*patch++ = BPF_ALU64_REG(BPF_OR, BPF_REG_AX, off_reg);
*patch++ = BPF_ALU64_IMM(BPF_NEG, BPF_REG_AX, 0);
*patch++ = BPF_ALU64_IMM(BPF_ARSH, BPF_REG_AX, 63);
*patch++ = BPF_ALU64_REG(BPF_AND, BPF_REG_AX, off_reg);
```
  

Note that off_reg represents the scalar register being added to the pointer register, and BPF_REG_AUX represents the auxiliary register.

The above instructions do the following:

1.  The value of alu_limit is loaded into BPF_REG_AX.
    
2.  The value of off_reg at runtime is subtracted from alu_limit and stored into BPF_REG_AX. If off_reg > alu_limit, the highest bit of BPF_REG_AX is set (the sign bit).
    
3.  If the difference stored in BPF_REG_AUX is positive and off_reg is negative, indicating that alu_limit and the register’s value have opposing signs, the BPF_OR operation will set the sign bit.
    
4.  The BPF_NEG operation will negate the sign bit. If the sign bit is set, it will become 0, and if not, it will become 1.
    
5.  The BPF_ARSH operation does an arithmetic right shift of 63 bits. This fills BPF_REG_AX with either all 0s or 1s, the value of the sign bit.
    
6.  Depending on the result of the above operation, the BPF_AND operation will either null out off_reg or leave it unchanged.
    

This means that if off_reg exceeds alu_limit, or if off_reg and alu_limit have opposing signs, the value of off_reg will be replaced with 0, nulling the pointer arithmetic operation.

### 5. eBPF programming

#### 5.1. List of expected contexts of BPF program

List of expected context of each **eBPF program type**: https://blogs.oracle.com/linux/post/bpf-a-tour-of-program-types

#### 5.2. ELF section scan when bpf_load is called
- Code that compare ELF section when scanning: https://github.com/pratyushanand/learn-bpf/blob/master/bpf_load.c

```c
bool is_socket = strncmp(event, "socket", 6) == 0;

bool is_kprobe = strncmp(event, "kprobe/", 7) == 0;

bool is_kretprobe = strncmp(event, "kretprobe/", 10) == 0;

bool is_tracepoint = strncmp(event, "tracepoint/", 11) == 0;

bool is_xdp = strncmp(event, "xdp", 3) == 0;

bool is_perf_event = strncmp(event, "perf_event", 10) == 0;

bool is_cgroup_skb = strncmp(event, "cgroup/skb", 10) == 0;

bool is_
