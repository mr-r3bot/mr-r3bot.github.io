---
layout: post
title:  "eBPF Programming: Write eBPF program in C (part 2)"
date:   2021-11-05 16:00:00 +0700
categories: research
author: Quang Vo
toc: true
description: Vulnerability Research 
tags: eBPF, research, linux, kernel
---

## Introduction

### 1. Choosing your level of eBPF abstraction
- Raw eBPF instructions written by hand using a C macro DSL.
- Direct use of LLVM/Clang to compile C into eBPF ELF files.
- High-level APIs that compile and load strings of a custom DSL C
  - `iovisor/bcc` ( Python )
  - `iovisor/gobpf` ( Golang )  

In this blog post, we will code eBPF program in C and use LLVM/Clang to compile C into ELF files.

### 2. Program context & section

First, there are 2 things we need to know about eBPF program:
- There are many different program types and each **program type** accept a different parameter input ( expected context ): [https://blogs.oracle.com/linux/post/bpf-a-tour-of-program-types](https://blogs.oracle.com/linux/post/bpf-a-tour-of-program-types) 
- When program is loaded, it will scan for `ELF section` in the BPF program, here is the list of all the ELF sections: [https://github.com/pratyushanand/learn-bpf/blob/master/bpf_load.c](https://github.com/pratyushanand/learn-bpf/blob/master/bpf_load.c)


example code of SECTION scanning:
```c
bool is_socket = strncmp(event, "socket", 6) == 0;

bool is_kprobe = strncmp(event, "kprobe/", 7) == 0;

bool is_kretprobe = strncmp(event, "kretprobe/", 10) == 0;

bool is_tracepoint = strncmp(event, "tracepoint/", 11) == 0;

bool is_xdp = strncmp(event, "xdp", 3) == 0;

bool is_perf_event = strncmp(event, "perf_event", 10) == 0;

bool is_cgroup_skb = strncmp(event, "cgroup/skb", 10) == 0;

bool is_cgroup_sk = strncmp(event, "cgroup/sock", 11) == 0;
```
