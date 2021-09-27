---
layout: post
title:  "DownUnder CTF 2021 - Attacking AES ECB mode - Break Me challenge"
date:   2021-09-27 16:00:00 +0700
categories: research
author: Quang Vo
toc: true
description: Research crypto 
tags: Crypto
---

## Introduction
DownUnder CTF was an awesome event, I enjoyed it a lot. Unfortunately I'm not Australian so I cannot join a team to compete for prizes. I solved the web challenges ( easy-mode) quite fast, after that, I decided to try something new which I've never done before - Crypto challenge :(. @James Kettel once said that if you want to learn something new but you don't know which topic to choose to learn, pick the one that you scared the most, because that's your weakness. I came across this awesome [article](https://zachgrace.com/posts/attacking-ecb/) explain how to attack AES ECB mode

Break-me Challenge was a AES encryption challenge with ECB mode:

The source code:

```python
#!/usr/bin/python3
import sys
import os
from Crypto.Cipher import AES
from base64 import b64encode

bs = 16 # blocksize
flag = open('flag.txt', 'rb').read().strip()
key = open('key.txt', 'r').read().strip().encode() # my usual password

def enc(pt):
    cipher = AES.new(key, AES.MODE_ECB)
    ct = cipher.encrypt(pad(pt+key))
    res = b64encode(ct).decode('utf-8')
    return res

def pad(pt):
    while len(pt) % bs:
        pt += b'0'
    return (pt)

def main():
    print('AES-128')
    while(1):
        msg = input('Enter plaintext:\n').strip()
        pt = flag + str.encode(msg)
        ct = enc(pt)
        print(ct)

if __name__ == '__main__':
    main()

```

So our ciphertext will have format: `Cipher text = flag + user_input + key + pad` 

Our purpose is to leak the `key` value from ciphertest to decrypt the flag.

## Attacking ECB

In ECB mode,  each block of plaintext is encrypted independently with the key as demonstrated by the diagram below.

<img width="691" alt="image" src="https://user-images.githubusercontent.com/37280106/134861544-8428cd24-0b9f-48c8-be5e-1f5438e91c2b.png">

Since each block will be **independently** encrypted with the key, so identical block will have identical cipher text. that's ECB's weakness. If we encrypt with data length > block size, there will be identical blocks of ciphertext.

Basically, the strategy to attack ECB included 3 steps:
- Identify the block size
- Find the offset
- Brute force character by character

### 1. Identify the block size

This is easy, the block size is 16 bytes as stated in the source code. In the real-world scenarios, if you don't have access to the source code, you can still identify the block size by sending specific characters to the **cryptographic oracle** ( the server that give us ciphertext) and watch the block's length change.

```bash
[+] Opening connection to pwn-2021.duc.tf on port 31914: Done
Send:  AAAAAAAAAAAAAAAA
Length:  64
Cipher text from server:  ['8MAq3pGs7/KTcv0c3ijqTJhv/z9V8QA7l9TkMkU72YJxgLlJxgOGUNChbRePei65m8XWdhGwJb3Z/JWY2GlrlQ==', '']
==============================
Send:  AAAAAAAAAAAAAAAAA
Length:  80
Cipher text from server:  ['8MAq3pGs7/KTcv0c3ijqTJhv/z9V8QA7l9TkMkU72YJxgLlJxgOGUNChbRePei65Dcmd8bzNKRbuji9aZ1gFG8kjwLbp8PJU0prnC44o+1g=', '']
[*] Closed connection to pwn-2021.duc.tf port 31914
```

As you can see, when we send 16 characters of A, the total block's length is 64, when we send 17 characters, we get 80
So the block size will be: 80-64 = 16 bytes.

### 2. Find the offset

In this [article](https://zachgrace.com/posts/attacking-ecb/), the author did a very good job in explaining what is the offset and how do we find it. I copied a part from his blog to help you easier to understand, if you want to read more about this in detail, I suggest you go and read his blog.

*In real-world scenarios, we’ll most likely not have our chosen plaintext start as the first byte of a block, so we’ll need to calculate the offset. The offset can be found by prepending bytes in increasing length to `block size * 2` of a static value until two consecutive blocks of ciphertext are found.

*By adding characters to the beginning of our control data, we will eventually get two consecutive blocks of repeating ciphertext.*

The code to find offset:
```python

def find_offset(p) -> int:
    static = "A"*block_size*2
    offset_char = "}"
    for i in range(0, block_size):
        data_send = offset_char * i + static
        data_return = send_payload(p, data_send)
        blocks = b64decode(data_return[0])
        if blocks[block_size*2] == blocks[block_size*3]:
            print("Found offset: ", i)
            return i

    print("Offset error")
    exit(1)

```

The result I got back from server is 0, so there is no offset

### 3. Brute force character by character

Once we have the offset, we can start to brute force the key value. We will do it by filling the inputs with `block_size - 1` character and get the ciphertext from the oracle. The last byte will be append from an unknown byte of ciphertext and we save that value as our `base_block` ( In this challenge, the unknown byte will be a part of `key` value because of how the ciphertext was formatted ). 

Now, we can brute force the unknown byte by looping through all the printable characters and comparing with our `base_block` until we find a match.

To find the next value of unknown ciphertext, we can use a static value of `block size - 2` so two bytes of the cipher text enter our controlled block. The payload will be `offset + static + key`

It will be easier to understand it if you look at this [diagram](https://zachgrace.com/posts/attacking-ecb/)


Code to brute force the key value:
```python
def brute_force_letter(p, key="") -> str:
    offset = find_offset(p)
    offset_str = "B" * offset
    try:
        for i in range(0, block_size):
            static = "A"*(block_size - len(key) - 1)
            base_block = send_payload(p, offset_str + static)
            base_block = b64decode(base_block[0])
            block_should_be = base_block[block_size*2: block_size*3]

            for c in string.printable:
                data_send = offset_str + static + key + c
                data_return = send_payload(p, data_send)[0]
                decoded_block = b64decode(data_return)
                if block_should_be == decoded_block[block_size*2:block_size*3]:
                    print ("Found a character: ", c)
                    key += c
                    print ("Current key value: ", key)
                    break
        return key
        
    except Exception:
        p.close()
        print ("Reconnecting ....")
        new_process = remote("pwn-2021.duc.tf", 31914)
        brute_force_letter(new_process, key)

```

We can recover the full key in plaintext by keep repeating the process.

```bash
Found a character:  0
Current key value:  !_SECRETSOURCE_!
Flag: DUCTF{ECB_M0DE_K3YP4D_D474_L34k}

```

### Full source code

```python
import string
from Crypto.Cipher import AES
from base64 import b64decode
from pwn import *


block_size = 16


def send_payload(p, data: str) -> str:
    p.sendlineafter("Enter plaintext:", data.encode())
    p.recvline()
    return_data = p.recvline()
    return return_data.decode().split("\n")


def find_offset(p) -> int:
    static = "A"*block_size*2
    offset_char = "}"
    for i in range(0, block_size):
        data_send = offset_char * i + static
        data_return = send_payload(p, data_send)
        blocks = b64decode(data_return[0])
        if blocks[block_size*2] == blocks[block_size*3]:
            print("Found offset: ", i)
            return i

    print("Offset error")
    exit(1)


def brute_force_letter(p, key="") -> str:
    offset = find_offset(p)
    offset_str = "B" * offset
    try:
        for i in range(0, block_size):
            static = "A"*(block_size - len(key) - 1)
            base_block = send_payload(p, offset_str + static)
            base_block = b64decode(base_block[0])
            block_should_be = base_block[block_size*2: block_size*3]

            for c in string.printable:
                data_send = offset_str + static + key + c
                data_return = send_payload(p, data_send)[0]
                decoded_block = b64decode(data_return)
                if block_should_be == decoded_block[block_size*2:block_size*3]:
                    print ("Found a character: ", c)
                    key += c
                    print ("Current key value: ", key)
                    break
        return key
        
    except Exception:
        p.close()
        print ("Reconnecting ....")
        new_process = remote("pwn-2021.duc.tf", 31914)
        brute_force_letter(new_process, key)

def main(p):
    key = brute_force_letter(p)
    data = send_payload(p, "")
    cipher = AES.new(key, AES.MODE_ECB)
    pt = cipher.decrypt(data[0])
    print(pt)
    DUCTF{ECB_M0DE_K3YP4D_D474_L34k}


if __name__ == "__main__":
    p = remote("pwn-2021.duc.tf", 31914)
    main(p)

```
