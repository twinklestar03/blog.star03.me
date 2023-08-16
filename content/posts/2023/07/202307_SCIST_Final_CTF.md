---
title: 'SCIST 2023 Final CTF Pwnable / Reverse 官方解答'
author: "TwinkleStar03"
tags: [Reverse Engineering, Pwnable, SCIST 2023]
categories: [Write-Up]
date: 2023-07-20
description: SCIST 2023 期末考 CTF Pwnable 題解
---


## 前言
這次幫 SCIST 設計了 3 題 Pwnable 與 1 題 Reverse，難度大概在簡單到中等。

---

## Pwnable
### Way Back Home
- 難度: 易
- 考點: `Ret2Text`

漏洞發生在:
```c
    char buf[0x20];
    gets(buf);
```

用到 `gets` 就是個裸的 BOF 然後有一個會直接 `system('/bin/sh')` 的 Function 可以跳。

### Shellcode Without Shell
- 難度: 易
- 考點: `Shellcode`

可以直接送 shellcode 給題目跑，但有上 seccomp，只能 `open`, `read`, `write`。

可以直接猜到要 `open('/home/pwn/flag.txt')` 然後 `read()` 到某個 buffer 再 `write()` 到 STDOUT。

### Rand Oriented Programming
- 難度: 中
- 考點: `ROP`, `Format-string`

存在 Format-String 的漏洞，可以任意 Leak Address
```c
                rand_region[used_region].space = AllocRandSpace();
                printf("What's your name?");
                scanf("%s", rand_region[used_region].name);
                printf("Random Code Author Recorded:");
                printf(rand_region[used_region].name);
                used_region++;
```

`ReadExecROP` 會直接讀你的輸入並跳上去執行，直接堆 ROP Chain 就可以了: 
```c
    if((read(0, stack+(LEN_STACK/2), LEN_STACK/2)) < 0) error("read");
    asm volatile (
            "mov %0, %%rsp\n"
            "xor %%rax, %%rax\n"
            "xor %%rbx, %%rbx\n"
            "xor %%rcx, %%rcx\n"
            "xor %%rdx, %%rdx\n"
            "xor %%rdi, %%rdi\n"
            "xor %%rsi, %%rsi\n"
            "xor %%rbp, %%rbp\n"
            "xor %%r8,  %%r8\n"
            "xor %%r9,  %%r9\n"
            "xor %%r10, %%r10\n"
            "xor %%r11, %%r11\n"
            "xor %%r12, %%r12\n"
            "xor %%r13, %%r13\n"
            "xor %%r14, %%r14\n"
            "xor %%r15, %%r15\n"
            "ret\n"
            :
            : "r" (stack+(LEN_STACK/2))
    );
```

---

## Reverse

### BinWalker Key Validator Service
- 難度: 中
- 考點: `BST`

其中最醜的結構其實是 Binary Search Tree，這支程式會把 Key 讀入並塞進去 BST 裡頭，做出 Pre-order Traversal 後將結果加上某個數字後跟某個 Array 做比對。Key 就是 Flag 的 ASCII。

`solver.py`:
```python
inorder = [18337, 16920, 16163, 10590, 8183, 5427, 3170, 793, 546, 1938, 2943, 3455, 3196, 4136, 6883, 6817, 6903, 8851, 8192, 8410, 11036, 10592, 12391, 14100, 13843, 12714, 17205, 18732, 18611, 19770, 19149, 19433, 19277, 20831, 19774, 31795, 22193, 21536, 21483, 23838, 22524, 22430, 22199, 22596, 23460, 30712, 27174, 24997, 23889, 23864, 25595, 25281, 26649, 26646, 28360, 30588, 28583, 31879]
target = [18418, 16987, 16234, 10509, 8099, 5448, 3099, 809, 599, 1997, 2868, 3345, 3148, 4191, 6844, 6851, 6814, 8957, 8289, 8360, 11109, 10559, 12308, 14119, 13938, 12760, 17270, 18756, 18668, 19790, 19135, 19418, 19326, 20736, 19722, 31837, 22229, 21631, 21378, 23920, 22476, 22508, 22227, 22561, 23510, 30631, 27218, 25047, 23909, 23886, 25502, 25267, 26730, 26658, 28324, 30557, 28634]

# flag = [0x53, 0x43, 0x49, 0x53, 0x54, 0x7b, 0x79, 0x30, 0x75, 0x5f, 0x4b, 0x6e, 0x30, 0x77, 0x5f, 0x62, 0x69, 0x6e, 0x61, 0x72, 0x79, 0x5f, 0x73, 0x33, 0x61, 0x72, 0x43, 0x68, 0x5f, 0x74, 0x72, 0x33, 0x33, 0x5f, 0x34, 0x6e, 0x64, 0x5f, 0x69, 0x6e, 0x30, 0x72, 0x64, 0x65, 0x72, 0x5f, 0x74, 0x72, 0x34, 0x76, 0x65, 0x72, 0x73, 0x34, 0x6c, 0x21, 0x7d]
flag = []
for i, t in zip(inorder, target):
    for guess in range(0xffff):
        if i ^ guess == t:
            print(f'[+] Found {guess}')
            flag.append(guess)
            break

print(len(flag))
for f in flag:
    print(chr(f), end='')
print(' ')
```