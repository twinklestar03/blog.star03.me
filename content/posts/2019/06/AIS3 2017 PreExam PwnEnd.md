---
title: 'Write-up:: AIS3 PreExam 2017 - Pwn End'
author: TwinkleStar03
tags: [AIS3 2017 PreExam, Pwnable, Write-Up]
categories: [CTF]
date: 2019-06-26
description: AIS3-2017 的題目，Pwn-end。
---

因為喜歡上 Pwnable 所以想要加強實力。在網路上找找古題來解，希望可以學到點東西!


-----

## 0x01 分析漏洞

載下來有個ELF Executable，直接拿IDA窺視裡面有甚麼。
![Disass](/images/AIS3_end/disass.png)

`_start`是初始化的部分，每個register都被歸零了。

然後看到`_end`裡面有開闢一塊0x128的buffer，然後`edx = 0x148`，之後呼叫了`syscall`，因為先前的`xor rax, rax`所以`rax=0`所以syscall會呼叫到`sys_read(0, rsi, 0x148)`。

到這邊漏洞已經探頭了，因為`edx = 0x148`所以`sys_read`可以read進0x148個byte，但是開出來的buffer只有0x128個byte，**Stack BufferOverflow Confirm!!**

---

## 0x02 建構Payload

但要怎麼利用這個洞Spawn a shell呢? 在`_start`中下面還有一個`syscall`，那應該可以用他來執行`sys_execve`吧~

但是....我們可以控制的register只有rsi**(buf)**跟rax**(Function return放rax，所以可以透過控制輸入的字元長度來控制rax)**，但rdi不能控制所以不能正常的執行`/bin/sh`....

回頭爬爬Syscall table，發現有一個性質接近也可以執行檔案的函數`stub_execveat(int dfd, const char __user *filename, const char __user *const __user *argv, const char __user*const __user *envp, int flags)`

Hey!這樣子好像行得通，`*filename`這參數可以控制了因為他吃的是rsi，然後呼叫他的方法是把rax設定成322，所以**輸入字串長度要是322**，**但是要注意要把rdx清空，不然會爛掉。**

把rdx清空不難，在_start前面有`xor rdx, rdx`，Stack都可以被~~灌滿了///~~跳過去就不是問題了。

所以輸入要是`/bin/sh\x00` + 塞0x120個byte來填buf + `xor rdx rdx`的address + 更多垃圾byte來湊長度。

---

## 0x03 生成Payload

```python exploit.py
filename = '/bin/sh\x00'
padding = 'A' * (296 - 8) # 填剩下來的buf
xor_rdx_rdx = '\xed\x00\x40\x00\x00\x00\x00\x00'

print(filename + padding + (xor_rdx_rdx)*3 + '\x41')

```

---

## 0xFF 結語

原本是剛學到rop的概念，想要拿題目來練習，找著找著找到這題，覺得做法很有趣就記錄下來了w

成功get shell的時候總是很開心呢w (ﾉ∀`*)