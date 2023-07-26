---
title: 'Flare-On Challenge 9 Write-Up'
author: "TwinkleStar03"
tags: [Reverse Engineering, Flare-On Challenge, Write-Up]
categories: [CTF]
date: 2022-10-25
description: Flare-On Challenge 9 的玩走過程與心得
---

生平第一次把 Flare-On Challenge 全部打完，以往可能解個 5-6 題就沒動力繼續打下去了。
非常感謝那些一路上提供的夥伴們！

不過這 Write-up 確實有點晚才寫出來，都結束兩個月了 XD

## 01 - Flaredle
小小的 JS，跑某段 Code 就噴 Flag 了。

## 02 - Pixel Poker
要點到特定的像素，點到的話就會把 Flag 變成圖片的樣子顯示在畫面中。
直接用 Debugger Set EIP 到解 Flag 的地方就好了，會有一個金毛小孩對你比讚。

另一位一起奮鬥的夥伴有發現 `.rsrc` 裡面有兩張 bmp，他直接把兩張 bmp XOR 在一起後也可以弄出 Flag。
但這做法有一個缺點，解出來的圖雖然 Flag 是對的，但會被 rick-roll。

## 03 - Magic 8 Ball
打開來會看到一顆八號球，按照順序按出特定順序的按鍵，再輸入 `gimme me flag plz`，Flag 就會噴出來了。

題外話：原本想說把資料 Dump 出來自己寫 Flag 解密，但想說好累就自己動動手玩遊戲了 XD

## 04 - darn_mice
一個可愛的小東西，基本上程式會把輸入拿進去跟一個固定的 Array 做運算，然後會把運算結果的每個 Byte 當成 Shellcode 跑。

我原本以為是什麼解出惡意的 Shellcode 然後要弄很噁心的東西，但實際上就只是要確保 Code 可以正常結束。
也是就是說只要讓每個 Byte 最後運算的結果可以是 `ret` 就好。

寫個小腳本拼一下，Flag 就跑出來ㄌ。

## 05 - t8
一個小 Backdoor，但他是用 C++ 寫的，長得真的很噁心。
他會判斷某種時間然後去 Trigger 後續的行為，像是送 Http Request 之類的。

會用到 Random 去生出一個 Key 然後去 XOR Payload

可以從封包裡面知道當時跑的 Seed，還原 Backdoor 當時使用的 seed，再寫一個 Server 送一樣的回應，然後就得到 Flag 了。

## 06 - alamode
是一個會做 IPC 的小玩具，原本我以為單純就是個 .NET DLL。
實際上裡頭有被 Embed 其他 Native Code，而這些 Code 會做 IPC，如果給了正確的 Key，就會吐 Flag 回去。

## 07 - anode
一個用 [nexe](https://github.com/nexe/nexe) 包裝過後的 Node.js，可以直接從 binary 裡面找到用來跑的 JS code。
不過會看到一個很恐怖的東西...

```js
// something strange is happening...
  if (1n) {
    console.log("uh-oh, math is too correct...");
    process.exit(0);
  }
```

看得出來這個 Node.js runtime 被動過手腳了... 自己動動手實驗一下就會發現 `Math.random` 的結果序列是固定的，然後 `condition` 的判斷都很錯。

基本上程式邏輯會將輸入每個字元轉成數字，然後丟進去 State Machine，每個 State 會對應到一個 Bitwise 行為。
最後拿著 State Machine 轉換後的資料去比對另一個 Hardcoded 的內容，比對一樣的會是 Flag。

為了知道到底 `condition` 被動過什麼手腳，我直接對 JS 做 Patching，讓他變成可以執行任意 JS 的小工具，就可以知道任意 expression 的結果了。

最後寫了一個腳本，會呼叫被我 Patch 過的 anode 並模擬 State Machine。
我將 JS 整理成比較好處理的格式，腳本會將 `condition` 或是 `Math.random` 用到的數值記下來，然後構建成 `expression` 拿去送給 Patch 過的小程式。
根據結果就可以知道每個 `if...else statement` 會跑進哪裡了。最後我就會得出所有會執行到的路徑。

得到路徑之後發現就只是一連串的加減跟 XOR，把順序倒過來跑一次就可以還原出 Flag 了。

## 08 - Backdoor

### Brief
第八題應該是本次最難但也最有趣的一題了，是一題 .NET 的題目。
拿去 Decompile 基本上會發現主要的邏輯都被 obfuscate 過，基本上有兩種 function: `flare_xx` 跟 `flared_xx` (xx 是數字 e.g 01, 02...) 分別是 unpack 跟 obfuscated IL。

基本上的程式邏輯會透過 `try...catch` 去 catch 跑到 Corrupted IL 的 Exception，然後就會去跑對應的 `flare_xx` function 做 decrypt 然後把該 Function Signature 抓出來，然後與 Decrypted IL 一起丟進去 DynamicMethod 執行對應的 Code。


噁心的點是，這個解出來的東西，會用一樣的方式去跑下一層，然後一層接著一層...印象中有三層的樣子...
然後會有兩種 Unpack 手法，分別使用的加密方式不一樣。不過這些對應的 Unpack 手法也就意味著對應著某個特定的，而且是沒有被 Encrypt 的 Code，所以可以很輕易地對照出來哪些 `flared_xx` function 是用哪些方式 Unpack 的，對後續寫出 Unpacker 蠻有用的。

### Unpacking
我在這題嘗試了兩種方式，一種是透過 Hook .NET 的 Compiler 讓他在 Compile 階段把被拿去跑的 IL 吐出來，但似乎我只會取得第一層得第一個 Function 的 IL，我猜是因為 Dynamic Method 在執行的時候會進去 native code 的部分，在那邊可能又有另一個新的 Compiler 結構在做下一層的 Compile，所以我才會沒辦法得到全部的 IL。

原本想要偷懶的，最後只好寫 Unpacker，一層一層剝洋蔥...

#### Stage0
基本上是會有一張表，表上是 Offset 跟要被寫上去的值。
跟一些 [ECMA-335](http://www.ecma-international.org/publications/files/ECMA-ST/Ecma-335.pdf) 打一架之後，我知道那些被填上去的值是一系列的 Metadata token。照著一樣的方式把值拿出來填上去就好。

#### Stage1
分別有 ARC4 解密跟一個 State Machine。
ARC4 的 Key 是固定的，可以在執行過程 Dump 出來，而要將這些 Decrypted 後的 bytearray 本身就會是要跑的 IL。
然後要將這些 IL 送進去 State Machine，算出要用來 Patch 的 Metadata Token。

做完這些之後呢，就可以來逆向了 XD

### Backdoor
是一個會送 DNS Request 的 Backdoor，會將資料跟請求透過一系列轉換寫在 Hostname 上送出去給 name server (C2)。
只要能夠照著某種特定的順序執行一定順序的 Command，程式就會自己解密一個 Section 然後把這東西打開。

我是寫一個假 C2 去送 Request，但因為這東西會隨機睡一段時間，所以我就放著給他跑一陣子。
回來就發現虛擬機裡面跑出了一個黑畫面...是會動的 flag.gif！

![flag.gif](/images/Flare-On9/FLAG.gif)

## 09 - Encryptor
這題其實我花不少時間在看各種算數邏輯，基本上題目是一個勒索軟體，要想辦法破解加解密方法把被加密的 Flag 檔案解密。

這題有用到兩種加密方式，一種是對稱式加密另一個是非對稱式加密，對稱式加密的部分會直接看到 chacha20 的 magic，基本上都不用多看。

還會看到各種大數運算，很多都是用帶 carry 的指令做運算，不像我會寫出來那種要一位一位數字作運算的，算是學到新東西了。
基本上會看到兩個對`大數 - 1`的函數，接著把兩個結果相乘的行為... 不覺得這聽起來很耳熟嗎？就是 RSA 的 phi 呀！

基本上知道是 RSA 後就可以很好猜出前後的程式邏輯。這題是用 RSA 去對 chacha20 的 key 做 signing 的動作，然後會把 `N`, `Signed key + nonce`, 寫在檔案尾部。

讀出來用檔案 hardcoded 的 public key 去做解密就可以解出來了。

Decryptor:
```python
from Crypto.Cipher import ChaCha20
import argparse


SHARED_E = 65537


def main(args):
    with open(args.path, 'rb') as fp:
        data = fp.read()

    enc_state = int(data[len(data)-1-256:].decode(), 16)
    runtime_n = int(data[len(data)-(1+256) * 3:len(data)-(1+256) * 2].decode(), 16)
    enc_file  = data[:len(data)-(1+256)*4]

    print(f'[*] Encrypted data size: {len(enc_file)}')
    print(f'[*] Encrypted state: {hex(enc_state)}')
    print(f'[*] Runtime_n: {hex(runtime_n)}')

    # n = c ^ e mod N
    recoverd = pow(enc_state, SHARED_E, runtime_n)
    recoverd = bytes.fromhex(hex(recoverd)[2:])[::-1]

    key = recoverd[:0x20]
    print(f'[+] Retrived Key: {key.hex()} ({hex(len(key))})')

    nonce = recoverd[0x20+4:]
    print(f'[+] Retrived Nonce: {nonce.hex()} ({hex(len(nonce))})')

    cipher = ChaCha20.new(key=key, nonce=nonce)
    dec_file = cipher.decrypt(enc_file)
    with open(args.path+'.decrypted', 'wb') as fp:
        fp.write(dec_file)

    print(f'[+] The decrypted file should save to {args.path+'.decrypted'}')

if __name__ == '__main__':
    parser = argparse.ArgumentParser(prog="Decryptor of FlareOn Challenge 9")
    parser.add_argument("path", type=str, help="Path to file")
    main(parser.parse_args())
```

## 10 - Nur_getraumt

一個跑在麥金塔電腦上的小程式，不過解這題不需要過多的逆向。

基本上程式會拿著你的輸入當成 Key 去跟某個資料 XOR 後驗證 CRC，如果正確就會把 XOR 的結果丟給你跟你說這是 Flag。

啊...我知道 Flag 一定是 `@flare-on.com` 結尾，那我就拿著這個去對那段資料到處 XOR 看看會噴出什麼。
就這樣東拼西湊就可以還原出一部分的 Flag 或是 Key，最後拿著那些文字去 Google 會發現是一首歌的歌詞，繼續猜猜樂就可以把 Flag 拼出來了。

## 11 - The challenge that shall not be named

### Brief
是一個 PyArmor 混淆過後的 Python，可以用 Pyinstaller 解包，解開之後可以看到裡頭的 PyArmor bytecode `11.pyc`。

PyArmor 是一個 Python Obfuscator，在這題是用 extreme mode 去做 obfucate，所以會少一些 runtime 檔案。
似乎 PyArmor 會去 Hook 掉 cpython runtime 來解析自己的 bytecode 再交由 cpython 去 eval context。

### Unpack
11.pyc 裡面會看到被 PyArmor 包起來的 Bytecode，並不會看到實際的程式邏輯。

我嘗試了一些網路上的方法:
- mysterium
    - 不太管用
- 自己加料過的 cpython 3.7 會將執行中的 code object dump 出來
    - `PyEval_EvalFrameDefault`
    - 玩走後跟別人討論，似乎可以不用自己 build 這麼麻煩，只要 hook runtime 就好

以上方法效果都不是很顯著，似乎沒有跑到關鍵的內容物就停下來了。
最後弄出一個可以跑 PyArmor 的執行環境把檔案跑起來，發現他會有 `ImportError` 程式會嘗試 import `_crypt`。
可是 Windows 底下不應該會有這個 module 才對...

但現在知道他會嘗試 import 這東西，那我就寫一個 `_crypt.py` 然後在裡面塞任意想要執行的內容就可以對當時的 code 做各種事了！

我用 `inspect` 去把所有 Code Object 從 stack 上爬出來：
```python
import inspect

for idx, frameinfo in enumerate(inspect.stack()):
    print(idx, frameinfo.frame)

    c = frameinfo.frame.f_code
    for idx, obj in enumerate(c.co_consts):
        print(idx, obj)
        if inspect.iscode(obj):
            print(idx, obj.co_name, obj.co_consts)
```

然後 Flag 就噴出來了，在我毫不知情這在幹嘛的情況下。
```
13 <frame at 0x0000020B3B6FD428, file 'dist\\obf\\11.py', line 2, code <module>>
0 0
1 ('pyarmor',)
2 b'PYARMOR\x00\x00\x03\x07\x00B\r\r\n\t0\xe0\x02\x01\x00\x00\x00\x01\x00\x00\x00@\x00\x00\x00a\x02\x00\x00\x0b\x00\x00x\xa7\xf5\x80\x15\x8c\x1f\x90\xbb\x16Xu\x86\x9d\xbb\xbd\x8d\x00\x00\x00\x00\x00\x00\x00\x00\xa9\x02\xe3\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0c\x00\x00\x00@\x00\x00bs\xcc\x00\x00\x00t\x0e\x83\x00\t\x00S\x00\t\x00\t\x00\x00\x00\x00\x00\xa1u0S\xbb7?\x0f[%\xb5\x7f\xc7\xbc\xc8\x0b\x17\xdf\x12Uz\xf6D\xe9\xa1s0QH3\xb4\nR >} \xbb\x8b\x0e\x03\xda\x12R\xec\xf0c\xea:~<S\x90=\xb8\n\x83,\xb9}4\xb2\x1e\n\xe3\xd8\xbeU\x12\xf8\xd4\xf1\xb5s\x93[\\2\xb4\x07>%\xb5y \xb3\xe7\x0b\x17\xd0\xfdV\xf8\xf0\xfa\xebm?~R\\1\x17\x05\xb8(\x00t&!r\n\x8c\xd3#T\xa3\xf4\xfa\xeb\xa1r0S\xd3;c\x03W%\xf8~\xf8\xdd\r\n\x03\xcc\xa7^\x9b\n\xfe\xeb:y\x01Rb3\x81\x0f["\xb5\x7f\xaf\xb7\x94\x06\x1b\xdf_TE\xf6\xfb\xeb\xa1ruRb\xcc\xe1Y7\xd1\xa4jZ\x8f\xcc\'\xb2\xfcV\xcb)\x01\xe9\x02\x00\x00\x00\xa9\x0fZ\x05crypt\xda\x06base64Z\x08requests\xda\x06configZ\x04ARC4\xda\x06cipher\xda\tb64encodeZ\x07encrypt\xda\x04flagZ\x04post\xda\nexceptionsZ\x10RequestException\xda\x01e\xda\tExceptionz\x0e__armor_wrap__\xa9\x00r\x0c\x00\x00\x00r\x0c\x00\x00\x00\xfa\x0b<frozen 11>\xda\x08<module>\x01\x00\x00\x00s\x1a\x00\x00\x00\x08\x01\x08\x01\x08\x03\x02\x01\x02\x01\x08\x03\x0e\x01\x14\x02\x02\x01\x1a\x01\x14\x01\x10\x01\x10\x01)\n\xe9\x00\x00\x00\x00Nz\x1chttp://www.evil.flare-on.coms.\x00\x00\x00Pyth0n_Prot3ction_tuRn3d_Up_t0_11@flare-on.coms\x19\x00\x00\x00PyArmor_Pr0tecteth_My_K3y)\x03\xda\x03urlr\x08\x00\x00\x00\xda\x03keyr\x11\x00\x00\x00r\x08\x00\x00\x00r\x10\x00\x00\x00)\x01\xda\x04data'
```

不過從各種噴出來的東西可以猜一下，應該是把某些捏出來的東西解密後往 `http://www.evil.flare-on.com` 送出去吧。
賽後跟別人討論的時候發現大家都用 Hook cpython 的方式把 code object dump 出來，然後再去看他用什麼方式去加解密（~~畢竟是 Flare-On 一定是 ARC4~~）。

## 結語
最後還是要再次感謝那些陪我一起腦力激盪的夥伴們，如果只有自己一個人我可能也沒辦法玩走這次的 Flare-On Challenge。
也算是解鎖一個人生成就了，希望下次的 Flare-On Challenge 也可以順利玩走呢！