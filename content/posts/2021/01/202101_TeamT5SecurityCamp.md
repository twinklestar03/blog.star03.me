---
title: 'TeamT5 資安研習營 - 實作題目分析'
author: "TwinkleStar03"
tags: [MalwareAnalysis, TeamT5 SecurityCamp]
categories: [Write-Up]
date: 2021-01-10
description: TeamT5 資安研習營前測，程式分析過程與心得。
---

新的一年，自己的網誌也該來更新一下了!
除了把Hexo升級跟把網誌變成Dark mode外，怎麼能夠少了新文章呢?

2021是我進入資安領域的第二年，然後發現了TeamT5辦了一個SecurityCamp。
想要學習新東西所以報名參加，發現參加前還要先做樣本分析...真的有夠硬核XD

這篇文章就是我在分析過程的二三事。



---

## Recon

把樣本塞進IDA後發現這隻檔案有被加殼，加上的是UPX的殼。

丟進PEStudio可以知道這是一隻DLL檔案，等等後續可能會用到Loader來協助自己分析。
![](/images/TeamT5SecurityCamp/recon_pestudio.png)


## 手動脫殼的二三事

因為沒甚麼接觸過樣本分析，所以我想要從手動脫殼來開始練習，所以就不使用 `upx -d` 了。

這邊用的是x32dbg，用rundll32載入DLL再踩上DLL自己的EP。
![](/images/TeamT5SecurityCamp/unpacking_rundll32.png)

運用Unpack時會改動ESP的特性，在對ESP操作的instruction下斷點。
Continue 後我發現了這個地方。
![](/images/TeamT5SecurityCamp/unpacking_cleaning_stack.png)

不斷的往Stack中放 `0`，之後接著跳去一個很遠的地方，我認為那邊就是這隻DLL的OEP了。

前往目標位置然後用Scylla把Unpacked的DLL dump出來，然後用Scylla來Fix IAT 跟 Import table，之後就可以來繼續分析了。

只不過抓Import Table似乎出了點問題...
![](/images/TeamT5SecurityCamp/unpacking_import_table.png)

我後續比對自己手脫跟 `upx -d` 脫出來的檔案，發現會有function數量上的差異。
而且消失的function不在連續記憶體上，所以排除了dump整個爛掉的可能，猜測就是這個環節出了問題。
![](/images/TeamT5SecurityCamp/unpacking_missing_function.png)

> 後續檢查發現，少掉的function大多都是IDA沒有解析出來，但他還是存在於檔案中的
> 是一些長的像jump table結構的東西。
![](/images/TeamT5SecurityCamp/unpacking_missing_function_2.png)
> 所以我後續分析還是用UPX脫出來的為準。


## 行為分析

我這邊透過Process Montior與Wireshark來記錄，在透過rundll32去跑這隻DLL的RegisterServer函數。

### 生成常駐檔案

樣本會先生成一隻DLL，並放在: 
`C:\ProgramData\Software\Microsoft\Windows\Defender\AutoUpdate.dll`
之後使用regsvr32去註冊這隻DLL成為DLL Server。

此外我在尋找AutoRun的時候找到了這個，也能證明這一個DLL是生出來的檔案並常駐於系統。
```
key: HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce
name: WindowsDefender
operation: write
typeValue: REG_SZ
value: regsvr32.exe /s "C:\ProgramData\Software\Microsoft\Windows\Defender\AutoUpdate.dll"
```

而這個AutoUpdate.dll一樣有加殼，也是UPX的殼，然後run起來行為差不多(#

### 移除初始檔案

從ProcessMonitor中，可以看到樣本會先生成一個Patch檔，並放在 `C:\ProgramData\temp\[A-Za-z0-9]{4}.tmp.bat`。之後會呼叫cmd去執行這個Batch file來達成移除初始檔案。

![](/images/TeamT5SecurityCamp/behavior_spawn_batch.png)

Batch File:
```batch
:repeat
    del "C:\Users\tim12\Desktop\TeamT5_Analysis\Unpacking\b6eeed4fd8eb48126ffb216fd392ae74.dll"
    if exist "C:\Users\tim12\Desktop\TeamT5_Analysis\Unpacking\b6eeed4fd8eb48126ffb216fd392ae74.dll" goto repeat
    del "%~f0"
```

### DNS Request

樣本跑起來之後，我在Wireshark錄到了一個DNS Request，看起來是要解析C2 Server的位置。

不過這邊卻長得像一個忘記改掉的Placeholder，蠻有趣的w

![](/images/TeamT5SecurityCamp/behavior_dns_request.png)
