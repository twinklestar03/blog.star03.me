---
title: '交大 2022 網路程式設計概論 - 修課心得' 
tags: [NYCU, INP, Network Programming]
categories: [NYCU]
date: 2023-01-05
description: 2022 陽明交通大學，網路程式設計概論修課心得
slug: nycu-inp-f22
---

# 課程概要
基本上就是學習網路程式的技術架構並親手實踐。
這次的上課模式跟往年都不一樣，每週上課時間不教學而是實作一個 Lab。
當天做完並完成 DEMO 可以得到 105% 的分數，下週 DEMO 的話則是 90% 的分數。

沒有期中期末考試而是出作業。期中作業是寫一個 IRC Chat Server 期末則是寫 Name Server。

每個 Lab 都相當有趣，第一次體驗到這樣形式的課程，覺得很新鮮！

如果想要看看實作內容的話，可以參考我[記錄了所有 Lab 的 Repository](https://github.com/twinklestar03/nycu-inp-f22/)。

# 最特別的 Lab8
尤其是 Lab8 - Robust UDP Challenge，兩個同學一組要一起構思並寫出基於 UDP 的 File Transfer Protocol。
總共傳 1,000 個檔案，隊伍之間會有排名，根據傳輸完成率與傳輸的時間排名次。

老師有提供一個記分板，但官方計分板上就只有排名，我覺得一個可以做成 KoTH 形式的小比賽沒有視覺化就太可惜了，
就現學現賣寫了一個 echart.js 的網頁出來，並去官方計分板上面爬資料下來做視覺化，可以到我的網站上玩玩看。 [連結](https://netproc.t03.io/)

基本上想要爭取名次的組別都會瘋狂最佳化自己的傳輸方式，透過壓縮資料或是改善 Protocol 的方法拉高 Channel Utilization 來加快傳輸速度。
我與 [@nella17](https://github.com/nella17) 一組，在最後取得了第一名的成績。（花費 12 秒，官方解 ~40 秒）

老師沒預期到大家會猛力地在最佳化自己的作法，所以空下一週的時間讓抽組別上台分享自己的作法，前三名強制上台報告。
大家似乎蠻喜歡我們這組的發表的，發表過程中還遇到地震，看來地牛應該也蠻喜歡的 XD。

# 學到的東西
- Linux Socket Programming
    - TCP
    - UDP
    - Domain Socket
    - Raw Socket

- IRC Server Implementation
- Name Server Implementation

# 結語
就如一開始所說的一樣，這樣的上課模式很新鮮很好玩。
對於喜歡實作大於考試的我來說，這樣的課程規劃再好不過了。
不過課程錄影的部分就沒有很認真的看了。

~~這堂課又涼又甜，就算不看課程錄影也可以高分過關喔，只要實作能力夠強就好~~