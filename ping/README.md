# ping

ping destIP -l length -n counts

一个简单Ping程序，每隔1s使用ICMP报文向目标发送一个ICMP请求(长度为length),总次数由counts指定。


<ul>fix me
    <li>length长度超过一定长度产生Segmentation fault</li>
    <li>接收到的报文最大长492。</li>
<ul>

