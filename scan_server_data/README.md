# server_scan
采集服务器信息

## 介绍
使用nmap的python库，进行服务器数据信息的采集，采集的内容包括：

1. 端口号
2. 状态（开放/关闭/过滤）
3. 端口运行协议（TCP/UDP等）
4. 服务器操作系统（Windows，Linux）
5. 端口运行哪些服务（邮件服务/DNS服务）


## 环境配置

1. pip install python-libnmap


## 目前发现的问题

1. 探测丢包情况很严重，需要进行多次探测；
2. 使用nmap,python第三方包使用libnmap，需要进一步考虑；
3. 论文量来进行评估，写成一篇呢，还是两篇。

## 暂时备注
1. 199.15.81.130，该服务器IP开放很多的服务
2. 219.146.1.66，山东电信从哈尔滨无法dig进行域名解析，其端口udp和tcp扫描为filter|open和filter，但是从山东可以dig进行域名解析，其端口扫描，tcp和udp都是open。是否可以从这里探测dns的提供服务的依据。
另外通过端口扫描，也可以判断某ip是否为dns服务器。
3. 只能进行常用端口扫描，全部扫描不现实，太多数据，并且容易出错。

## 程序改进的地方
1. 输入的参数的控制
2. -F的参数时候，代码里面1000和100的改写
3. 需要给数据库增加索引，否则越来越慢


## 数据库查询命令

1. 实现统计功能
```
db.getCollection('server_tcp_details').aggregate([
{ $match : { 'source':'dns','state':'up'}},
{$group : {_id : "$open_count", num_tutorial : {$sum : 1}}}
])
```

