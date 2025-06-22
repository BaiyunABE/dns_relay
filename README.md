# DNS Relay Server

这是一个简单的DNS中继服务器实现，运行在Windows平台上。它监听本地UDP端口53，接收客户端的DNS查询请求，然后将请求转发给远程DNS服务器（如8.8.8.8），并将响应返回给原始客户端。

## 功能特性

- 本地DNS请求监听（UDP端口53）
- DNS请求转发到远程DNS服务器
- DNS报文解析和显示（包括头部、问题和回答部分）
- 支持A记录和CNAME记录的解析
- 超时处理（5秒超时）

## 项目结构

```
dns_relay/
├── include/
│   └── dns_relay.h         # 头文件声明
├── src/
│   ├── dns_relay.c         # DNS中继核心实现
│   └── main.c              # 主程序入口
└── README.md               # 项目说明（本文档）
```

## 代码说明

### 核心组件

1. **DNS报文结构**
   - `dns_header`: DNS头部结构（16字节）
   - `dns_question`: DNS问题部分结构
   - `dns_resource`: DNS资源记录结构

2. **网络处理**
   - `init_dns_relay()`: 初始化Winsock和套接字
   - `run_dns_relay()`: 主循环，处理DNS请求
   - `close_dns_relay()`: 清理资源

3. **DNS解析**
   - `read_dns_header()`: 解析DNS头部
   - `read_domain_name()`: 读取域名（支持压缩格式）
   - `read_dns_question()`: 解析问题部分
   - `read_dns_resource()`: 解析资源记录

4. **显示功能**
   - `print_dns_header()`: 格式化显示DNS头部
   - `print_dns_question()`: 显示问题部分
   - `print_dns_answer()`: 显示回答记录

### 工作流程

1. 初始化Winsock和本地监听套接字
2. 进入主循环，等待客户端DNS查询
3. 接收查询后，解析并显示DNS报文
4. 将查询转发到远程DNS服务器
5. 接收远程服务器的响应
6. 将响应返回给原始客户端

## 编译与运行

### 编译说明

使用支持C99标准的编译器（如GCC或MSVC）编译：

```bash
gcc src/dns_relay.c src/main.c -o dns_relay.exe -lws2_32
```

### 运行程序

1. 以管理员权限运行程序（需要绑定53端口）
2. 程序将显示：
   ```
   DNS中继端口 53 转 8.8.8.8:53
   ```
3. 配置客户端DNS设置为127.0.0.1
4. 所有DNS查询将被中继转发

## 输出示例

```
收到 192.168.1.100:12345 DNS查询
DNS Message Header:
+---------+-------+----------------------+
| Field   | Value | Description          |
+---------+-------+----------------------+
| ID      | 12345 | Transaction ID       |
| QR      | 0     | Query                |
| Opcode  | 0     | Standard query       |
...（更多头部信息）...

DNS Message Question:
QNAME: example.com
+--------+-------+-------------+
| Field  | Value | Description |
+--------+-------+-------------+
| QTYPE  | 1     | A           |
| QCLASS | 1     | IN          |
+--------+-------+-------------+

收到 8.8.8.8:53 响应
DNS Message Answer:
NAME: example.com
+----------+-------+----------------------+
| Field    | Value | Description          |
+----------+-------+----------------------+
| TYPE     | 1     | A                    |
| CLASS    | 1     | IN                   |
| TTL      | 3600  | Time To Live         |
| RDLENGTH | 4     | Resource Data Length|
+----------+-------+----------------------+
RDATA: 93.184.216.34
```

## 注意事项

1. 需要以管理员权限运行（绑定53端口需要特权）
2. 仅支持IPv4和A/CNAME记录类型
3. 超时时间设置为5秒
4. 远程DNS服务器默认为8.8.8.8，可在代码中修改

## 可能的扩展

1. 添加本地DNS缓存
2. 支持域名过滤功能
3. 增加配置文件支持
4. 支持更多DNS记录类型（如AAAA、MX等）
5. 添加日志记录功能