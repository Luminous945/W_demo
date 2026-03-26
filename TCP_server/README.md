简单的TCP服务器。

tcp避不开的问题
1. 粘包如何处理
（1） 固定长度
    通过协议规定长度
（2） 使用分隔符
    例如 HTTP：
        GET / HTTP/1.1\r\n
        Host: example.com\r\n
        \r\n
        \r\n 就是分隔符。
    适合：
        聊天
        HTTP
        文本协议
（3） 长度字段
    RPC / 游戏服务器 / 高性能服务器最常见方案。
    协议设计：
        | length | data |
其实就是设计一个通讯协议。
recv()
   ↓
缓冲区 buffer
   ↓
协议解析
   ↓
handleMessage()