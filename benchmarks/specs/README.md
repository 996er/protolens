# 协议最小状态模型

本目录为协议适配提供可阅读的状态迁移示例，沿用 `TRANSITION:` 文本格式。
这些文件是人工编写的简化模型，不是 RFC/标准全文，也不是目标实现已经验证的完整 FSM。

| ProtoLens 协议 | 文件 | 范围 |
| --- | --- | --- |
| `ftp` | [ftp_minimal.txt](ftp_minimal.txt) | 已有 FTP 控制连接、认证和数据通道示例 |
| `rtsp` | [rtsp_minimal.txt](rtsp_minimal.txt) | 已有 RTSP 媒体会话示例 |
| `smtp` | [smtp_minimal.txt](smtp_minimal.txt) | 邮件事务与可选 STARTTLS |
| `dns` | [dns_minimal.txt](dns_minimal.txt) | UDP 查询、响应匹配、错误与重试 |
| `sip` | [sip_minimal.txt](sip_minimal.txt) | 注册事务和呼叫对话示例 |
| `ssh` | [ssh_minimal.txt](ssh_minimal.txt) | SSH 2 版本交换、密钥协商和认证 |
| `tls` | [tls_minimal.txt](tls_minimal.txt) | TLS 1.2 完整握手示例，不适用于 TLS 1.3 |
| `dtls` / `dtls12` | [dtls_minimal.txt](dtls_minimal.txt) | DTLS 1.2 cookie、握手 flight 和重传 |
| `dicom` | [dicom_minimal.txt](dicom_minimal.txt) | DICOM Upper Layer association、数据和释放 |
| `http` | [http_minimal.txt](http_minimal.txt) | HTTP/1.1 请求、响应和连接复用 |
| `daap-http` / `daap` | [daap_http_minimal.txt](daap_http_minimal.txt) | 基于 benchmark 固定版本源码的 DAAP 会话示例 |

各 benchmark 的 `spec_paths` 使用相对于 JSON 所在目录的路径，例如
`./specs/dns_minimal.txt`。多个 FTP 目标共享同一份模型；HTTP 文件另供通用 HTTP
适配使用，DAAP 文件同时引用它说明 HTTP 层语义。新增文件内列出了标准或源码来源。

`TRANSITION: SOURCE -- TRIGGER [guard] -> TARGET ; action=...` 表示抽象迁移。
文件内的 `SERVER_*`、超时、握手完成等事件属于响应或环境观察，不是客户端报文。
带参数绑定、加密或未实现模板的客户端事件也不能直接按名称发送，需要完整原始报文。
二进制消息使用 `raw-b64:`，具体模板支持范围见上级 [README](../README.md#protolens-协议适配)。

当前在线 FSM 构建仅将 `spec_paths` 的文件名用作查询提示，不读取这些文件正文作为规范证据。
`fsm_build.rfc_queries` 和目标源码仍决定在线研究范围；目录中的模型可供人工检查，
也可由已有 `RFCParser` 单独解析。解析成功不代表模型完整、报文可执行或目标状态已验证。
本次补齐文件不改变这一构建行为。
