# ProFuzzBench 目标配置

以下 13 份配置以 `ftp_fftp_openai.json` 为模板，目标路径和参数依据
`profuzzbench/subjects/<协议>/<目标>/Dockerfile`、`run.sh` 及
`profuzzbench/scripts/execution/profuzzbench_exec_all.sh`。

| ProFuzzBench 目标 | 配置文件 | AFLNet 协议 | 连接 |
| --- | --- | --- | --- |
| FTP/LightFTP | [ftp_lightftp_openai.json](ftp_lightftp_openai.json) | FTP | TCP 2200 |
| FTP/BFTPD | [ftp_bftpd_openai.json](ftp_bftpd_openai.json) | FTP | TCP 21 |
| FTP/ProFTPD | [ftp_proftpd_openai.json](ftp_proftpd_openai.json) | FTP | TCP 21 |
| FTP/PureFTPD | [ftp_pureftpd_openai.json](ftp_pureftpd_openai.json) | FTP | TCP 21 |
| SMTP/Exim | [smtp_exim_openai.json](smtp_exim_openai.json) | SMTP | TCP 25 |
| DNS/Dnsmasq | [dns_dnsmasq_openai.json](dns_dnsmasq_openai.json) | DNS | UDP 5353 |
| RTSP/Live555 | [rtsp_live555_openai.json](rtsp_live555_openai.json) | RTSP | TCP 8554 |
| SIP/Kamailio | [sip_kamailio_openai.json](sip_kamailio_openai.json) | SIP | UDP 5060 |
| SSH/OpenSSH | [ssh_openssh_openai.json](ssh_openssh_openai.json) | SSH | TCP 22 |
| TLS/OpenSSL | [tls_openssl_openai.json](tls_openssl_openai.json) | TLS | TCP 4433 |
| DTLS/TinyDTLS | [dtls_tinydtls_openai.json](dtls_tinydtls_openai.json) | DTLS12 | UDP 20220 |
| DICOM/Dcmtk | [dicom_dcmtk_openai.json](dicom_dcmtk_openai.json) | DICOM | TCP 5158 |
| DAAP/forked-daapd | [daap_forked_daapd_openai.json](daap_forked_daapd_openai.json) | HTTP | TCP 3689 |

`ftp_fftp_openai.json` 保留为原始本地示例；`rtsp_live555.json` 保留为示例配置。
`rtsp_live555_openai.json` 现在指向实际 Live555 源码和程序。

## 路径和公共设置

- 配置面向按各目标 Dockerfile 准备好的独立实验环境。源码、种子、字典、服务配置及清理脚本位于 `/home/ubuntu/experiments`；该目录中的 `basic.conf`、`clean`、`in-ftp` 等文件属于当前目标，不能混用不同目标的文件。
- ProtoLens 仓库及 AFLNet 路径沿用示例中的 `/home/ubuntu/protolens`。若运行在 ProFuzzBench 容器内，需将仓库及所需工具部署到该路径，或同时修改 `aflnet.binary` 和 `aflnet.cmd[0]`。
- 每个目标使用独立的 `/home/ubuntu/experiments/runs/<协议>-<目标>-openai` 输出目录。修改路径时须同步修改 `source_root`、`run_command`、`run_dir` 及 `aflnet.cmd` 中的相关路径；JSON 中不展开 shell 环境变量。
- `build_command` 为空，表示目标应已按 Dockerfile 完成补丁、依赖安装和 AFL 插桩构建。LLM 设置沿用模板的 `openai-compatible` / `deepseek-v4-pro`。
- AFLNet 参数保留批量执行脚本中的目标差异，包括清理脚本、`-R`、`-W` 和 SIP 客户端端口 `-l 5061`。`-t` 和 `timeout_ms` 均设为该脚本默认的 5000 ms；`duration_seconds: 0` 和 `dry_run: false` 沿用模板。
- 所有协议均配置 `spec_paths`，使用相对于 JSON 所在目录的 `./specs/<协议>_minimal.txt`；文件索引和使用范围见 [specs/README.md](specs/README.md)。FTP 和 RTSP 保留已有模型，其余协议补齐最小状态迁移示例，另提供通用 HTTP 模型。当前程序仅将 `spec_paths` 用作文件名提示，不解析本地规范文件正文；在线研究仍使用 `fsm_build.rfc_queries`。DICOM 查询官方 DICOM 标准并允许 `dicom.nema.org`；DAAP 使用 ProtoLens 的 `daap-http` 协议名，HTTP 语义查询 RFC，DAAP 应用行为依据源码。

## 启动前准备

ProtoLens 从 `source_root` 启动目标。配置中的程序和配置文件参数使用绝对路径；还需完成原目标环境中的初始化：

- 通用：继承 Dockerfile 的 `WORKDIR=/home/ubuntu/experiments`、AFL 和 ASAN 环境变量，以及目标用户、目录和权限设置。原始低端口目标需要相应绑定权限。
- Live555：将 Dockerfile 准备在 `live555/testProgs` 下的测试媒体复制或链接到 `live555` 源码根目录。服务器按当前工作目录查找媒体，源码分析需要保留整个 `live555` 目录。
- Dnsmasq：保留 Dockerfile 安装的 `/etc/dnsmasq.conf`，包括端口 5353 和 `test.com` 地址配置。
- OpenSSH：按原 `run.sh` 完成首次连接初始化，并准备其构建安装生成的主机密钥和 `sshd_config`。
- OpenSSL：保留目标目录下的 `key.pem` 和 `cert.pem`。
- Kamailio：准备 PJSIP 被叫端、`StarWars3.wav` 和 `run_pjsip`；AFLNet 的 `-c` 在迭代时执行该脚本。
- DCMTK：保留 `build/bin/ACME_STORE`、`build/bin/dcmqrscp.cfg`，并设置 Dockerfile 中的 `DCMDICTPATH`。启动参数显式指定配置文件以适配源码根目录作为工作目录。
- forked-daapd：按原 `run.sh` 启动 DBus、Avahi，并准备 Dockerfile 中的数据库目录和媒体资源。

准备完成并配置 LLM 凭据后，例如：

```bash
protolens run --config benchmarks/ftp_lightftp_openai.json
```

这些 JSON 的加载和静态参数一致性可以在没有目标二进制的环境中检查；实际服务启动及 fuzzing 仍需在对应实验环境中验证。

## ProtoLens 协议适配

Python 侧现已覆盖上述配置使用的全部 10 类协议。协议注册表位于
`protolens/protocols.py`，供消息编码、反馈、校准、Monitor 提示和回放共用。
`dtls` / `dtls12` 均对应 AFLNet `DTLS12`，`daap` / `daap-http` 对应 `HTTP`。
配置中的显式 `aflnet.cmd` 保持原样，`-N` 决定 TCP/UDP，`-l` 指定的客户端端口也用于 socket harness 和路径校准。

| 协议 | 内置基础消息示例 | 校准能力 |
| --- | --- | --- |
| FTP | `USER anonymous`、`PASS password` | greeting、状态码和多行回复 |
| RTSP | `OPTIONS`、`SETUP /media`、`PLAY --session=123` | 状态码、Content-Length、Session 绑定 |
| SMTP | `EHLO localhost`、`MAIL FROM:<a@example.com>` | greeting、状态码和多行回复 |
| DAAP/HTTP | `GET /server-info`、`GET /databases` | HTTP 状态码和 Content-Length |
| SIP | `OPTIONS`、`REGISTER sip:127.0.0.1` | UDP/TCP、临时/最终响应；不自动完成认证或对话协商 |
| DNS | `QUERY test.com A`、`QUERY test.com AAAA --id=123` | UDP 响应事务 ID、RCODE 与报文完整性 |
| TLS | `CLIENT_HELLO`、`CHANGE_CIPHER_SPEC`、`CLOSE_NOTIFY` | TLS record 响应观察 |
| DTLS 1.2 | `CLIENT_HELLO --cookie=001122`、`CLOSE_NOTIFY` | UDP DTLS record 响应观察 |
| SSH | `IDENTIFICATION`、`KEXINIT`、`NEWKEYS` | identification 和明文 packet 响应观察 |
| DICOM | `A-ASSOCIATE-RQ --called-ae=ACME_STORE`、`A-RELEASE-RQ`、`A-ABORT` | Upper Layer PDU 响应观察 |

基础模板用于构造 fuzzing 起始输入，不是完整协议客户端。TLS/DTLS/SSH 的密钥协商、加密后报文，
DICOM DIMSE、SMTP DATA 正文和目标相关扩展等应使用现有抓包种子或显式的
`raw-b64:<完整 wire bytes 的 base64>`；也支持 `raw:<带转义的字节>`。
完整文本请求的换行、头部和正文会原样保留。未知二进制消息名称不会再转成带 CRLF 的伪请求。
DTLS cookie、SIP tag/认证及 SSH 会话上下文不会自动生成或绑定；负向模板（如握手前 NEWKEYS）仍可用于模糊测试。

二进制协议的校准结果 `response_observed` 仅表示收到按帧读取的响应，可能包含拒绝或 alert；
不计入 accepted prefix，不代表完成握手或进入隐藏状态。DNS 的截断响应、HTTP chunked body
等尚无完整校准 oracle 的情况返回 `inconclusive`。所有校准结果都保留 `state_verified: false`。
UDP harness 明确报告 TCP reset、half-close、TLS renegotiation 不适用。

反馈分析按 DNS section counts、TLS/DTLS record、DICOM PDU、SSH 明文包和文本消息长度切分；
不能可靠切分的尾部保持为一个原始块。较小的队列消息附带可重用的 `wire_message`，
超过 4096 字节的消息仅保留大小与摘要，原始内容仍在 queue 文件中。
SSH 加密包和 MAC 长度无法仅从字节流可靠推断，因此不承诺完整拆包。
崩溃回放区分普通 corpus 与 `replayable-crashes` 的本机 unsigned-int 长度前缀格式；
最小化后保留原格式。现有 ProFuzzBench corpus 会保留，ProtoLens 只管理自身生成的文件。

DICOM 的规范构建允许配置中列出的官方 NEMA 站点。为兼容现有工件格式，
`rfc_number` 可存放 `PS3.8` 这样的标准编号，`source_type: rfc` 继续表示规范证据。
协议提示更新会使旧的 FSM 构建缓存失效，已有工件仍保留。

实现依据：[DNS RFC 1035](https://www.rfc-editor.org/rfc/rfc1035)、
[TLS 1.2 RFC 5246](https://www.rfc-editor.org/rfc/rfc5246)、
[DTLS 1.2 RFC 6347](https://www.rfc-editor.org/rfc/rfc6347)、
[SSH RFC 4253](https://www.rfc-editor.org/rfc/rfc4253)、
[SIP RFC 3261](https://www.rfc-editor.org/rfc/rfc3261) 和
[DICOM PS3.8](https://dicom.nema.org/medical/dicom/current/output/chtml/part08/sect_9.3.2.html)。

无需 LLM 和目标程序的适配回归检查（会启动临时本地 UDP 测试服务）：

```bash
python3 -m unittest tests.test_protocol_support tests.test_path_calibration -q
```
