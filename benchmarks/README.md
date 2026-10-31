# ProFuzzBench 目标配置

以下 13 份配置以 `ftp_fftp_openai.json` 为模板，目标路径和参数依据
`profuzzbench/subjects/<协议>/<目标>/Dockerfile`、`run.sh`、`cov_script.sh` 及
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
- `build_command` 为空，表示目标应已按 Dockerfile 完成补丁、依赖安装和 AFL 插桩构建；启用覆盖率时还需要对应的 GCC/gcov 构建。LLM 保留各文件原有的服务商与模型配置，仅修正 PureFTPD 的 `deepseek-v4.1-flasho` 拼写。模型是否可用取决于配置的 API 服务，ProFuzzBench 无法验证这一项。
- AFLNet 参数保留批量执行脚本中的目标差异，包括清理脚本、`-R`、`-W` 和 SIP 客户端端口 `-l 5061`。显式 `cmd` 是实际执行命令；多数配置的 `-t` 为 5000 ms，保留原有 Live555 的 `1000+` 和 FFTP 的默认超时。`timeout_ms` 虽然名为毫秒，但当前配置类将其定义为兼容的 `-D` 启动等待字段，现与命令中的 `-D` 数值一致（AFLNet 的 `-D` 单位是微秒），不能把它当成 `-t`。
- 所有协议均配置 `spec_paths`，使用相对于 JSON 所在目录的 `./specs/<协议>_minimal.txt`；文件索引和使用范围见 [specs/README.md](specs/README.md)。FTP 和 RTSP 保留已有模型，其余协议补齐最小状态迁移示例，另提供通用 HTTP 模型。当前程序仅将 `spec_paths` 用作文件名提示，不解析本地规范文件正文；在线研究仍使用 `fsm_build.rfc_queries`。DICOM 查询官方 DICOM 标准并允许 `dicom.nema.org`；DAAP 使用 ProtoLens 的 `daap-http` 协议名，HTTP 语义查询 RFC，DAAP 应用行为依据源码。

## 启动前准备

各实际目标已显式设置 `aflnet.cwd`，与对应 `run.sh` 的 `cd` 一致；覆盖率使用独立的 `source_coverage.cwd`。配置中的程序和配置文件参数使用绝对路径；还需完成原目标环境中的初始化：

- 通用：继承 Dockerfile 的 `WORKDIR=/home/ubuntu/experiments`、AFL 和 ASAN 环境变量，以及目标用户、目录和权限设置。原始低端口目标需要相应绑定权限。
- Live555：保留 Dockerfile 准备在 `live555/testProgs` 和 `live555-cov/testProgs` 下的测试媒体；两种实例分别在对应 `testProgs` 目录运行，源码分析仍使用整个源码树。
- Dnsmasq：保留 Dockerfile 安装的 `/etc/dnsmasq.conf`，包括端口 5353 和 `test.com` 地址配置。
- OpenSSH：按原 `run.sh` 完成首次连接初始化，并准备其构建安装生成的主机密钥和 `sshd_config`。
- OpenSSL：保留目标目录下的 `key.pem` 和 `cert.pem`。
- Kamailio：准备 PJSIP 被叫端、`StarWars3.wav` 和 `run_pjsip`；AFLNet 的 `-c` 在迭代时执行该脚本。
- DCMTK：保留两种构建的 `build/bin/ACME_STORE`、`build/bin/dcmqrscp.cfg`；JSON 已显式设置 Dockerfile 中的 `DCMDICTPATH`。AFLNet 的启动参数显式指定原配置文件。
- forked-daapd：按原 `run.sh` 启动 DBus、Avahi，并准备 Dockerfile 中的数据库目录和媒体资源。

准备完成并配置 LLM 凭据后，例如：

```bash
protolens run --config benchmarks/ftp_lightftp_openai.json
```

这些 JSON 的加载和静态参数一致性可以在没有目标二进制的环境中检查；实际服务启动及 fuzzing 仍需在对应实验环境中验证。

## 独立源码覆盖率配置

全部 JSON 均包含 `source_coverage`。路径按 Dockerfile 中实际构建名称填写：
Live555 使用 `live555-cov`，其余使用 `*-gcov`；不能把 AFL 插桩程序当成 gcov 程序。
`build_root` 必须包含 `.gcno`，并使用与构建 GCC 匹配的 `gcov`。
采集器要求覆盖率实例与 AFLNet 使用不同端口，因此在原 `cov_script.sh` 的命令基础上调整监听端口。

| 目标 | 覆盖率端口 | 退出信号 | 端口配置方式 | 默认启用 |
| --- | --- | --- | --- | --- |
| FFTP / LightFTP | 2201 | SIGUSR1 | `fftp fftp.conf 2201` | 是 |
| BFTPD | 2121 | SIGTERM | `coverage/bftpd.conf` | 否，见下文 |
| ProFTPD | 2122 | SIGTERM | `coverage/proftpd.conf` | 是 |
| PureFTPD | 2123 | SIGTERM | `-S 127.0.0.1,2123` | 否，见下文 |
| Exim | 2525 | SIGTERM | `-oX 2525`，独立 PID 文件 | 是 |
| Dnsmasq | 5354 | SIGTERM | `--conf-file=…/coverage/dnsmasq.conf` | 是 |
| Live555 | 8555 | SIGUSR1 | `testOnDemandRTSPServer 8555` | 是 |
| Kamailio | 5062 | SIGTERM | `coverage/kamailio.cfg` 中的 `listen` 和 `port` | 是 |
| OpenSSH | 2222 | SIGTERM | `-p 2222` | 是 |
| OpenSSL | 4434 | SIGTERM | `s_server … -accept 4434` | 是 |
| TinyDTLS | 20221 | SIGUSR1 | `dtls-server -p 20221` | 是 |
| DCMTK | 5159 | SIGUSR1 | `coverage/dcmqrscp.cfg` | 是，需重建带新补丁的 gcov 程序 |
| forked-daapd | 3690 | SIGUSR1 | `coverage/forked-daapd.conf` | 是 |

`coverage/` 中的六份配置复制自对应 ProFuzzBench 文件，仅调整覆盖率实例的端口、
部分数据库/日志/PID/存储路径及 Kamailio 可选导入文件的绝对路径。不要用这些文件覆盖
`/home/ubuntu/experiments` 中的 AFLNet 服务配置。Dnsmasq v2.73rc6 的配置文件会覆盖
命令行参数，单独加 `--port=5354` 无法覆盖原文件中的 `port=5353`，因此必须使用独立配置。
forked-daapd 保留 `db/` 和媒体目录，但使用独立的数据库文件，启动等待为 1 秒、回放超时为 10 秒。
OpenSSH 的两个实例均显式设置 `LD_LIBRARY_PATH=/home/ubuntu/experiments/openssl-install/lib`。

以下限制来自当前目标补丁和采集器实现，不能仅靠复制 JSON 解决：

- **BFTPD / PureFTPD**：原版 `gcov.patch` 在登录路径清除 `GCOV_PREFIX`，原 `cov_script.sh` 还配合 chroot 内目录和数据拷贝。当前采集器要求每个用例的数据写入独立的 `GCOV_PREFIX` 目录，两者不兼容。已补齐命令和路径，但默认关闭；保留重定位、处理 chroot/降权后的写入权限并验证登录后的 `.gcda` 数据后才能启用。
- **DCMTK**：原 `normal.patch` 只修改默认配置文件路径；新增的 `source_coverage.patch` 使用专用线程等待 `SIGUSR1`，调用 `__gcov_dump()` 后退出，保持 `GCOV_PREFIX` 重定位。只应用于 gcov 构建，要求 `--single-process`。JSON 已启用覆盖率并改用 `SIGUSR1`，**旧二进制必须先打补丁并重新编译**，步骤见 [DCMTK 说明](../profuzzbench/subjects/DICOM/Dcmtk/README.md#protolens-source_coverage)。独立配置指向 `dcmtk-gcov/build/bin/ACME_STORE`，避免覆盖率回放写入 AFLNet 的存储目录。
- **Kamailio**：覆盖率命令使用 gcov 版本的模块和运行目录，避开 AFLNet 的服务端口 5060、客户端端口 5061。采集器不会执行 AFLNet 的 `-c run_pjsip`，也不会重写种子中的 SIP URI；原脚本的被叫注册/完整呼叫流程不能视为已经复现。
- **清理与后台服务**：覆盖率采集器没有逐用例清理钩子，不会调用 `ftpclean` / `clean`。Exim 原脚本还会复制二进制到 `/usr/exim/bin/exim`；JSON 直接执行各构建目录中的程序，并保留 `-d` 前台调试方式，若流程触发重新执行，仍需核对安装路径。共享目录、权限、DBus、Avahi 和其他系统服务仍按原环境准备。

`rtsp_live555.json` 是离线源码模型，新增的覆盖率配置默认关闭；启用真实 Live555 应使用
`rtsp_live555_openai.json` 或 `rtsp_live555_coverage.example.json`。后者保留 `dry_run: true`，
输出目录已与 OpenAI 配置分开。FFTP 与 LightFTP 是同一目标的两份配置，不能在同一网络环境同时运行。

本次核验覆盖 JSON 加载、协议/端口一致性、运行目录、目标参数、配置文件和补丁，
并通过协议及源码覆盖率模块的回归测试。DCMTK 提供另需真实 gcov 构建的专项集成测试；
其他目标的静态检查不代表已经完成启动、登录、完整会话或覆盖率回放验证。

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
