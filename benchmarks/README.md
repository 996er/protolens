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
- FTP 和 RTSP 复用已有 `spec_paths`；其余协议使用空列表，由 `fsm_build.rfc_queries` 提供查询。当前程序仅将 `spec_paths` 用作文件名提示，不解析本地规范文件。DICOM 查询官方 DICOM 标准并允许 `dicom.nema.org`；DAAP 使用 ProtoLens 的 `daap-http` 协议名，HTTP 语义查询 RFC，DAAP 应用行为依据源码。

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
