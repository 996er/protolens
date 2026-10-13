# MonitorAgent 有效种子生成效率低下分析

本报告基于 `monitor_agent.llm.jsonl` 的 36 条 LLM 调用记录，以及当前仓库中 MonitorAgent、AFLNet 导入、路径规划、种子编码和反馈分析代码。结论先说在前面：这次不是 LLM 没有生成种子，而是生成到 AFLNet 有效保留之间的转化链路损耗很大。

## 1. 关键事实

- 日志共 36 条 `monitor_agent` LLM 对话记录，文件大小约 4.3MB。
- 35 条响应成功解析，1 条响应解析失败。失败原因是模型输出了两个拼接的 JSON 对象，触发 `JSONDecodeError: Extra data`，不是 SSL、SDK 或连接问题。
- 35 条成功响应共给出 284 个候选 seed candidate。
- 复放当前 `MonitorAgent._write_llm_breakthrough_seeds()` 写入逻辑后，可以确认至少 209 个 monitor seed 已经在后续 prompt 的 `previous_monitor_seeds` 中出现过。最后一轮还会额外写出 5 个，因此按当前逻辑预测总写入量为 214。
- AFLNet 统计中的 `paths_imported` 从 0 增长到 6。这里的 `paths_imported` 不是 MonitorAgent 写出的文件数，而是 AFLNet 通过 `save_if_interesting()` 判断为有趣并保留的导入队列项数。
- 因此，本次的粗略有效保留比例大约是 `6 / 209 = 2.9%`。精确到每个 seed 的归因还需要 `.processed`、AFLNet queue、monitor seed manifest 或 per-seed 执行回执。

从 fuzzing 统计看，14 小时并非完全没有进展：

- `execs_done`: 111477 -> 454033
- `paths_total`: 496 -> 616
- `paths_imported`: 0 -> 6
- `bitmap_cvg`: 1.23% -> 1.28%
- IPSM nodes: 24 -> 24
- IPSM edges: 237 -> 258
- 最后 21 轮左右 `bitmap_cvg` 基本卡在 1.28%，没有新增 response-state node。

## 2. 最高优先级原因：运行反馈没有真正回流到 LLM

LLM 每次拿到的 `seed_feedback` 都几乎一样：

- `seed_count = 22`
- `observed_count = 22`
- 来源都是初始语料 `queued_by_aflnet`

这说明 MonitorAgent 写入的 209 个新 seed 没有以“执行结果”的形式进入下一轮提示。代码上也能看到这一点：

- [pipeline.py](/home/ubuntu/protolens/protolens/pipeline.py:463) 只读取 `seed_manifest.json`，这是初始 corpus 的 manifest。
- [monitor_agent.py](/home/ubuntu/protolens/protolens/agents/monitor_agent.py:290) 只把 `previous_monitor_seeds` 放回 prompt。
- [monitor_agent.py](/home/ubuntu/protolens/protolens/agents/monitor_agent.py:741) 只保留最近 40 个 monitor seed 的哈希、消息和预期覆盖。
- [aflnet_feedback.py](/home/ubuntu/protolens/protolens/fuzzer/aflnet_feedback.py:103) 的 seed feedback 归因也是围绕初始 seed manifest 做的。

这导致模型只知道“我之前生成过什么”，但不知道：

- 哪些 seed 被 AFLNet 读取了。
- 哪些 seed 被执行了。
- 哪些 seed 被 `save_if_interesting()` 保留。
- 哪些 seed 只触发了 timeout、连接失败、登录失败、TLS 失败或无新覆盖。
- 哪些 message 前缀真正到达了目标状态。

结果就是模型在长时间瓶颈期里反复基于同一套静态猜测生成候选，不能从失败中收敛。

建议优先修复：

- 为每个 monitor seed 记录 per-seed receipt：`submitted`、`processed`、`executed`、`queued`、`new_edges`、`response_sequence`、`timeout`、`duration`、`failure_reason`。
- 将 `monitor_seed_manifest.json` 和 AFLNet queue/processed 结果合并进 `seed_feedback`。
- prompt 里不要只给 `previous_monitor_seeds`，要给“有效、无效、未执行”的分类样本。
- 让下一轮候选明确避开已经证明无效的 prefix、命令组合和目标状态假设。

## 3. 路径和 conflict 身份映射错误导致候选被确定性丢弃

本次 284 个候选中，有 62 个候选本身引用了不可达或不存在的 `conflict_id`。按实际写入逻辑复放，59 个在写入阶段被跳过，2 个重复被跳过，9 个因为每轮最多写 8 个而落在批次尾部，最终确认写入 209 个。

主要问题在这里：

- [conflict_detector.py](/home/ubuntu/protolens/protolens/agents/conflict_detector.py:23) 对 `divergence.impl_element` 或 `spec_element` 调用 `_state_and_transition()`。
- [conflict_detector.py](/home/ubuntu/protolens/protolens/agents/conflict_detector.py:105) 只识别包含 `--` 的标签。如果标签是 `chunk_0001__t44__46` 这种 transition ID，就会被当成 state。
- [path_planner.py](/home/ubuntu/protolens/protolens/fuzzer/path_planner.py:26) 随后把这个“伪 state”当作目标状态，找不到就标记为 unreachable。
- [monitor_agent.py](/home/ubuntu/protolens/protolens/agents/monitor_agent.py:358) 用 `{path.conflict_id: path}` 建索引，同一个 `conflict_id` 如果有多个 planned path，后面的会覆盖前面的。
- [monitor_agent.py](/home/ubuntu/protolens/protolens/agents/monitor_agent.py:364) 对不可达 path 直接跳过 seed candidate。

这里有两个实际后果：

- 一些 transition ID 被错当成 state ID，导致路径被判为不可达，候选还没进入 AFLNet 就被丢弃。
- 同一个 conflict 的可达 path 可能被后面的不可达 path 覆盖，造成 LLM 输出了看似合法的 `conflict_id`，写入阶段却被拒绝。

建议优先修复：

- 将 `state_id`、`transition_id`、`conflict_id`、`candidate_id` 分开建模，不要在字符串标签里猜。
- conflict detector 对 divergence element 做结构化解析，transition ID 必须回查 FSM，不能直接当 state。
- prompt 中只暴露可执行的 candidate id，或者在 schema 中强制 candidate 从 allowlist 里选。
- 同一个 conflict 的多条 path 不应互相覆盖，写入时应按 `candidate_id` 或可达 path 列表选择。

## 4. FTP 编码器会改写 LLM 的测试意图

MonitorAgent 让模型输出的是 message 字符串，但 `CorpusEncoder` 会把这些字符串解释成协议意图并补默认参数。FTP 里尤其明显：

- [corpus_encoder.py](/home/ubuntu/protolens/protolens/tools/corpus_encoder.py:409) 使用 `_ftp_command()` 编码 FTP message。
- [corpus_encoder.py](/home/ubuntu/protolens/protolens/tools/corpus_encoder.py:416) 给 `AUTH`、`PORT`、`RETR`、`TYPE` 等命令设置默认参数。
- [corpus_encoder.py](/home/ubuntu/protolens/protolens/tools/corpus_encoder.py:502) `_method()` 会提取第一个 token 并大写。
- [corpus_encoder.py](/home/ubuntu/protolens/protolens/tools/corpus_encoder.py:524) `_argument_text()` 会用 split/join 折叠空白和换行。

这会直接改变测试语义，例如：

- 模型想发送裸 `RETR` 测试“缺少参数”，实际会变成 `RETR protolens.txt\r\n`。
- 模型想发送裸 `PORT` 测试“缺少参数”，实际会变成 `PORT 127,0,0,1,7,138\r\n`。
- 模型想把 `NO` 和 `OP\r\n` 分片发送来测试重组，实际每个 message 都会被补成一条独立命令并追加 CRLF。

这类改写会让很多看起来合理的负向测试 seed 失去原始目的。日志中已经出现了模型尝试测试缺参、异常参数、分片命令和 TLS 前缀混合的候选，这些候选经过当前编码器后未必还能触发它们声称的分支。

建议优先修复：

- 区分 `ftp_command` 高层意图和 `raw_bytes` 原始 payload。
- 对“缺参”“错误空白”“分片发送”“二进制前缀”等候选，必须允许 raw/base64 模式。
- 编码后把实际 payload 摘要和反解结果写入 manifest，下一轮反馈给 LLM。
- 对 LLM 的 `expected_new_coverage` 和编码后的实际 payload 做一致性检查，不一致则跳过或降权。

## 5. 执行能力和候选假设不匹配

AFLNet 当前发送路径是单 TCP/UDP socket 的线性 message sequence：

- [afl-fuzz.c](/home/ubuntu/protolens/afl-fuzz.c:997) `send_over_network()` 每次建立一个连接。
- [afl-fuzz.c](/home/ubuntu/protolens/afl-fuzz.c:1080) 按 `kl_messages` 顺序发送消息并接收响应。
- [afl-fuzz.c](/home/ubuntu/protolens/afl-fuzz.c:7973) 只有 `save_if_interesting()` 判断有新覆盖时才增加 `queued_imported`。

但是日志里的候选大量围绕 FTP 的 TLS、PASV、PORT、数据通道和认证后状态：

- 至少 48 个确认写出的 monitor seed 包含 `AUTH TLS`。
- 至少 46 个确认写出的 monitor seed 在 `AUTH TLS` 后继续发送明文 FTP 命令。
- 至少 76 个包含 `PASV`。
- 至少 56 个包含 `PORT`。

这些并不一定全部无效，因为测试 TLS 握手错误、PASV 参数错误、PORT 边界本身也可能有价值。但当前 executor 没有真正升级 TLS，没有解析 PASV 并连接数据通道，也没有为 PORT 建立服务端监听。因此“成功进入加密控制通道后状态”“成功触发数据连接处理后状态”这类候选假设很可能达不到。

建议优先修复：

- 在 benchmark JSON 或 transport manifest 中显式声明 executor capability：`supports_tls_upgrade`、`supports_data_connection`、`supports_multi_connection`、`known_credentials`、`known_files`。
- LLM prompt 里暴露 capability，让模型不要生成当前 harness 无法执行的假设。
- 对复杂前缀做 isolated preflight，确认状态可达后再导入 fuzzing。
- 对 FTP 至少提供可选的 PASV/PORT 数据通道 harness，或者把这类路径降级为“错误处理测试”，不要声称能到达成功传输状态。

## 6. prompt 被大量静态噪声占用，且模板会污染协议动作

本次 36 次调用累计消耗约 1,200,851 tokens，其中 prompt token 超过 1,004,132。大量上下文每轮重复，真正新增的动态反馈很少。

尤其是 heuristic seed templates 里混入了服务端内部动作或 C 代码式事件，例如 `listen() returns 0`、`accept() returns ...`、`client thread starts...`。这些来自 path trigger：

- [path_planner.py](/home/ubuntu/protolens/protolens/fuzzer/path_planner.py:56) 直接把 transition trigger 放入 messages。
- [monitor_agent.py](/home/ubuntu/protolens/protolens/agents/monitor_agent.py:289) 又把 planned path 转成 heuristic seed templates。

好消息是，本次模型实际输出的 284 个 candidate 没有直接照抄这些内部动作作为 FTP 命令，说明模型能识别部分噪声。但这些内容仍然占据 prompt、干扰目标建模，并让模型在瓶颈期反复读同一批无效上下文。

建议优先修复：

- path trigger 分成 `client_send`、`server_event`、`internal_event`。
- 只有 `client_send` 可以进入 seed template。
- 对 FTP command 做 allowlist，同时保留 raw malformed 模式。
- prompt 中只保留与当前 stagnation frontier 相关的少量 path、最近有效 seed、最近失败 seed。

## 7. budget 策略会放大瓶颈期低效问题

当前默认每个 stagnation signature 只允许一次成功 LLM 调用：

- [config.py](/home/ubuntu/protolens/protolens/config.py:56) `max_llm_calls_per_stagnation_signature = 1`
- [monitor_agent.py](/home/ubuntu/protolens/protolens/agents/monitor_agent.py:123) 达到预算后抑制后续 LLM 调用。
- [monitor_agent.py](/home/ubuntu/protolens/protolens/agents/monitor_agent.py:207) 在写 seed 前就消耗该 signature 的 LLM 预算。
- [monitor_agent.py](/home/ubuntu/protolens/protolens/agents/monitor_agent.py:233) 只要写出了 seed，就把 `_last_improvement` 重置，即使 AFLNet 还没有证明这些 seed 带来新覆盖。

这会产生一个不理想的闭环：

- 某个 coverage signature 下只探索一种策略。
- 即使候选全被写入阶段跳过，或者写入后没有新覆盖，也可能消耗掉这轮预算。
- 只要写了 seed，就把“生成行为”当作阶段性进展，而不是把 AFLNet 的真实覆盖增长当作进展。

建议修复：

- LLM 调用预算按“有效执行结果”消耗，而不是按“请求成功”消耗。
- `stagnant_no_seed`、全 invalid、无 imported 的轮次不应永久耗尽该 signature。
- 对同一 signature 允许少量不同策略族，例如 raw malformed、valid prefix extension、negative auth path。
- `_last_improvement` 应区分“提交了候选”和“覆盖真实变化”。

## 8. 次要因素：执行吞吐和不稳定性需要测量，但不是首要根因

日志显示 `execs_per_sec` 大致在 7 到 12 左右，`stability` 约 82%，`variable_paths` 较多。这说明目标执行确实偏慢且存在不稳定路径，会降低导入 seed 被快速验证的速度。

但不要把原因简单归结为 `-D10000`。代码里：

- [afl-fuzz.c](/home/ubuntu/protolens/afl-fuzz.c:369) 默认 `server_wait_usecs = 10000`。
- [afl-fuzz.c](/home/ubuntu/protolens/afl-fuzz.c:1008) 使用 `usleep(server_wait_usecs)`。
- [afl-fuzz.c](/home/ubuntu/protolens/afl-fuzz.c:9242) `-D` 读取的也是微秒值。

所以 `-D10000` 是 10ms，不是 10 秒。以 8 exec/s 计算，单次执行约 125ms，10ms 只是其中一部分。真正耗时可能来自 cleanup、server 启动、connect retry、socket recv、目标自身状态机或 timeout，需要单独打点确认。

建议增加：

- 每个 seed 的执行耗时分解：cleanup、server_wait、connect、send、recv、target runtime。
- AFLNet 导入目录扫描、`.processed` 标记和 `save_if_interesting()` 的 per-seed 日志。
- 重复执行同一 seed 的稳定性采样。

## 9. 推荐修复顺序

1. 先修 feedback loop：把 monitor seed 的真实执行结果回流给 LLM。这会直接提升下一轮生成质量。
2. 修 `conflict_id/state/transition/candidate_id` 混用问题，避免大量候选在写入阶段确定性丢弃。
3. 修 FTP encoder：加入 raw bytes/base64 模式，并保留缺参、空白、分片和二进制 payload 的真实意图。
4. 给 prompt 加 executor capability，避免让 LLM 生成当前 AFLNet harness 无法执行的 TLS/data-channel 成功路径。
5. 重构 prompt 内容，去掉内部事件模板和重复静态上下文。
6. 调整 stagnation budget，不要让“请求成功但无有效导入”耗尽探索机会。
7. 最后再做性能调优，测量 cleanup/connect/recv/timeout 的真实占比。

最不建议的做法是只增大 `max_seed_batch` 或只换更强模型。当前损耗主要发生在反馈、路径身份、编码和执行能力之间，单纯让模型多生成候选只会放大低转化率。

