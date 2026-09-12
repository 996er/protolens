# ProtoLens

**Adversarial Multi-Agent State Reasoning for Deep Protocol Vulnerability Discovery**

ProtoLens 是一个面向有状态网络协议的缺陷发现系统。它把协议状态机作为一等对象，从 RFC 规范和实现代码中分别构建 FSM，利用多智能体对抗推理定位高风险状态，再把这些状态转化为可执行的、路径感知的 fuzzing 任务。

当前仓库以 AFLNet/AFL 为基础，ProtoLens 的第一阶段目标不是替换现有 fuzzing 引擎，而是在其上方增加“协议理解、状态推理、路径规划、冲突驱动测试生成”四类能力。

## 目标

## 当前实现完整性（2026-09）

当前代码已经形成 LLM-native FSM 到 AFLNet 的闭环：在线模型检索权威 RFC 并构建 SpecificationFSM，模型分块读取项目源码并构建 ImplementationFSM，模型比较两侧语义并生成 UnifiedFSM/DivergenceMap，随后执行多 Agent 推理、路径规划、seed 生成、AFLNet campaign 和动态反馈分析。

本轮完整性审查修复了以下会影响结果可信度的问题：

1. seed 改为 AFLNet 可直接按协议边界解析的原始请求流，不再错误添加 4 字节长度前缀。
2. AFLNet 二进制解析、目标参数分隔、构建命令、campaign 超时进程组清理及 `replayable-crashes`/`replayable-hangs` 收集形成闭环。
3. FSM 同边合并保留规范和实现两侧证据，并检测 `action_mismatch`。
4. 第三方兼容 LLM 支持额外 Header、完整 endpoint、本地免密服务、可选 `response_format` 和 Markdown JSON 围栏。
5. 单个 Agent 失败不会丢失整轮结果，配置快照会脱敏认证 Header，重复运行会清理旧 finding 与旧生成语料。

当前已经继续补齐的能力：

1. FSM 构建链路不再调用 `RFCParser`。SpecificationFSMBuilder 强制模型通过 Responses API `web_search` 检索 RFC Editor/IETF 最新规范、更新和废止关系，并使用严格 JSON Schema 返回结果。
2. FSM 构建链路不再调用 `StaticAnalysis`。ImplementationFSMBuilder 本地只读取、筛选和分块源码文本，所有状态、guard、action、错误路径语义均由模型恢复，并校验每条边的源码原文证据。
3. FSMMerger 不再使用规则键匹配，改由模型做语义冲突分析和合并；`transition_sources` 完整性校验禁止静默遗漏任一输入 transition。
4. TCP reset、half-close、reconnect、TLS handshake 已通过 `TransportAwareHarness` 提供显式关闭的 socket 级执行骨架；TLS renegotiation 在标准 Python TLS 栈无法真实执行时会标记 `supported=false`，不伪造成功。
5. 动态 AFLNet 输出分析、响应状态映射、闭环再规划建议、crash replay、删除式最小化和报告汇总已接入 pipeline。
6. `mutation_points` 已生成 AFLNet queue weight schedule，并在仓库根目录 `afl-fuzz.c` 中通过 `AFLNET_PROTO_SCHEDULE` 接入 power score 调整。

因此，当前结论是“研究型 MVP 已具备 LLM-native 端到端审计闭环；模型判断仍需通过证据校验和后续动态测试确认，生产级跨层 harness 和多 worker AFLNet 并行调度仍需要继续工程化”。FSM 构建阶段不提供离线规则 fallback；模型、联网或 Schema 输出失败会终止构建并保留对话审计记录。

### 核心目标

1. 从协议规范和实现代码中自动构建协议 FSM。
2. 发现规范 FSM 与实现 FSM 的分歧，并把分歧作为高优先级异常信号。
3. 使用 Attacker、Defender、Cross-Layer 三类 agent 对协议状态进行对抗性分析。
4. 将推理冲突和 FSM 分歧转换为可复现的 fuzzing 目标。
5. 复用 AFLNet 的网络 fuzzing 能力，逐步增强其状态感知调度与输入生成。

### 非目标

1. 不在 MVP 阶段实现完整的通用协议解析器。
2. 不在第一版中完全替换 AFLNet 的队列调度、覆盖率反馈和 crash 管理。
3. 不要求 LLM 直接生成最终 exploit，只要求生成可验证的状态路径、假设和测试策略。
4. 不把 agent 推理结果直接视为程序异常结论，所有高危信号都必须经过动态验证。

## 总体架构

```text
Phase 1: FSM Construction
  OpenAI Responses API + web_search (RFC Editor / IETF)
        |
        v
  Source Code Text Chunks -> LLM TransitionFacts -> EvidenceTable
        |                                      |
        v                                      v
  ImplementationFSMBuilder -> target capabilities
        |                         |
        |                         v
        |              SpecificationFSMBuilder + scoped RFC web search
        |                         |
        +-------------------------+
                    |
                    v
             LLM FSMMerger -> UnifiedFSM + DivergenceMap

Phase 2: Adversarial State Reasoning
  UnifiedFSM + DivergenceMap + Code Context
        |
        v
  DirectionGenerator
        |
        v
  AttackerAgent + DefenderAgent + CrossLayerAgent
        |
        v
  ConflictDetector -> PrioritizedConflictSet

Phase 3: State-Aware Test Synthesis
  PrioritizedConflictSet + UnifiedFSM
        |
        v
  PathPlanner -> CandidatePaths -> PathCalibrator -> Selected PlannedStatePath
        |
        v
  PathAwareFuzzer / CrossLayerFuzzer
        |
        v
  AFLNet Execution + Crash / Hang / Coverage Reports
```

## 当前代码详细执行流程

本节描述当前仓库中 `protolens` 包的真实执行顺序。所有路径均以 `ProtoLensConfig.run_dir` 为实验工作目录，除 `build_command` 构建目标外，AFLNet 的启动命令只允许来自 JSON 配置中的 `aflnet.cmd` 字段。

### 0. CLI 分发入口

程序入口是 `protolens/main.py` 中的 `main()`：

```text
main(argv)
  -> build_parser()
  -> argparse 解析子命令
  -> args.func(args)
  -> 将返回 dict 以 JSON 打印到 stdout
```

当前子命令：

1. `init`：生成初始 `config.json`。
2. `build-impl`：只分析源码，生成 TransitionFact、EvidenceTable 和 ImplementationFSM。
3. `build-spec`：读取实现能力，按限定范围检索 RFC 并生成 SpecificationFSM。
4. `merge-fsm`：读取两个已完成 FSM，生成 UnifiedFSM 和 divergence。
5. `build-fsm`：按 `build-impl -> build-spec -> merge-fsm` 恢复执行，默认复用有效 checkpoint。
6. `reason`：读取已有 FSM/divergence，运行 agent 和 conflict detector。
7. `fuzz`：读取已有 FSM/conflict，规划路径并准备或执行 AFLNet。
8. `run`：端到端串行执行 `init_run -> build_fsm -> reason -> synthesize_and_fuzz -> write_report`。

异常处理统一在 `main()` 中完成：普通模式只输出可读错误；`--debug` 会输出 traceback，并把详细日志写入 `run_dir/protolens.log`。

### 1. 配置加载与校验

所有非 `init` 子命令首先调用：

```text
ProtoLensConfig.load(config_path)
  -> json.load()
  -> ProtoLensConfig.from_dict()
  -> AFLNetConfig.from_dict()
  -> TransportHarnessConfig.from_dict()
  -> LLMConfig.from_dict()
  -> FSMBuildConfig.from_dict()
  -> ProtoLensConfig.validate()
```

配置处理规则：

1. `spec_paths`、`source_root`、`run_dir` 会相对配置文件所在目录解析为绝对路径；`spec_paths` 仅作为旧配置中的 RFC 文件名提示，不读取或解析其内容。
2. `aflnet.cmd` 可以是 shell 字符串或 JSON 字符串数组；如果第一个元素是带目录的相对路径，会相对配置文件目录解析。
3. `aflnet.dry_run=false` 时必须配置 `port` 和 `aflnet.cmd`。
4. `run_command` 只是配置快照/人工参考字段，不作为 AFLNet 启动入口。
5. `AFLNetAdapter._build_command()` 只返回 `config.aflnet.cmd`，不展开占位符、不合成命令、不从其他字段兜底。
6. FSM 构建要求在线 `llm.provider`，并要求服务实现 Responses API、Web Search 和 Structured Outputs；离线 provider 不会触发规则 fallback。
7. `fsm_build.rfc_queries` 控制 RFC 检索问题，`rfc_analysis_scope` 限定规范分析面，`target_supported_extensions_only=true` 时可选扩展必须先出现在实现 TransitionFact 的能力列表中。`allowed_rfc_domains` 限制权威来源，`max_web_search_calls` 防止模型只搜索而不输出。RFC URL 按文档身份规范化，去除搜索跟踪片段并识别 RFC Editor/IETF 的 HTML、TXT、PDF、info、errata 和 datatracker 路径。模型若引用尚未出现在搜索结果中的 RFC，系统不会重建大型 FSM，而是分批执行只打开缺失 URL 的小型定向 Web Search；结构化验证输出失败时，已完成工具调用中的来源证据仍会保留。补证后仍未验证的来源不允许进入 FSM。`source_extensions`、`ignore_directories`、`chunk_chars`、`max_file_bytes` 控制源码语料读取。

### 2. `init` 执行流程

```text
cmd_init(args)
  -> 创建 run_dir
  -> 写 run_dir/config.json
  -> 返回 {"config": ..., "run_dir": ...}
```

`init` 不会生成默认 `aflnet.cmd`。如果后续要真实启动 AFLNet，开发者必须在 JSON 的 `aflnet.cmd` 中显式写入完整命令。`init` 默认生成 `llm.provider=openai`、模型、`fsm_build`、`monitor_agent`、`transport_harness` 和 `path_calibration` 配置；`path_calibration.enabled=false`，不会自动启动目标探测。可通过 `--llm-provider`、`--llm-model`、`--rfc-query` 覆盖模型与 RFC 检索参数。

### 3. Pipeline 初始化

所有执行型子命令都会构造 `ProtoLensPipeline(config)`，初始化组件如下：

```text
ArtifactStore(run_dir)
StageCheckpointStore(run_dir/checkpoints/fsm_stages.json)
Logger(run_dir/protolens.log)
SpecificationFSMBuilder
ImplementationFSMBuilder
FSMMerger
DirectionGenerator
LLMClient.from_config(llm)（由三个 FSM 组件和三个 reasoning agent 共享）
AttackerAgent / DefenderAgent / CrossLayerAgent
ConflictDetector
PathPlanner
PathCalibrator
StateAwareTestSynthesizer
CrossLayerFuzzer
PathAwareFuzzer(AFLNetAdapter)
AFLNetDynamicAnalyzer
AFLNetStateMapper
SeedFeedbackAnalyzer
CrashReplayVerifier
ClosedLoopReplanner
TransportAwareHarness
```

### 4. 分阶段 FSM 构建与断点续跑

```text
build_fsm(force=false)
  -> build_implementation()
     -> 源码文件 SHA-256 + 配置 + 模型形成 implementation fingerprint
     -> checkpoint 有效则直接读取工件，否则生成 TransitionFact/EvidenceTable/ImplementationFSM
  -> build_specification()
     -> 从 TransitionFact 提取 message_type/trigger 能力，不传源码证据
     -> RFC 范围 + 能力 + 配置 + 模型形成 specification fingerprint
     -> checkpoint 有效则直接读取工件，否则执行限定范围的 RFC web search
  -> merge_fsms()
     -> 两侧 FSM 文件 SHA-256 + 模型形成 merge fingerprint
     -> checkpoint 有效则直接读取工件，否则做一次语义比较/合并
  -> 原子更新 checkpoints/fsm_stages.json
```

checkpoint 同时校验输入 fingerprint、应有工件集合及每个输出文件的 SHA-256。源码、构建范围、实现能力、模型配置或上游 FSM 任一变化都会使对应阶段失效；前置阶段成功重建后会删除下游 checkpoint。`--force` 忽略指定阶段 checkpoint，`build-fsm --force` 和 `run --force-fsm` 强制重建全部 FSM 阶段。失败阶段不会写完成记录，因此再次执行会从最后一个成功阶段恢复。

#### 4.1 SpecificationFSMBuilder

规范 FSM 构建只走在线模型：

```text
SpecificationFSMBuilder.build(config, implementation_capabilities)
  -> 只接收 TransitionFact 中去重后的 message_type/trigger 能力
  -> 生成默认协议查询或读取 fsm_build.rfc_queries
  -> LLMClient.responses_json(web_search=true, tool_choice=required)
  -> max_web_search_calls 限制工具调用；若搜索结束但没有 output_text，自动发起无工具 Schema 收口请求
  -> status=incomplete 且 reason=max_output_tokens 时保留原始响应：已完成 Web Search 的请求回放原始输入、搜索输出和加密推理上下文后进入无工具收口，其他请求按 2 倍提高 max_output_tokens 后重试；收口预算最低 24000，逐次倍增，上限 128000
  -> 失败的 incomplete 原始响应及 usage 会写入 findings/fsm_*.llm.jsonl，便于区分模型输出耗尽与空响应
  -> Web Search 仅允许 rfc-editor.org / datatracker.ietf.org / ietf.org
  -> 仅分析控制连接状态、认证与命令顺序、数据连接建立、TLS/安全扩展
  -> 可选扩展仅在目标实现能力列表存在对应命令/触发条件时纳入
  -> 排除文件内容、目录展示、纯注册表元数据和无关应用语义
  -> 模型解析 RFC update/obsolete 链和最新适用规范
  -> 模型输出 FSM、RFC source URL、latestness rationale、uncertainties
  -> 校验确实执行 web_search、声明 URL 出现在真实搜索 source 列表且属于允许域、每条边携带 RFC URL 证据
  -> `RFC 959 Section 4.1` 等文本引用会映射到已声明且已验证的 RFC URL；仍缺 URL 的边进入小型 Schema 修复，只能复用原 excerpt 和已验证 URL，或删除 socket/library/runtime 等非规范 transition
  -> 协议展示名称与配置 ID 做通用等价校验，例如 `FTP (File Transfer Protocol)` 归一为 `ftp`；原始标签写入 metadata.model_protocol_label，不同协议如 SFTP 仍拒绝
  -> 客户端递归校验完整 JSON Schema，再校验状态、边、initial/terminal/error state 和置信度
```

本阶段不读取本地 RFC 文本、不使用正则抽取、没有 RTSP/FTP 特例，也没有离线 fallback。输出 `ProtocolFSM` 中的每条 `StateTransition` 必须携带权威 RFC URL/章节证据，用于后续 divergence、agent 和 report 审计。

#### 4.2 ImplementationFSMBuilder

实现 FSM 构建只把源码文本交给模型分析：

```text
ImplementationFSMBuilder.build(config)
  -> 遍历 source_root，按配置过滤源码后缀和生成目录
  -> 读取文本并按 chunk_chars 切块；本地不做任何协议语义抽取
  -> 每个 chunk 调用模型，只输出 TransitionFact[]、analyzed_files 和 uncertainties
  -> chunk 输出立即校验证据；唯一的纯空白差异映射回源码原文字节并修正行号，省略号/改写/歧义证据携带 transition id 自动要求模型重生
  -> 本地把完全相同的源码证据去重到 EvidenceTable，TransitionFact 只保留 evidence_ids
  -> 所有 compact TransitionFact 只调用一次 LLM assembler，输出状态、边和 fact_ids，不传源码摘录
  -> 本地按 fact_ids 恢复内存中的证据并执行最终精确原文校验
  -> 校验协议名、FSM 结构和每条 transition 的源码证据
  -> evidence.excerpt 必须是已读取源码中的精确原文，否则构建失败
  -> ImplementationFSM 和 UnifiedFSM 同样归一到配置协议 ID，避免模型展示名称传播到后续组件
```

空白或无状态语义的 chunk 可以返回空 TransitionFact 数组，全部 chunk 合并后不允许为空。超出 `max_file_bytes` 的源码会明确报错并终止，不会跳过后伪称已分析。`implementation_evidence_table.json` 是结构化 FSM 工件中源码摘录的唯一存储位置；`implementation_transition_facts.json` 和 `impl_fsm.json` 只保存 `evidence_ids`。`merge-fsm` 在内存中解析引用后再调用 FSMMerger。自动恢复、丢弃和重试过的证据只记录位置和摘要，不在 FSM metadata 重复保存源码原文；LLM 原始结果及 rejected 状态保留在 `findings/fsm_implementation.llm.jsonl` 供调用审计。

#### 4.3 FSMMerger

合并逻辑完全由模型完成：

```text
spec_fsm + impl_fsm
  -> Responses API strict JSON Schema
  -> 语义比较 state alias / trigger / guard / action / error handling
  -> 输出 UnifiedFSM + DivergenceMap + transition_sources
  -> 程序校验每个 spec/impl transition id 都被映射
  -> 校验 unified transition id、divergence kind/severity 和 evidence
```

当前会产生：

1. `missing_transition`
2. `extra_transition`
3. `guard_mismatch`
4. `state_mismatch`
5. `action_mismatch`
6. `error_handling_mismatch`

### 5. `reason()` 执行流程

```text
reason(fsm, divergences)
  -> 清理本轮 findings/*.jsonl 和 findings/*.llm.jsonl
  -> DirectionGenerator.generate(fsm, divergences)
  -> 从 UnifiedFSM transition evidence 收集已验证的源码证据
  -> 对每个 direction 依次运行三个 agent
  -> 每个 agent 输出 ReasoningFinding
  -> 写 findings/<agent>.jsonl
  -> 写 findings/<agent>.llm.jsonl
  -> ConflictDetector.detect(divergences, findings)
  -> 写 directions.json
  -> 写 conflicts.json
```

Agent 调用顺序固定为：

```text
for direction in directions:
  AttackerAgent.analyze(context)
  DefenderAgent.analyze(context)
  CrossLayerAgent.analyze(context)
```

LLM 行为：

1. `llm.provider=offline/mock/rule-based` 时使用规则 fallback，不请求远端模型。
2. OpenAI-compatible LLM 返回空响应、坏 JSON 或 schema 不满足时，agent 会记录失败并使用规则 fallback。
3. 每个 agent 与 LLM 的 system prompt、user prompt、response、schema_name、最终状态会写入 `findings/<agent>.llm.jsonl`。
4. 单个 agent 失败不会终止整轮 pipeline；错误会写入日志，其他 agent 继续执行。

ConflictDetector 会把 FSM divergence 和 agent finding 转为 `Conflict`，并按 P0/P1/P2 与 `risk_score` 排序。

### 6. `synthesize_and_fuzz()` 执行流程

```text
synthesize_and_fuzz(fsm, conflicts)
  -> PathPlanner.plan(fsm, conflicts)
  -> 写 candidate_paths.json (图上候选，无执行证明)
  -> PathCalibrator.calibrate(config, candidates)
  -> 写 path_calibration.json、calibrated_paths.json
  -> PathCalibrator.select(candidates)，按响应结果选择每个 conflict 的路径
  -> CrossLayerFuzzer.synthesize_interleavings(conflicts)
  -> CrossLayerFuzzer.transport_harness_manifest(planned_paths)
  -> 立即写 planned_paths.json
  -> 立即写 transport_harness_manifest.json
  -> StateAwareTestSynthesizer 将每条选中的候选路径扩展为 seed family
  -> 立即写 seed_intents.json
  -> PathAwareFuzzer.prepare(config, planned_paths)
  -> 写 prepared/dry-run/error 快照:
       fuzz_result.json
       dynamic_analysis.json
       state_mapping.json
       seed_feedback.json
       crash_replay.json
       replanning_plan.json
       transport_harness_result.json
  -> prepared 时调用 PathAwareFuzzer.execute(...)
  -> AFLNet running 回调中周期性刷新:
       fuzz_result.json
       dynamic_analysis.json
       state_mapping.json
       seed_feedback.json
       crash_replay.json(status=pending)
       replanning_plan.json(status=pending)
       transport_harness_result.json(status=pending)
  -> AFLNet executed/timed-out/interrupted/error 后写最终快照:
       AFLNetDynamicAnalyzer.analyze(fuzz_result)
       AFLNetStateMapper.map(dynamic_analysis, planned_paths)
       SeedFeedbackAnalyzer.analyze(dynamic_analysis, seed_manifest)
       CrashReplayVerifier.verify(config, fuzz_result)
       ClosedLoopReplanner.plan(dynamic_analysis, planned_paths, conflicts, seed_feedback)
       TransportAwareHarness.execute(config, transport_manifest)
```

该阶段不会等 AFLNet campaign 完全结束后才第一次写 JSON。`duration_seconds=0` 表示 AFLNet 按用户配置持续运行，但 `planned_paths.json`、`seed_intents.json`、`seed_manifest.json`、`dynamic_analysis.json`、`state_mapping.json`、`seed_feedback.json`、`crash_replay.json`、`replanning_plan.json`、`transport_harness_manifest.json`、`transport_harness_result.json` 会在启动前或 running 回调中持续存在。未完成 campaign 的 replay/replan/transport 工件必须显式标记 `status=pending`，不能伪装为最终确认结果。

#### 6.1 PathPlanner

`PathPlanner` 把 unified FSM 当作候选生成器，从 `initial_state` 做有界 BFS，生成到 conflict state 的多个前缀，再附加争议 transition。默认每个 conflict 最多 3 条，前缀最多 16 条边，最多 2000 个搜索节点；同一候选中每条边最多访问一次，允许自环，避免无限循环。它不会求解自然语言 guard，也不会把图上可达当成执行成功。

```text
Conflict
  -> states: START -> ... -> conflict.state
  -> messages: transition.trigger 序列
  -> required_guards: 路径 guard
  -> mutation_points: 靠近冲突 transition 的消息下标
```

找不到路径时，路径会被标记为 `reachable=false`，表示本次有界搜索未找到候选，不证明实现中绝对不可达；这类记录仍带稳定 `candidate_id`，并标记 `calibration.status=not_executable`，方便审计。`reachable=true` 只保留旧接口的图上候选含义。候选包含内容派生的 `candidate_id`、有序 `transition_ids` 和 `calibration`；`candidate_id` 同时由状态、消息、guard 和 conflict 派生。

#### 6.1.0 执行校准与路径选择

开启 `path_calibration.enabled` 后，`synthesize_and_fuzz()` 在准备 AFLNet corpus 前进行校准。目标必须已能通过 `aflnet.cmd` 中 `--` 后的命令独立启动。校准器沿用 `source_root`、`host`、`port`，先运行现有 `build_command`，然后对每条候选启动独立目标进程，在同一 TCP 连接中依次发送 `CorpusEncoder` 生成的实际消息。每条候选结束后关闭连接、终止并回收所启动的目标进程组，再进行下一条候选。AFLNet 本身仍只由 JSON 中 `aflnet.cmd` 启动，没有新增命令入口。

该模式仅支持本机回环地址，且要求目标端口开始时无人监听；发现已有 listener 会记录 `inconclusive`，不会向其发送候选协议消息。每次进程重启不等于文件系统、数据库等外部状态重置，实验环境应为可重复的测试实例。校准探测可能改变目标的外部数据，不能将其描述为无副作用的静态检查。

响应 oracle 支持 RTSP/HTTP 状态行、header 和 Content-Length body，以及 FTP/SMTP greeting、多行响应。TCP 分片、截断、连接关闭、响应大小上限和超时都会被处理。FTP/SMTP 的 2xx/3xx、RTSP/HTTP 的 2xx 计为该请求的正向响应；例如 FTP 331 仅表示 USER 得到了继续输入口令的响应，不能证明已认证。1xx、需要额外协议协商、transfer-encoding 等本轮未支持的情况保持 `inconclusive`。空响应不能当作成功。

| calibration.status | 含义 |
| --- | --- |
| `candidate` | 未执行：禁用、dry-run、预算耗尽或不支持的执行配置 |
| `response_accepted` | 这一条具体编码序列的每个请求均得到正向响应 |
| `rejected` | 收到 4xx/5xx 等拒绝响应，停止该候选并保存拒绝位置 |
| `inconclusive` | 启动失败、端口占用、超时、断连、解析不完整或不支持的响应 |
| `not_executable` | 没有可发送的候选消息或图搜索没有得到候选 |

每条结果记录 `accepted_prefix_length`、逐消息 `response_code`、请求 SHA256、消息和 transition 下标；拒绝时记录 `failure_index`。不保存完整原始响应或请求内容到校准日志。所有结果都保留 `state_verified=false`：正向响应不证明到达 LLM 命名的内部状态，也不证明新增覆盖率。全局 IPSM 标签或 queue 文件名不参与这里的执行校准。

选择顺序为：完整正向响应的候选优先，其次成功响应前缀更长的候选，再次消息数更少的候选。每个 conflict 选一条供现有 synthesis 消费，所有替代候选及失败证据保留。没有成功候选时继续保留探索路径，不把单次拒绝解释为 FSM transition 永远不可达，不删除原始 FSM。负向变体仍可能产生拒绝响应，基线的校准结果不自动继承为变体的成功证明。

工件链路：`candidate_paths.json` 保存探测前候选；`path_calibration.json` 保存结果和选中的 ID；`calibrated_paths.json` 保存所有附带结果的候选；`planned_paths.json` 保存实际交给 synthesis 的路径及跨层路径；`seed_intents.json` 和 `seed_manifest.json` 通过 `source_candidate_id` 关联来源；`state_mapping.json` 同时保留选中路径的校准结果。每轮重新执行，不复用旧环境下的正向响应证明。

在现有配置中增加以下字段，并设置现有 `aflnet.dry_run=false`：

```json
{
  "path_calibration": {
    "enabled": true,
    "max_candidates": 3,
    "max_depth": 16,
    "max_expansions": 2000,
    "max_probes": 30,
    "startup_seconds": 3.0,
    "timeout_seconds": 2.0
  }
}
```

```bash
python3 -m protolens.main fuzz --config /absolute/path/to/config.json
python3 -m unittest tests.test_path_calibration
```

默认 `enabled=false`，避免现有实验自动增加目标执行；此时仍生成多候选并显式保留未验证状态。`dry_run=true` 无论校准开关如何都不会启动探测。总探测数由 `max_probes` 限制，超出预算的候选保持未验证。本轮使用现有编码器，因此动态 Session、真实凭据、数据连接等仍可能导致拒绝或未决；校准会如实暴露这些输入实现限制，并不会自动修复这些前置条件。还未提供覆盖率插桩 oracle，因此论文应报告“响应校准的候选选择”，不能宣称“已证明内部 FSM 状态或覆盖率提升”。

#### 6.1.1 StateAwareTestSynthesizer

`PathPlanner` 负责生成候选，`PathCalibrator` 用执行结果选择路径；`StateAwareTestSynthesizer` 将选中路径扩展成可审计的 seed family。当前每条候选 path 会按协议和 guard 生成以下类型的 `SeedIntent`：

1. `baseline_valid_prefix`：为兼容保留的变体名称，保持选中路径作为对照 seed；是否收到正向响应以校准结果为准，不能从名称推断有效性。
2. `direct_divergent_trigger`：从 conflict transition 中解析争议触发命令，尽早探测实现是否接受。
3. `missing_guard_material`：移除或省略 session/auth/transport/data-connection 等 guard 材料。
4. `stale_session_value`：替换陈旧或错误的 session/auth 材料。
5. `malformed_guard_field`：在 guard 相关字段上生成畸形值。
6. `wrong_message_order`：把边界命令移到前置条件之前。
7. `duplicate_boundary_message`：重复 mutation point 附近的命令，测试幂等和状态复用。
8. `recovery_after_error`：先发送错误边界命令，再发送有效前缀，测试 parser/state recovery。

输出 `seed_intents.json`，每个条目包含 `seed_id`、`conflict_id`、`family_id`、`variant`、`objective`、`messages`、`mutation_points`、`required_guards`、`expected_feedback` 和 `priority`。这些字段会继续进入 corpus manifest、queue 权重和 feedback 归因，避免 FSM/agent 语义在最后被压缩成几条重复命令序列。

#### 6.2 CrossLayerFuzzer

`CrossLayerFuzzer` 针对 `cross_layer_contamination` 生成跨层意图路径，例如 reset、half-close、TLS renegotiation 等。普通 AFLNet seed 无法表达的路径会标记：

```text
reachable=false
reason="requires a transport-aware harness; plain AFLNet corpus cannot encode connection reset"
```

这些路径不会进入普通 AFLNet seed corpus，但会进入 `transport_harness_manifest.json`。

#### 6.3 PathAwareFuzzer 与 AFLNetAdapter

`PathAwareFuzzer.run()` 保留为兼容入口，内部仍调用 `AFLNetAdapter.prepare_and_run()`；pipeline 使用 `prepare()` 与 `execute()` 分阶段落盘：

```text
prepare(config, planned_paths)
  -> command = _build_command(config)
  -> 从 command 中解析 -i、-o、可选 -x
  -> 将 seed_intents 编码并按 payload SHA-256 去重后写入 -i 指向的真实目录
  -> 写 seed_manifest.json，记录 seed_id / variant / objective / byte_ranges / payload_sha256 / priority
  -> 将 dictionary 写入 -x 指向的真实文件；无 -x 时仅写 run_dir 下审计字典
  -> 按 seed 维度写 aflnet_queue_weights.json/tsv 到 run_dir
  -> dry_run=true: 返回 FuzzResult(mode="dry-run")
  -> live 且缺少 -i/-o: 返回 FuzzResult(mode="error")
  -> live 且 binary 可解析: 返回 FuzzResult(mode="prepared")

execute(config, prepared)
  -> 如存在 build_command，先执行 build_command
  -> subprocess.Popen(command, env={"AFLNET_PROTO_SCHEDULE": ...})
  -> 立即触发 running 进度回调，包含 process_id/started_at
  -> duration_seconds=0: 不设置等待截止时间，持续刷新 running 快照
  -> duration_seconds>0: 超时后清理进程组并返回 timed-out
  -> Ctrl-C/KeyboardInterrupt: 清理进程组并返回 interrupted
  -> 收集 replayable-crashes/replayable-hangs/crashes/hangs
```

旧版本曾把 seed 固定写入 `run_dir/corpus`，但 AFLNet 实际消费的是 `aflnet.cmd -i` 指定目录。当前实现以 `aflnet.cmd` 为唯一真实来源：

```text
aflnet.cmd = [
  "/path/to/afl-fuzz",
  "-i", "/real/input/corpus",
  "-o", "/real/output",
  "-x", "/real/protocol.dict",
  "-N", "tcp://127.0.0.1/2121",
  "-P", "FTP",
  "--",
  "/path/to/server"
]

ProtoLens corpus_dir      = /real/input/corpus
ProtoLens output_dir      = /real/output
ProtoLens dictionary_path = /real/protocol.dict
```

关键约束：

1. `_build_command()` 只读取 `config.aflnet.cmd`。
2. ProtoLens 不展开占位符、不合成 AFLNet 命令、不从 `binary`、`run_command`、`extra_args` 或其它字段补 AFLNet 参数。
3. JSON 中 `aflnet.cmd` 必须自己写好 `-i`、`-o`、`-N`、`-P`、`-D`、`-x`、目标程序和 `--` 分隔；live 模式缺少 `-i/-o` 会结构化报错。
4. 外部 `-i` 目录可能已有用户 seed，ProtoLens 只通过 `aflnet_corpus_manifest.json` 清理上一次自己生成的 seed，不删除用户文件。
5. 外部 `-x` 字典会保留已有 token，只追加或更新 `protolens_tok_*`。
6. ProtoLens 只额外设置环境变量 `AFLNET_PROTO_SCHEDULE` 和 `AFLNET_PROTOLENS_IMPORT_DIR`。前者用于仓库内 patch 过的 `afl-fuzz` 读取 queue weight TSV，后者用于运行时监控 agent 注入新 seed；二者都不改变 `aflnet.cmd`。

#### 6.4 动态反馈与闭环工件

`AFLNetDynamicAnalyzer` 读取 AFLNet 输出目录：

```text
fuzzer_stats
plot_data
ipsm.dot
queue/
replayable-crashes/ 或 crashes/
replayable-hangs/ 或 hangs/
```

输出 `dynamic_analysis.json`，包含 stats、plot 最新行、IPSM 节点/边、queue/crash/hang 计数和 health signals。

`AFLNetStateMapper` 使用 `ipsm.dot` 标签和 queue 文件名，把 planned path 映射为：

```text
observed | unobserved
matched_states
queue_files
```

没有证据时保持 `unobserved`，不编造覆盖。

`ClosedLoopReplanner` 根据 crash、无 stats、无 IPSM edge、execs/sec 等信号生成 `replanning_plan.json`。下一轮执行 `fuzz`/端到端任务时，`AFLNetAdapter.prepare()` 会读取同一 `run_dir/replanning_plan.json`，`CorpusEncoder.write_seed_queue_schedule()` 将 `next_round_seed_priorities` 合并进 `aflnet_queue_weights.json/tsv`。因此 replan 不再只是建议工件，而是下一轮 corpus schedule 的真实输入；运行中的 `afl-fuzz` 仍按启动时加载的 schedule 工作，新的权重会在下一轮 campaign 生效。

`SeedFeedbackAnalyzer` 读取 `seed_manifest.json` 和 AFLNet 动态输出，生成 `seed_feedback.json`。当前格式为 `protolens.seed_feedback.v2`，归因只使用 AFL/AFLNet 文件名中的精确关系：

```text
queue/id:000001,orig:<seed_file>        -> 物理 seed 的 direct queue ID
queue/id:000010,src:000001,...          -> 继承 src queue 的 root seed IDs
crashes/id:000020,src:000010,...        -> 通过 src queue ID 归因到 root seed IDs
hangs/id:000021,src:000001+000002,...   -> splice 父队列的多个 root seed IDs
```

`seed_feedback.json` 会输出每个 seed 的 `queue_ids`、`direct_queue_ids`、`derived_queue_ids`、`queue_matches`、`crash_matches`、`hang_matches` 和 `attribution_basis=exact_orig_or_queue_src_lineage`。共享 `conflict_id`、共享 family 或字符串前缀不会再导致串归因。

IPSM 状态标签是 campaign-global observation，不是 per-seed execution proof。`global_state_observation` 单独记录全局 `node_labels`/`edge_pairs`；每个 seed 只保留 `global_state_overlap` 作为审计辅助。未出现精确 queue/crash/hang lineage 的 seed 即使状态名出现在 IPSM 中，也保持 `status=unobserved`，不会被标记为 `state_observed`。

`ClosedLoopReplanner` 现在会把 `seed_feedback` 纳入下一轮调度，输出 `seed_actions` 与 `next_round_seed_priorities`。被 queue/crash/hang 精确归因的 variant 会建议扩展；多次未观察到的 variant 会建议降权或抑制。状态标签 overlap 只作为全局上下文，不参与 seed observed 计数。

#### 6.5 MonitorAgent 运行时覆盖率闭环

`MonitorAgent` 在 AFLNet running 回调中周期性工作：

```text
AFLNetDynamicAnalyzer.analyze(fuzz_result)
  -> MonitorAgent.observe(dynamic_analysis, planned_paths, conflicts)
  -> 比较 paths_total / last_path / bitmap_cvg / ipsm_nodes / ipsm_edges / queue_count / crash_count / hang_count
  -> 覆盖率签名在 stagnation_seconds 内无变化且满足执行数阈值时，调用 LLM 做瓶颈分析
  -> LLM 按 protolens_monitor_seed_candidates JSON Schema 返回 bottleneck_summary 和 seed_candidates
  -> ProtoLens 校验 conflict_id、client message 序列、AFLNet seed 可表达性
  -> 对 message 序列 canonical key 和 encoder 生成后的 payload SHA-256 做去重
  -> 由未重复的 LLM message 序列 + protocol encoder 生成 breakthrough seed
  -> 写入 run_dir/monitor_import_queue/
  -> 记录 monitor_seed_manifest.json、findings/monitor_agent.jsonl、findings/monitor_agent.llm.jsonl 与 monitor_agent_report.json
```

监控 agent 不伪造覆盖增长。它只根据真实 `fuzzer_stats`、`plot_data`、`ipsm.dot` 和 queue 目录判断瓶颈；停滞后必须由 LLM 输出结构化瓶颈分析和候选 seed。ProtoLens 不把候选 seed 直接标记为新覆盖，只把它编码为普通 AFLNet 原始协议请求流，并保留 guard、mutation point、conflict、LLM rationale、expected_new_coverage 等审计信息。若 LLM 离线或返回无效 JSON/Schema，状态会记录为 `llm_failed`，不会用规则 seed 冒充模型结果。

MonitorAgent 的 LLM 上下文现在包含压缩后的 `seed_feedback`：已观察/未观察 seed 样例、variant 汇总、conflict 汇总和历史 monitor seed hash。模型应基于这些反馈生成突破性 seed，避免重复输出已经被初始 corpus 或历史 monitor 尝试过的 payload。

为了避免同一瓶颈反复消耗模型费用并写入完全相同的 seed，`MonitorAgent` 会维护 `run_dir/monitor_seed_manifest.json`。该 manifest 保存历史 monitor seed 的 canonical key、payload SHA-256、每个 coverage signature 的成功 LLM 调用计数、失败计数和 retry-after 时间。启动或重启后，monitor 会加载 manifest，并扫描 `monitor_import_queue/` 中已有的 `src:protolens_monitor` seed，把历史 payload hash 纳入去重集合。

默认 `monitor_agent.max_llm_calls_per_stagnation_signature=1` 只限制成功分析次数。LLM 临时失败不会消耗成功预算，而是写入 `coverage_llm_failures` 并按 `monitor_agent.llm_failure_backoff_seconds` 指数退避；退避窗口内返回 `stagnant_llm_backoff`，失败超过 `monitor_agent.max_llm_failures_per_stagnation_signature` 后返回 `stagnant_llm_failure_suppressed`。如果模型返回与历史相同的 message 序列或最终 payload，则候选会进入 `skipped_candidates`，原因是 `duplicate_monitor_seed`。

#### 6.6 Seed 参数与 Intent 审计关系

`CorpusEncoder` 不再把模型给出的具体参数压成固定模板。FTP、SMTP、HTTP/DAAP-HTTP、RTSP encoder 会保留 message 中的目标字段和参数，例如：

```text
CWD /one      -> CWD /one\r\n
CWD /two      -> CWD /two\r\n
MAIL FROM:<a@example.com> -> MAIL FROM:<a@example.com>\r\n
GET /server-info --host=127.0.0.1 -> GET /server-info HTTP/1.1
PLAY /media --session=ABC123 -> Session: ABC123
SETUP /media --transport=RTP/AVP/TCP;unicast;interleaved=2-3
```

对于内容去重，`seed_manifest.v2` 将一个物理 seed 关联到多个 logical intent：保留的 entry 含 `coalesced_intents`，重复 payload 的 intent 会在 `skipped` 中记录 `physical_seed_id` 与 `physical_seed_file`。这样 corpus 不重复写相同 payload，但 candidate、variant、objective、mutation point、expected feedback 的审计关系不会丢失。

响应绑定已接入 `PathCalibrator` 的真实执行器。校准时 `_ResponseReader` 会记录 RTSP/HTTP 响应头；RTSP `SETUP` 等响应中的 `Session` 会提取到 `response_bindings`，并在后续 `PLAY`、`PAUSE`、`TEARDOWN`、`GET_PARAMETER` 消息没有显式 `--session=`、`--omit-session`、`--stale-session` 或 malformed guard 指令时自动追加真实 `--session=<value>`。每个 probe event 会记录 `message`、`bound_message`、`response_headers` 和 `bindings_after_response`，后续 synthesis 使用校准后的 `path.messages` 保留成功前缀中的真实会话值。

为了让运行中的 AFLNet 立即消费这些 seed，仓库根目录 `afl-fuzz.c` 增加了 `AFLNET_PROTOLENS_IMPORT_DIR` 导入器。AFLNet 主循环会扫描该目录，执行每个未处理 seed，并且只有 `save_if_interesting()` 观察到真实新覆盖、crash 或 hang 时才加入 AFL 队列。成功导入的 queue entry 会设置更高 `handicap` 并跳到队尾优先 fuzz；未产生新覆盖的 seed 只会写 `.processed` 标记，不会被当成有效覆盖成果。

#### 6.6 Crash replay 与最小化

`CrashReplayVerifier`：

```text
查找 replayable-crashes/ 或 crashes/
  -> 解析 aflnet.cmd 中 -- 后面的 target command
  -> 查找 aflnet-replay
  -> 启动 target command
  -> 执行 aflnet-replay seed PROTOCOL port timeout
  -> 观察 target 是否非零退出
  -> confirmed=true 时做 bounded deletion minimization
```

确认标准是 replay 后目标进程出现可观察的非零退出。无法确认时不会把 crash 标记成已验证。

#### 6.7 TransportAwareHarness

`TransportAwareHarness` 默认关闭：

```json
"transport_harness": {
  "enabled": false,
  "timeout_seconds": 3.0,
  "use_tls": false,
  "verify_tls": false,
  "max_actions": 20
}
```

开启后，它会读取 `transport_harness_manifest.json` 中普通 AFLNet seed 无法表达的动作，并通过 socket 执行：

1. TCP connect。
2. 协议消息 send。
3. TCP half-close。
4. TCP reset。
5. reconnect。
6. TLS handshake。

TLS renegotiation 或 TLS socket 上无法强制 TCP RST 的场景会在 `transport_harness_result.json` 中标记 `supported=false` 和具体原因。

### 7. `write_report()` 执行流程

```text
write_report(fsm, divergences, conflicts, planned_paths, fuzz_result)
  -> 汇总协议、target、FSM、divergence、conflict、fuzz mode
  -> 输出 Top Conflicts
  -> 输出 Planned Paths，包括 candidate_id、calibration.status、accepted_prefix_length
  -> 输出 AFLNet Command
  -> 读取 path_calibration.json
  -> 读取 dynamic_analysis.json
  -> 读取 state_mapping.json
  -> 读取 seed_feedback.json
  -> 读取 crash_replay.json
  -> 读取 replanning_plan.json
  -> 读取 transport_harness_result.json
  -> 读取 monitor_agent_report.json
  -> 写 report.md
```

报告只汇总已有 artifact；如果某个动态工件不存在，不会生成假数据。

### 8. 子命令之间的文件依赖

分步执行时，命令依赖关系如下：

```text
init
  -> config.json

build-impl --config config.json
  -> implementation_transition_facts.json
  -> implementation_evidence_table.json
  -> implementation_source_manifest.json
  -> impl_fsm.json

build-spec --config config.json
  -> 读取 implementation_transition_facts.json
  -> spec_fsm.json

merge-fsm --config config.json
  -> 读取 spec_fsm.json / impl_fsm.json / implementation_evidence_table.json
  -> unified_fsm.json
  -> divergences.json

build-fsm --config config.json
  -> 按上述三个阶段执行或命中 checkpoint 后跳过

reason --config config.json
  -> 读取 unified_fsm.json
  -> 读取 divergences.json
  -> directions.json
  -> findings/*.jsonl
  -> findings/*.llm.jsonl
  -> conflicts.json

fuzz --config config.json
  -> 读取 unified_fsm.json
  -> 读取 conflicts.json
  -> 读取 divergences.json
  -> candidate_paths.json
  -> path_calibration.json
  -> calibrated_paths.json
  -> planned_paths.json
  -> seed_intents.json
  -> corpus/
  -> seed_manifest.json
  -> dictionaries/
  -> aflnet_queue_weights.json
  -> aflnet_queue_weights.tsv
  -> fuzz_result.json
  -> dynamic_analysis.json
  -> state_mapping.json
  -> seed_feedback.json
  -> crash_replay.json
  -> replanning_plan.json
  -> transport_harness_manifest.json
  -> transport_harness_result.json
  -> monitor_agent_report.json
  -> report.md
```

`build-impl`、`build-spec`、`merge-fsm` 都支持 `--force`；`build-fsm` 默认恢复全部依赖并可用 `--force` 重建。`reason` 和 `fuzz` 支持通过 `--fsm`、`--divergences`、`--conflicts` 指定替代 artifact 路径，便于复用或人工编辑中间结果。

## 三个核心创新点

### 1. Protocol State Machine as First-Class Object, PSMCO

传统 fuzzing 往往把协议状态当作隐含副产物。ProtoLens 将 FSM 显式建模为核心中间表示：

```text
ProtocolFSM
  states
  transitions
  messages
  guards
  actions
  error_states
  terminal_states
  evidence
```

FSM 的每个节点和边都保留证据来源，包括在线检索到的 RFC 章节、模型引用且经原文校验的源码位置、agent 推理片段和动态执行观察。

### 2. Adversarial State Reasoning, ASR

ProtoLens 使用角色分离的 agent 进行状态级安全推理：

| Agent | 关注点 | 典型问题 | 输出 |
|------|--------|----------|------|
| AttackerAgent | 可利用性 | 如何绕过 guard、污染状态、触发未定义路径？ | 攻击假设、前置条件、候选输入 |
| DefenderAgent | 防护与约束 | 代码中有哪些检查、状态约束、重置逻辑？ | 安全评估、防护证据、风险反驳 |
| CrossLayerAgent | 跨层交互 | TLS、HTTP、RTSP、认证层之间是否共享或污染状态？ | 跨层路径、污染点、同步异常 |

当 AttackerAgent 高置信度认为某状态可利用，而 DefenderAgent 高置信度认为该状态受保护时，这种“推理冲突”会被视为需要动态验证的高价值目标。

### 3. Cross-Layer State Contamination Testing, CLSCT

很多真实协议异常来自层间状态不同步。例如：

1. TLS renegotiation 改变底层连接安全属性，但上层 HTTP parser 沿用旧状态。
2. RTSP session 状态变化后，RTP/RTCP 资源仍然可被旧 token 访问。
3. 认证层失败后，业务层请求处理器仍保留部分权限上下文。

ProtoLens 将这些跨层状态污染建模为独立冲突类型，并优先交给 CrossLayerFuzzer 生成交错序列。

## 项目结构

目标 Python 包结构：

```text
protolens/
├── __init__.py
├── config.py
├── pipeline.py
├── main.py
│
├── fsm/
│   ├── fsm_model.py
│   ├── llm_support.py
│   ├── spec_fsm_builder.py
│   ├── impl_fsm_builder.py
│   └── fsm_merger.py
│
├── agents/
│   ├── base_agent.py
│   ├── direction_agent.py
│   ├── attacker_agent.py
│   ├── defender_agent.py
│   ├── cross_layer_agent.py
│   └── conflict_detector.py
│
├── fuzzer/
│   ├── path_planner.py
│   ├── path_aware_fuzzer.py
│   ├── cross_layer_fuzzer.py
│   ├── aflnet_adapter.py
│   ├── aflnet_feedback.py
│   └── transport_harness.py
│
├── tools/
│   ├── rfc_parser.py        # 兼容保留，FSM pipeline 不调用
│   ├── static_analysis.py   # 兼容保留，FSM pipeline 不调用
│   └── corpus_encoder.py
│
├── utils/
│   ├── llm_client.py
│   ├── logger.py
│   └── artifact_store.py
│
└── benchmarks/
    ├── rtsp_live555.json
    ├── ftp_lightftp.json
    └── tls_http.json
```

现有 AFLNet 代码保留在仓库根目录。ProtoLens 通过 `fuzzer/aflnet_adapter.py` 调用 AFLNet，而不是把 Python 逻辑混入 C fuzzing 主循环。

## 核心数据模型

### ProtocolFSM

```python
@dataclass
class ProtocolFSM:
    protocol: str
    version: str | None
    states: dict[str, State]
    transitions: list[StateTransition]
    initial_state: str
    terminal_states: set[str]
    error_states: set[str]
    metadata: dict[str, Any]
```

### StateTransition

```python
@dataclass
class StateTransition:
    source: str
    target: str
    trigger: str
    message_type: str | None
    guard: str | None
    action: str | None
    error_handling: str | None
    evidence: list[Evidence]
    confidence: float
```

### Divergence

```python
@dataclass
class Divergence:
    kind: Literal[
        "missing_transition",
        "extra_transition",
        "guard_mismatch",
        "state_mismatch",
        "action_mismatch",
        "error_handling_mismatch",
    ]
    spec_element: str | None
    impl_element: str | None
    severity: Literal["P0", "P1", "P2"]
    rationale: str
    evidence: list[Evidence]
```

### ReasoningFinding

```python
@dataclass
class ReasoningFinding:
    agent: Literal["attacker", "defender", "cross_layer"]
    state: str
    transition: str | None
    claim: str
    confidence: float
    preconditions: list[str]
    suggested_tests: list[str]
    evidence: list[Evidence]
```

### Conflict

```python
@dataclass
class Conflict:
    kind: Literal[
        "asr_conflict",
        "fsm_divergence",
        "cross_layer_contamination",
        "unvalidated_hypothesis",
    ]
    priority: Literal["P0", "P1", "P2"]
    state: str
    transition: str | None
    description: str
    expected_path: list[str]
    fuzzing_strategy: str
    source_findings: list[str]
```

## Phase 1: FSM 构建

### SpecificationFSMBuilder

输入：

1. 协议名和 `fsm_build.rfc_queries`。
2. 当前 UTC 日期和 RFC/IETF 权威域名白名单。
3. `rfc_analysis_scope` 和从实现 TransitionFact 提取的紧凑能力列表。

处理流程：

1. 通过 Responses API 强制调用 Web Search，检索最新适用 RFC 及 update/obsolete 关系。
2. LLM 只在配置范围内阅读检索结果；可选扩展还必须由目标实现能力列表证明支持。
3. Structured Outputs 强制结果满足 SpecificationFSM JSON Schema。
4. Builder 校验 Web Search 调用、权威 URL、RFC 边证据和 FSM 引用完整性。
5. 输出 `spec_fsm.json` 和 `findings/fsm_specification.llm.jsonl`。

输出：

1. 理论 FSM。
2. 每条边对应的 RFC 章节证据。
3. 低置信度状态和待确认 guard 列表。

### ImplementationFSMBuilder

输入：

1. 目标服务源码。
2. 可选 entrypoint 相对路径和源码读取/分块配置。

处理流程：

1. 本地遍历、读取、分块源码，不执行正则、AST 或启发式协议语义抽取。
2. LLM 对每个源码 chunk 分析网络入口、parser、state variable、dispatch、guard、side effect、error return，只返回 TransitionFact。
3. Builder 验证证据原文后建立去重 EvidenceTable，facts 和后续 assembler 只传递 evidence ID。
4. 所有 compact facts 进入一次 LLM FSM assembler，处理跨文件调用、状态别名并返回 fact 覆盖映射。
5. Builder 验证每个 fact 都被覆盖，并验证每条最终实现边至少有一段可在项目源码中精确找到的证据原文。
6. 输出 `impl_fsm.json`、`implementation_transition_facts.json`、`implementation_evidence_table.json`、source manifest 和对话审计文件。

输出：

1. 实现 FSM。
2. 状态变量和源码位置映射。
3. 解析失败、状态重置、资源释放相关路径。

### FSMMerger

模型合并任务和程序硬校验：

1. 模型从语义上判断状态别名、触发消息、guard、action 和错误处理是否匹配。
2. 规范存在但实现缺失的 transition 标记为 `missing_transition`。
3. 实现存在但规范缺失的 transition 标记为 `extra_transition`。
4. guard 条件不同标记为 `guard_mismatch`。
5. 错误处理差异标记为 `error_handling_mismatch`。
6. 每个输入 transition id 必须出现在 `transition_sources`，否则整个构建失败。
7. 完整 prompt、Schema、响应和错误写入 `findings/fsm_merge.llm.jsonl`。

优先级初始规则：

| Divergence | Priority | 原因 |
|------------|----------|------|
| extra_transition | P0 | 实现接受了规范未声明路径 |
| guard_mismatch | P0/P1 | 可能绕过认证、顺序或资源约束 |
| error_handling_mismatch | P1 | 常导致状态残留和资源生命周期问题 |
| missing_transition | P2 | 更可能是兼容性或实现不完整问题 |

## Phase 2: 对抗性状态推理

### DirectionGenerator

`DirectionGenerator` 先把分析空间切成业务逻辑方向，避免 agent 只做泛泛安全评论。

示例方向：

1. Authentication and authorization state.
2. Session lifecycle and teardown.
3. Parser recovery after malformed input.
4. Resource allocation across repeated requests.
5. Cross-layer state synchronization.
6. Error response and partial state commit.

### Agent 输入上下文

每个 agent 都收到统一的 `AgentContext`：

```python
@dataclass
class AgentContext:
    protocol: str
    direction: str
    fsm: ProtocolFSM
    divergences: list[Divergence]
    code_snippets: list[Evidence]
    prior_traces: list[str]
    target_state: str | None
```

### ConflictDetector

冲突检测分为三类：

| Conflict Type | Priority | 判定条件 |
|---------------|----------|----------|
| Cross-layer state contamination | P0 | CrossLayerAgent 给出高置信污染路径 |
| FSM extra transition / guard mismatch | P0 | 实现路径比规范更宽松 |
| ASR conflict | P1 | Attacker 高可利用性，Defender 高保护性，二者证据不一致 |
| Unvalidated attacker hypothesis | P2 | 攻击假设合理但缺少实现证据 |

评分公式：

```text
risk_score =
  divergence_weight
  + attacker_confidence
  + cross_layer_weight
  + reachability_score
  + sanitizer_signal
  - defender_evidence_strength
```

其中 `defender_evidence_strength` 只降低优先级，不消除测试任务。强防护和强攻击假设并存时，系统应优先验证而不是提前判定安全。

## Phase 3: 状态感知测试合成

### PathPlanner

`PathPlanner` 在 `UnifiedFSM` 上执行有界 BFS，生成多条候选消息序列；当前没有实现加权最短路。`PathCalibrator` 对具体编码输入进行响应校准，再选择交给 synthesis 的路径。配置、状态和限制详见 6.1 节。

输入：

1. `Conflict`。
2. `UnifiedFSM`。
3. 初始状态和候选数量、搜索深度、搜索节点预算。当前不从已有 corpus 反推路径。

输出：

```text
PlannedStatePath
  candidate_id
  conflict_id
  states: S0 -> S1 -> ... -> Sn
  messages: M0, M1, ... Mn
  required_guards
  mutation_points
  transition_ids
  calibration: status / accepted_prefix_length / events / state_verified
```

### PathAwareFuzzer

职责：

1. 将 `PlannedStatePath` 编码为 AFLNet 可消费的请求序列。
2. 固定前缀路径，优先变异冲突 transition 附近的消息字段。
3. 根据 AFLNet 的状态反馈和覆盖率反馈调整路径权重。
4. 记录 crash、hang、new state、new edge、unexpected response。

### CrossLayerFuzzer

职责：

1. 生成多层消息交错序列。
2. 在层间边界处插入 renegotiation、reset、auth failure、half-close、timeout 等扰动。
3. 检查上层 parser 是否错误继承旧状态。

示例：

```text
TLS_HANDSHAKE
HTTP_AUTH_SUCCESS
TLS_RENEGOTIATION_WITH_WEAKER_CONTEXT
HTTP_PRIVILEGED_REQUEST
CONNECTION_HALF_CLOSE
HTTP_PIPELINED_REQUEST
```

## 与 AFLNet 的集成

ProtoLens 与 AFLNet 的交互保持在进程边界：

```text
ProtoLens Python Pipeline
  |
  | writes seed corpus, dictionaries, state paths, campaign config
  v
AFLNet Runner
  |
  | produces queue, crashes, hangs, state feedback, coverage
  v
ProtoLens Result Analyzer
```

### 集成点

1. Seed corpus：由 `corpus_encoder.py` 把路径消息序列写入 AFLNet 输入格式。
2. Dictionary：从 RFC message names、headers、method、status code 中生成。
3. Queue schedule：根据 `mutation_points` 和 guard 生成 `aflnet_queue_weights.tsv`，通过 `AFLNET_PROTO_SCHEDULE` 传给 patch 后的 `afl-fuzz`。
4. Target state：`AFLNetStateMapper` 使用 `ipsm.dot` 的节点标签和 queue 文件名把 conflict state 与 AFLNet 动态观察做证据映射。
5. Campaign config：`aflnet.cmd` 必须在 JSON 中完整配置 `-i`、`-o`、`-N`、`-P`、`-D`、`-x`、目标程序和 `--` 分隔；ProtoLens 不自动拼接或替换这些参数。
6. Candidate calibration：`PathPlanner` 从 FSM 生成多条候选路径，`PathCalibrator` 在 AFLNet corpus 准备前用真实 target socket 响应校准候选，按完整正向响应、最长成功前缀、最短候选的顺序为每个 conflict 选择一条路径。
7. Result analyzer：读取 AFLNet 输出目录，归档 crash、hang、coverage、state progression。
8. Runtime monitor：`MonitorAgent` 读取同一动态输出，覆盖停滞时调用 LLM 进行瓶颈分析并输出强 guard breakthrough seed 候选，ProtoLens 校验并写入 `AFLNET_PROTOLENS_IMPORT_DIR`，由 patch 后的 `afl-fuzz` 立即执行并只保留真实有趣输入。

当前仓库根目录的 `afl-fuzz.c` 已加入基于 `AFLNET_PROTO_SCHEDULE` 的 advisory power score 权重调整，以及基于 `AFLNET_PROTOLENS_IMPORT_DIR` 的运行时 seed 导入；未设置这些环境变量时行为保持 AFLNet 原有调度。

## CLI 设计

### Python 安装与 LLM SDK

ProtoLens 需要 Python 3.10 或更新版本。`requirement.txt` 列出 OpenAI SDK 及其传递依赖的锁定版本，安装命令为：

```bash
python3 -m pip install -r requirement.txt
```

所有在线 LLM 调用都通过 `protolens/utils/llm_client.py` 使用官方 OpenAI Python SDK：Agent 使用 Chat Completions，FSM 构建和网页检索使用 Responses。两条路径均使用 SDK 的 `with_raw_response.create()`，保留兼容服务扩展字段和完整原始 JSON，以供证据归档。参考 [OpenAI Docs](https://developers.openai.com/api/docs/libraries)。

现有 `llm.provider`、`model`、`base_url`、`api_key_env`、`extra_headers`、`timeout_seconds`、`max_tokens` 和 `response_format` 配置继续有效。`base_url` 可使用 API 根路径（例如 `https://example.com/v1`），也兼容以 `/chat/completions` 或 `/responses` 结尾的旧配置。远程接口仍需设置 `api_key_env` 指定的环境变量；本地无密钥接口使用 SDK 所需的占位 token，不包含真实凭证。

SDK 内部 `max_retries` 固定为 0，重试由 ProtoLens 的 `llm.retries` 控制，保留空响应格式降级、输出预算增长与网页检索后续写。每次请求通过上下文管理器关闭 SDK HTTP 客户端。离线模式不创建 SDK 客户端、不发起网络请求。

SDK 保持 HTTPS 证书校验，支持通过容器环境变量 `SSL_CERT_FILE` 指定可信 CA 证书包。迁移 SDK 不会自动信任自签名 CA；连接异常会保留底层证书或超时错误原因。AFLNet、编译器、目标程序等系统依赖仍由 Dockerfile 或系统包管理器安装，不属于 pip 依赖。

### 初始化 benchmark

```bash
python -m protolens.main init \
  --protocol rtsp \
  --target live555 \
  --source ./targets/live555 \
  --rfc-query "latest authoritative RTSP RFCs including updates and obsolete relationships" \
  --llm-provider openai \
  --llm-model gpt-5.4 \
  --out ./runs/rtsp-live555
```

### 分阶段构建 FSM

```bash
python -m protolens.main build-impl \
  --config ./runs/rtsp-live555/config.json

python -m protolens.main build-spec \
  --config ./runs/rtsp-live555/config.json

python -m protolens.main merge-fsm \
  --config ./runs/rtsp-live555/config.json
```

也可以使用一条可恢复命令按依赖顺序执行。重复执行时，有效阶段不会再次调用模型：

```bash
python -m protolens.main build-fsm \
  --config ./runs/rtsp-live555/config.json
```

仅在明确需要丢弃缓存时使用 `build-fsm --force`。各阶段返回 JSON 中的 `reused`，整链命令返回 `stage_reuse`，可直接确认实际是否调用了模型。

### 运行 agent 推理

```bash
python -m protolens.main reason \
  --config ./runs/rtsp-live555/config.json \
  --fsm ./runs/rtsp-live555/unified_fsm.json
```

### 生成并执行 fuzzing campaign

```bash
python -m protolens.main fuzz \
  --config ./runs/rtsp-live555/config.json \
  --fsm ./runs/rtsp-live555/unified_fsm.json \
  --conflicts ./runs/rtsp-live555/conflicts.json \
  --divergences ./runs/rtsp-live555/divergences.json
```

当前 `--jobs` 只接受 `1`。如果需要 AFLNet 并行 master/slave，应由开发者在 JSON 的 `aflnet.cmd` 中显式配置并行命令；ProtoLens 不合成额外 AFLNet 命令。

若需要开启候选路径执行校准，需要在同一个 `config.json` 中设置：

```json
{
  "aflnet": {
    "dry_run": false,
    "cmd": [
      "/abs/path/to/afl-fuzz",
      "-i", "/abs/path/to/run/corpus",
      "-o", "/abs/path/to/run/aflnet",
      "-N", "tcp://127.0.0.1/8554",
      "-P", "RTSP",
      "-D", "1000",
      "--",
      "/abs/path/to/target_server",
      "8554"
    ]
  },
  "path_calibration": {
    "enabled": true,
    "max_candidates": 3,
    "max_depth": 16,
    "max_expansions": 2000,
    "max_probes": 30,
    "startup_seconds": 3.0,
    "timeout_seconds": 2.0
  }
}
```

`PathCalibrator` 只从 `aflnet.cmd` 的 `--` 后半段读取 target 命令，不读取 `run_command`，也不合成任何 AFLNet 参数。

### 端到端执行

```bash
python -m protolens.main run \
  --config ./benchmarks/rtsp_live555_openai.json
```

## Artifact 目录

每次实验使用独立 run directory：

```text
runs/<protocol>-<target>-<timestamp>/
├── config.json
├── spec_fsm.json
├── impl_fsm.json                         # transition 只保存 evidence_ids
├── implementation_transition_facts.json # compact TransitionFact + evidence_ids
├── implementation_evidence_table.json   # 源码 excerpt 唯一结构化存储
├── implementation_source_manifest.json  # 文件路径、大小和 SHA-256
├── unified_fsm.json
├── divergences.json
├── checkpoints/
│   └── fsm_stages.json
├── directions.json
├── findings/
│   ├── attacker.jsonl
│   ├── attacker.llm.jsonl
│   ├── defender.jsonl
│   ├── defender.llm.jsonl
│   ├── cross_layer.jsonl
│   ├── cross_layer.llm.jsonl
│   ├── monitor_agent.jsonl
│   ├── monitor_agent.llm.jsonl
│   ├── fsm_specification.llm.jsonl
│   ├── fsm_implementation.llm.jsonl
│   └── fsm_merge.llm.jsonl
├── conflicts.json
├── candidate_paths.json
├── path_calibration.json
├── calibrated_paths.json
├── planned_paths.json
├── seed_intents.json
├── seed_manifest.json
├── corpus/
├── dictionaries/
├── aflnet_queue_weights.json
├── aflnet_queue_weights.tsv
├── monitor_import_queue/
│   └── .processed/
├── aflnet/
│   ├── queue/
│   ├── replayable-crashes/
│   ├── replayable-hangs/
│   ├── fuzzer_stats
│   ├── plot_data
│   └── ipsm.dot
├── fuzz_result.json
├── dynamic_analysis.json
├── state_mapping.json
├── seed_feedback.json
├── crash_replay.json
├── replanning_plan.json
├── transport_harness_manifest.json
├── transport_harness_result.json
├── monitor_seed_manifest.json
├── monitor_agent_report.json
└── report.md
```

## 配置文件

示例 benchmark 配置：

```json
{
  "protocol": "rtsp",
  "target_name": "live555",
  "spec_paths": [],
  "source_root": "./targets/live555",
  "entrypoints": ["RTSPServer.cpp", "RTSPClientConnection.cpp"],
  "build_command": "make",
  "run_command": "./testOnDemandRTSPServer 8554",
  "host": "127.0.0.1",
  "port": 8554,
  "aflnet": {
    "binary": "./afl-fuzz",
    "timeout_ms": 1000,
    "duration_seconds": 3600,
    "dry_run": false,
    "cmd": [
      "./afl-fuzz",
      "-d",
      "-i",
      "./runs/rtsp-live555/corpus",
      "-o",
      "./runs/rtsp-live555/aflnet",
      "-N",
      "tcp://127.0.0.1/8554",
      "-x",
      "./runs/rtsp-live555/dictionaries/rtsp.dict",
      "-P",
      "RTSP",
      "-D",
      "1000000",
      "-q",
      "3",
      "-s",
      "3",
      "-E",
      "-K",
      "-R",
      "--",
      "./testOnDemandRTSPServer",
      "8554"
    ]
  },
  "monitor_agent": {
    "enabled": true,
    "interval_seconds": 30.0,
    "stagnation_seconds": 300.0,
    "min_exec_delta": 1000,
    "max_seed_batch": 8,
    "max_llm_calls_per_stagnation_signature": 1
  },
  "transport_harness": {
    "enabled": false,
    "timeout_seconds": 3.0,
    "use_tls": false,
    "verify_tls": false,
    "max_actions": 20
  },
  "path_calibration": {
    "enabled": true,
    "max_candidates": 3,
    "max_depth": 16,
    "max_expansions": 2000,
    "max_probes": 30,
    "startup_seconds": 3.0,
    "timeout_seconds": 2.0
  },
  "fsm_build": {
    "rfc_queries": [
      "latest authoritative RTSP RFCs including updates and obsolete relationships"
    ],
    "rfc_analysis_scope": [
      "control connection lifecycle and states",
      "authentication and command sequencing",
      "data connection establishment",
      "TLS and protocol security extensions",
      "optional extensions evidenced as supported by the target implementation"
    ],
    "target_supported_extensions_only": true,
    "allowed_rfc_domains": [
      "rfc-editor.org",
      "datatracker.ietf.org",
      "ietf.org"
    ],
    "source_extensions": [".c", ".cc", ".cpp", ".h", ".hpp"],
    "ignore_directories": [".git", "build", "dist", "vendor"],
    "chunk_chars": 80000,
    "max_file_bytes": 2000000,
    "max_web_search_calls": 8
  },
  "llm": {
    "provider": "openai",
    "model": "gpt-5.4",
    "temperature": 0.0,
    "max_tokens": 24000,
    "retries": 2
  }
}
```

注意：`aflnet.cmd` 会直接传给 `subprocess.Popen()`。除第一个 AFLNet 二进制路径会在加载配置时做有限解析外，`-i`、`-o`、`-x`、目标程序参数都不会被 ProtoLens 替换或补全；建议在 JSON 中使用绝对路径，或确保相对路径在 `source_root` 作为工作目录时有效。

FSM 构建注意事项：`spec_paths` 可以为空，旧配置中的值只作为检索提示，不会读取。在线模型端必须支持 `/responses`、`web_search` 和 strict JSON Schema；仅支持 `/chat/completions` 的本地兼容服务无法完成 SpecificationFSM 的最新 RFC 检索，程序会明确失败。

## 报告输出

最终报告应包含：

1. 协议状态图摘要。
2. spec FSM 与 impl FSM 的主要分歧。
3. P0/P1/P2 conflict 列表。
4. 每个 conflict 的候选路径、选中路径、`candidate_id`、响应校准状态和成功前缀长度。
5. 动态验证结果：crash、hang、队列、状态映射、seed 反馈、monitor 生成 seed 和不可复现原因。
6. 关键证据：RFC 片段、源码位置、agent reasoning 摘要、触发输入及其 seed family 溯源。

## 当前新增组件实现说明

本轮完善后的 `fuzz` 阶段不是简单把一条 FSM 最短路径写成 seed，而是按 seed 维度保留语义来源和动态反馈：

1. `PathPlanner` 生成每个 conflict 的有界候选集合，输出 `candidate_paths.json`。可发送候选含 `candidate_id`、`transition_ids`、`required_guards`、`mutation_points` 和初始 `calibration.status=candidate`；搜索失败候选也有稳定 `candidate_id`，状态为 `not_executable`。
2. `PathCalibrator` 可选启动真实 target，对候选消息序列做 socket 响应校准，输出 `path_calibration.json` 和 `calibrated_paths.json`。校准只证明具体请求序列的响应接受情况，不证明内部状态或覆盖率。
3. `PathCalibrator.select()` 为每个 conflict 选择一条候选进入 `planned_paths.json`。所有未选候选仍作为审计证据保留，便于论文实验解释“为什么这条路径被放弃或降级”。
4. `StateAwareTestSynthesizer` 把选中路径扩展为 seed family：成功前缀保留为 baseline，目标字段变化集中在 mutation point；乱序和缺前置条件保留为单独负向测试，不混入正向路径。
5. `CorpusEncoder` 写入 AFLNet 原始请求流和 `seed_manifest.json`。manifest 记录 `source_candidate_id`、`family_id`、`variant`、payload SHA-256 和 queue 权重来源。
6. `AFLNetStateMapper`、`SeedFeedbackAnalyzer`、`ClosedLoopReplanner` 把 AFLNet 输出重新映射回 path/seed/variant，生成 `state_mapping.json`、`seed_feedback.json` 和 `replanning_plan.json`。
7. `MonitorAgent` 在运行时根据覆盖停滞调用 LLM，生成突破强 guard 的候选 seed，写入 `monitor_import_queue/`，由修改后的 `afl-fuzz.c` 主循环导入并用真实覆盖结果决定是否入队。

论文实验建议至少报告三组消融：原始 AFLNet、FSM 候选但关闭 `path_calibration`、FSM 候选加响应校准与 seed family feedback。指标应包含最终覆盖率、到达同等覆盖的时间、queue 中 seed family/variant 的保留比例、crash/hang replay 确认数，以及 `path_calibration.status` 分布。`response_accepted` 只能作为候选输入质量指标，不能直接写成内部状态覆盖。

## 历史 MVP 路线

### Milestone 1: 离线 FSM 与冲突生成

1. 建立 `protolens/` Python 包骨架。
2. 实现 `ProtocolFSM`、`StateTransition`、`Divergence`、`Conflict` 数据模型。
3. 实现基于 JSON 的 artifact store。
4. 实现手写或半自动的 `spec_fsm.json`、`impl_fsm.json` 合并。
5. 产出 `divergences.json` 和 `conflicts.json`。

### Milestone 2: LLM Agent 推理

1. 实现统一 `LLMClient`。
2. 实现 `BaseAgent` 和三个具体 agent。
3. 实现结构化 JSON 输出校验和失败重试。
4. 实现 `ConflictDetector`。
5. 在 RTSP/Live555 benchmark 上产出第一批 P0/P1 conflict。

### Milestone 3: AFLNet 驱动测试

1. 实现 `PathPlanner`。
2. 实现 `CorpusEncoder`，生成 AFLNet seed corpus。
3. 实现 `AFLNetAdapter`，启动 campaign 并收集输出。
4. 将 conflict 和 AFLNet 结果关联到 `report.md`。

### Milestone 4: Cross-Layer Testing

1. 增加 TLS+HTTP 或 RTSP+RTP benchmark。
2. 实现 `CrossLayerFuzzer` 的序列交错策略。
3. 增加跨层状态污染报告模板。

## 关键风险与缓解

| 风险 | 影响 | 缓解 |
|------|------|------|
| LLM 构建 FSM 不稳定 | 分歧误报或漏边 | strict Schema、权威域名、源码原文校验、transition 覆盖映射、完整对话审计 |
| 源码分块导致跨文件语义丢失 | impl FSM 缺边 | entrypoint 优先、TransitionFact 证据化、一次全局 assembler、fact 覆盖校验、AFLNet 动态反馈 |
| agent 输出泛泛而谈 | fuzzing 目标不可执行 | 强制输出 state、transition、precondition、test strategy |
| 路径不可达 | fuzzer 浪费时间 | PathPlanner 只生成候选，PathCalibrator 用真实 socket 响应校准，失败候选保留证据并降级选择 |
| AFLNet 状态编号和 FSM 状态难对应 | 结果难解释 | 使用响应签名、状态名、路径消息共同映射 |

## 设计原则

1. 所有 LLM 输出必须结构化、可校验、可追溯。
2. 所有高危结论都必须有动态验证路径。
3. FSM、divergence、conflict、planned path 都是可持久化 artifact。
4. MVP 先做进程外增强，避免过早修改 AFLNet 核心。
5. 优先支持一个端到端 benchmark，再扩展到多协议和跨层场景。
