# JByteScanner 大型项目优化路线图

> 更新日期：2026-07-28（P0.6 已按同事评审修订：强度矩阵 / SinkLocationKey+stmtIndex / 四层产物 / severity·confidence 分离）
> 适用基线：`feature/taie-migration` 当前代码及工作区未提交改动
> 历史功能阶段请参考 `CHANGELOG.md`；本文件聚焦 Tai-e 迁移后在真实大型项目上的可完成性、准确性和产物质量。

## 1. 路线图依据

本路线图来自以下真实扫描工作区的日志和报告：

- ecology10：`E:\code\ecology10\E10\webapps\ROOT\WEB-INF\.jbytescanner`
- qiqin-srm：`D:\collect_code\qiqin-srm\deploy\.jbytescanner`
- 汉得 SRM：`E:\code\汉得SRM\.jbytescanner`（人工源码复核：`E:\code\汉得SRM_src\audit.md`）

### 1.1 实测基线

| 指标 | ecology10 | qiqin-srm |
|---|---:|---:|
| Tai-e app classpath | 591 | 57 |
| Tai-e library classpath | 1421 | 1505 |
| World 构建 | 约 5 分钟后 OOM，未完成 | 约 9 秒 |
| PTA/taint | 未进入完成状态 | 约 32.09 秒 |
| 峰值内存 | OOM | 约 5.6 GB |
| duplicate class groups | 227 | 1208 |
| 重复类数量合计 | 37,127 | 424,244 |
| 原始 taint source | 107,491 | — |
| 唯一 taint source | 76,670 | — |
| taint flow / SARIF result | 未产出 | 10,826 |
| 唯一 source/sink message | — | 4,380 |
| SARIF 完全重复 result | — | 1,355 |
| Secret finding | 2,026 | 842 |

补充样本（汉得 SRM，2026-07-28，单次 worker 成功完成）：

| 指标 | 汉得 SRM |
|---|---:|
| Tai-e app classpath | 180 |
| Tai-e library classpath | 893 |
| application classes | 126,745 |
| entry 注入 | 1,590 |
| API param source | 3,413 |
| captured taint flows / SARIF | 7,316 |
| 人工高可信可用洞 | ≤ 数个（含 1 条未授权 SSRF 与 SARIF 高度吻合） |
| 库内 sink 容器告警占比（估） | ≈ 77% |
| 业务包 sink 容器告警 | ≈ 1,646；其中 `URL.<init>` 仅 5 条 |

### 1.2 当前核心判断

1. ecology10 的规模本身足以使单次全量 PTA 超出常规资源预算；当前还叠加了 classpath、application scope、入口和 source 的可避免放大，需要先区分“项目真实规模”和“扫描器额外膨胀”。
2. qiqin-srm 的首要问题不是漏报，而是 sink 语义、flow 聚合和报告生成导致结果数量与风险数量失真。
3. 汉得 SRM 在 PTA 已成功完成的前提下，暴露了**精度/噪声**问题：召回高、精确率低；主因是库方法体内弱 sink 命中、CI PTA 串味、过宽终态 sink、finding 身份不完整与 severity/confidence 混算。此类问题与项目品牌无关，属于默认分析管线的通用缺陷（见 **P0.6**，已按 2026-07-28 评审修订）。
4. 下一阶段应先建立“可去重、可度量、可预算、可分区、可分层 triage”的基础，再继续增加新的 source、sink、transfer 和入口补偿。`ecology10` 的单次全量完成属于优化目标和压力测试，不作为所有发布版本的硬门槛。

### 1.3 超大项目的成功定义

对 ecology10 这类 XL 项目，以下结果都可以视为合理：

- 在用户指定的时间和内存预算内完成单次全量扫描。
- preflight 判断单次全量风险过高后，自动或由用户选择按 package、模块或入口组分区扫描。
- 达到预算上限后安全终止当前批次，保存已经完成的结果、失败阶段和可恢复状态。

不合理的结果不是“没有单次跑完全量”，而是：

- 未做规模估算就运行数分钟后无诊断 OOM。
- OOM 后没有可用结果、覆盖率、失败批次或恢复点。
- 重复 class、route、entry、source 消耗了大量预算，却无法区分这些额外成本和项目本身的真实复杂度。

### 1.4 架构决策：保留 ASM，但收敛为统一轻量索引层

**结论：Tai-e 0.5.4 的前端和中型项目性能提升，不构成删除 ASM discovery 的理由。需要调整的是 ASM 的组织方式和职责边界，而不是把所有字节码解析迁入 Tai-e。当前阶段将 Tai-e 0.5.4 视为不修改源码的第三方分析内核，不维护 fork，也不改动 `D:\workspace\javaspace\tai-e-0.5.4`。**

推荐固定为两层：

| 层次 | 默认实现 | 负责 | 明确不负责 |
|---|---|---|---|
| Artifact/Class Index | ASM，进程内、低内存、可持久化 | artifact/class hash、重复与版本冲突、package histogram、annotation/route、method signature、精确到 descriptor 的 invoke candidate、constant/string、source/sink/transfer candidate、规模估算和分区规划 | 类型解析、动态分派、可达性、跨方法数据流、漏洞判定 |
| Semantic Analysis | 独立 Tai-e worker | class hierarchy、method resolution、IR、call graph、PTA、taint propagation、Spring DI/WEC、真实 source-to-sink flow 和稳定 statement identity | 重复 artifact 的发现与选择、扫描前预算判断、API/secret 基础产物 |

边界原则：

1. ASM 只陈述“字节码里存在什么候选事实”；Tai-e 判断“调用解析到谁、是否可达、数据是否真的传播”。
2. sink ASM pre-scan 只能用于裁剪 Tai-e 规则，不能直接成为 finding；key 必须使用 `owner + name + descriptor`。
3. API inventory、secret candidate、classpath conflict 和 preflight 不依赖 Tai-e World。即使 World 构建失败，也必须能交付这些轻量产物。
4. classpath mediation、application scope 和分区规划必须发生在 Tai-e 之前；进入 World 后再处理重复或选版本已经太晚。
5. Tai-e 内部同样使用 ASM，不等于 JByteScanner 应把业务索引绑定到 Tai-e frontend 内部实现。除非 Tai-e 提供稳定、低成本、无需完整 World 的公开索引 API，否则不应以其内部 visitor 替代独立 ClassIndex。

因此，当前 `DiscoveryEngine -> SecretScanner -> TaintEngine` 的串行阶段应调整为：

```text
Workspace/Config Migration
  -> Artifact Ingest
  -> Unified ASM ClassIndex
  -> Preflight & Scan Planning
  -> Fast Outputs (API / Secret / Classpath Report)
  -> Tai-e Worker (single-run or partitions)
  -> Structured TaintFlow Conversion
  -> Canonical Finding / Triage
  -> SARIF / PoC / optional local TFG
```

模式边界：

- `api`：默认只使用 ClassIndex，不构建 Tai-e World。
- `secrets`：默认只使用 ClassIndex。
- `scan`：ClassIndex + Tai-e worker。
- `scan --budget`：preflight 后选择单次或一等分区模式。
- Tai-e discovery 只可作为精确性对照或调试选项，不作为默认路径。

当前组件收敛方向：

- 保留 `AsmRouteExtractor` 的能力，但演进为 `ClassIndexBuilder + RouteProjection`，避免 route 模块独占一套 class parser。
- `RuleManager` 的 sink pre-scan、persistent source、model accessor 不再各自打开 JAR，而是消费统一 index。
- `SecretScanner` 消费 index 中的 constant/string candidate。
- `JarLoader` 后续拆分为 `ArtifactResolver`、`ClasspathPreflight`、`ApplicationScopePlanner`；解压/发现与选择/规划分离。
- `TaieManager` 与 `TaintEngine` 的 World/analysis 初始化在 JByteScanner 内收敛为一个 `TaieRunner`/worker 协议；worker 只是启动原版 Tai-e 0.5.4 并加载 JByteScanner plugin，不修改 Tai-e 源码。确认无调用后删除或归档 JByteScanner 内的 Tai-e 版 `RouteExtractor`、`ResilientSootWorldBuilder` 等历史路径。
- 内部 API 主产物改为结构化 `api-index.json`；`api.txt` 只保留兼容输出。

阶段优先级也需要调整：**最小可用 Unified ClassIndex 从 P2 前移到 P0/Milestone A；持久化增量缓存、完整 secret suppressor 和缓存失效策略仍留在 P2。** 这样先消除多模块重复解析和身份不一致，再建设增量能力，避免在多个临时 ASM 扫描器上分别加缓存。

---

## 2. 当前未提交改动评估

当前工作区的改动已纳入本路线图。`mvn test` 于 2026-07-23 执行通过：7 tests、0 failures、0 errors。

| 当前改动 | 状态 | 对大型项目的价值 | 仍需处理的问题 |
|---|---|---|---|
| `JarLoader` 发现 `WEB-INF/classes`、`BOOT-INF/classes` 等 loose class directory | 已实现并有测试 | 修复 ecology 一类 exploded Web 应用业务类漏扫 | 只解决“漏扫”，未解决 mixed/shaded JAR 整体提升、重复 artifact 和类冲突 |
| `rules_version: 3`、旧规则备份和增量合并 | 已实现并有测试 | 允许升级默认规则而不直接覆盖用户配置 | 当前只会添加/补字段，不能安全撤销已经证明高噪声的 bundled rule；规则缺少稳定 ID 和来源标记 |
| source/sink `index` 和 source `taint_type` | 已实现 | 可精确描述 receiver、参数和 call result，避免所有参数都成为 sink | 大量旧规则仍未配置 index；结果模型和日志 parser 仍丢弃 source/sink index |
| 可配置 `transfers` 及内置 String、上传、压缩、集合转换 | 已实现 | 改善 `only-app:true` 下的跨库传播漏报 | transfer 数量继续增长前应建立语义测试；部分宽泛 collection transfer 可能扩大传播范围 |
| `call-site-mode`、Spring 分析和 Service fallback 开关 | 已实现，部分为实验能力 | 改善接口调用、Spring DI 不完整导致的漏报 | `call-site-mode:true` 和 supplemental entry 可能放大 flow；必须用两个大样本做 A/B 性能与噪声回归 |
| typed cache persistent source 和 model accessor 推断 | 已实现，默认开启 | 能发现“持久化数据读取后进入危险 sink”的二阶流 | 对 app classpath 进行多轮 ASM 扫描，并增加 supplemental entry/source；大项目上需要预算、缓存和默认策略评估 |
| 大型 taint config 分片 | 已实现并有测试 | 解决 SnakeYAML 文档大小限制，35,000 entry 测试可生成 14 个 shard | 仍先序列化完整文档，再复制 `subList` 和二次序列化；降低格式限制但没有完全降低瞬时内存 |
| sink 预扫描 | 已实现 | 不向 Tai-e 写入完全未引用的 sink，减少 phantom/missing method 问题 | 当前 key 只有 `owner + methodName`，不能区分 overload/descriptor；同一 JAR 被重复扫描时也没有 class hash 去重 |
| TaintFlow 日志 parser 和 IR stmt sink 解析增强 | 已实现并有测试 | 修复 constructor、call-result source 和同名方法误判 | 仍依赖 `tai-e.log`；仍全量 `readAllLines`；没有直接消费已经捕获的 `Set<TaintFlow>` |
| OOM 捕获和 stderr stack trace | 部分实现 | 比仅捕获 Exception 更完整 | 文件日志仍主要只有 `t.toString()`；OOM 后继续处于同一 JVM 风险高，缺少 heap dump、GC 和阶段资源记录 |

### 2.1 当前改动尚未解决的关键事实

- `TaintEngine` 仍按每条 route 生成 entry signature，没有按 Java 方法去重。
- `JBSScanEntryPointPlugin` 的 application entry 循环仍在 `addEntryPoint()` 后才写入 `addedMethods`，因此重复方法仍会重复注入。
- `RuleManager` 的 API 参数 source 仍没有全局 canonical key；ecology 的 30,821 条已知重复 source 仍会生成。
- `JarLoader.shouldPromoteToApp()` 仍是“JAR 内命中一个业务类就整体提升为 application”。
- 默认规则仍把 Fastjson 普通 parse、`new URL/URI` 和 `new File` 当作终态 sink（**P0.6** 按 sink 强度矩阵 suppress/demote；**P1.3/P1.4** 做规则层 transfer/终态分离）。
- SARIF、PoC 和 Secret report 仍没有统一 finding fingerprint；`Vulnerability` 丢弃 `sourceIndex`/`sinkStmtIndex`/`sinkContainer` 等字段（**P0.6-A** 中间模型；**P1.7** 完整 canonical）。
- 主结果未按「sink 强度 + 包归属 + 语义证据」分层，库内部弱 sink 会直接进入 SARIF；worker 模式下 `VulnScorer` 依赖 host `World` 导致 auth 评分失真（**P0.6**）。

---

## 3. P0：控制 ecology10 的规模放大和失败方式

完成标准：已知 entry/source 重复归零；扫描前能够估算规模并选择单次或分区模式；在资源预算不足时安全停止并输出覆盖率、完成批次和失败原因。单次全量完成是加分目标，不是硬性发布门槛。

### P0.1 Route、EntryPoint、TaintSource 三层建模和去重

**涉及位置**：

- `TaintEngine.run()` entry signature 构造
- `RuleManager.generateTaieConfig()` API 参数 source 构造
- `JBSScanEntryPointPlugin.onStart()` entry 注入

**要求**：

```text
RouteKey      = (HTTP method, path, Java method, parameter bindings)
EntryPointKey = Java method signature
SourceKey     = (kind, Java method signature, index, taint type)
```

- Route 保持一对多，不能因为去重丢失同一 Java 方法对应的多个 HTTP 路径。
- PTA entry 按 `JMethod`/完整 method signature 去重。
- API param source、显式 source、persistent source 汇总到同一个 canonical source set。
- 插件使用 `if (addedMethods.add(method)) { solver.addEntryPoint(...) }`，而不是注入后再记录。
- 输出 raw/unique/duplicate 计数和 Top duplicate methods。

**验收门槛**：

- ecology API source 从 107,491 降到 76,670 或更低，canonical duplicate 为 0。
- entry signature raw/unique 可见，插件实际注入重复数为 0。
- 新增重复 route、重载方法、不同 source index 的单元测试。

### P0.2 Classpath preflight、artifact mediation 和 application scope

**要求**：

扫描前生成 `classpath-preflight.json`，至少记录：

```text
path, SHA-256, size, manifest/version,
classCount, applicationClassCount, applicationClassRatio,
duplicateClassCount, packageHistogram, selectedRole, selectionReason
```

分级处理：

1. 相同 SHA-256 的重复 artifact 可以自动去重。
2. 同名同版本但内容不同必须报警，不能静默选择。
3. 多版本 artifact 使用显式策略选择，并记录最终选择。
4. shaded/non-shaded 或不同 artifact 的重复 class 默认只报告，不自动删除。
5. `targetAppJars`、`depAppJars`、`libJars` 在进入 Tai-e 和 ASM 扫描前统一 canonicalize。

**mixed/shaded JAR**：

- 不再因为出现一个 `scan_packages` 类就把整个 JAR 提升为 application。
- 优先实现 class/package 级 application scope。
- 如果 Tai-e 不能对同一容器内的类分角色，则将匹配业务 package 的 class 提取到临时 app-only 目录，原 JAR 保留为 library，并记录提取清单和类加载优先级。

**重点回归**：

- ecology `classbean.jar`：33,615 classes 中业务类约 3,315，不能继续整体作为业务类处理。
- ecology 的 bcprov、POI schemas、Scala/Spark、Hadoop 冲突。
- qiqin 的同名同版本 JAR和 Hibernate、Nacos、Elasticsearch、Groovy 多版本共存。

### P0.3 Tai-e worker 子进程和资源预算

将 World/PTA/TFG 放入独立 worker JVM，主进程负责准备输入和收集结果。

**worker 参数和诊断**：

- 显式 `-Xms/-Xmx`。
- `-XX:+HeapDumpOnOutOfMemoryError` 和 workspace 内 heap dump 路径。
- GC 日志写入 workspace。
- 分别记录 World、PTA、TFG、report 的耗时、heap before/after、peak heap/RSS。
- 文件日志使用带 Throwable 的完整 stack trace，而不是只记录 `t.toString()`。
- OOM 后终止 worker，不在受损 JVM 中继续报告生成。

**超大项目执行模式**：

分区分析不是 OOM 后才启用的临时回退，而是 XL 项目的一等执行模式。preflight 预计超过预算时，支持按 package、模块/JAR 集合或 controller group 分批分析，最终按 canonical finding key 合并。每个批次必须记录入口数、类/方法覆盖范围、耗时、峰值内存和完成状态。

### P0.4 限制当前实验性入口/source 扩张

在 ecology 建立单批和分区基线前：

- `persistent_source_analysis` 增加 `off/on/auto` 模式和数量上限。
- `spring_service_entry_fallback` 保持默认关闭。
- `call-site-mode`、Spring plugin、persistent source 分别做 A/B benchmark，不能同时开启后只看最终数量。
- 记录每种机制新增的 source 数、entry 数、reachable method 数和 flow 数。

### P0.5 最小 Unified ClassIndex

先实现进程内、单次扫描生命周期内共享的最小索引，不在第一版同时引入数据库或复杂持久化：

- artifact canonicalization/hash 完成后，只解析被选中的唯一 class byte。
- 采用 streaming visitor；默认不保存完整方法字节码、instruction tree 或 class byte，避免索引本身在 ecology 上成为第二个内存热点。
- 统一 `ClassId`、`MethodId(owner, name, descriptor)`、`CallSiteId(method, offset/line)`，route、rule candidate、secret 均引用同一身份。
- 通过 projection 分别生成 route、secret、rule candidate 和 preflight 统计，不允许 projection 再次打开 JAR。
- 先提供内存预算和 spill 接口；只有 benchmark 证明需要时再启用磁盘分片。

完成标准：`DiscoveryEngine`、`RuleManager`、`SecretScanner` 不再各自维护独立的 JAR 全量遍历；每个唯一 class byte 的默认解析次数为 1，并在 `benchmark.json` 中记录 index class count、parse time、peak memory 和 cache hit/miss。

### P0.6 通用精度管线：sink 强度 + 包归属 + 语义证据 + 聚合实例

> **评审状态（2026-07-28）**：总体方向批准；**不得按初稿“无条件丢弃全部业务包外 sink”原样实施**。下列正文已吸收评审修改，作为合并门槛与实现规格。  
> **定位**：在不修改 Tai-e 0.5.4 源码的前提下，于 **flow 捕获之后、SARIF/PoC 之前** 建立默认精度层，降低跨项目结构性误报，同时禁止用包名硬删终态危险 sink。  
> **依据**：汉得 SRM raw 7,316 + 人工 `audit.md`；同事复算：业务包内 1,646（包外 77.5%）；exact unique 1,643；全规则 sink-fan-in 约 27。已知 TP `getPictureBase64` 的 `sinkContainer` 在业务 Service 内，包过滤本身不会误杀。  
> **与 P1 关系**：P0.6 落地 **FindingPipeline、分层产物、保守 suppress/demote、worker enrichment**；P1.3/P1.4 做规则层 transfer/终态分离；P1.7 在 P0.6 identity 上扩展完整 canonical/SARIF fingerprint。P0.6 不得依赖 P1 全部完成才可用。

#### 问题模型（跨项目通用）

在 `pta=cs:ci;only-app:true` + `taint_call_site_mode:true` + 全 Controller 参数 source 的默认配置下，以下现象可复现：

| 噪声类型 | 机制 | 典型表现 |
|---|---|---|
| **库内弱 sink 容器** | 可达库方法 IR 内的 `new URL`/`File`/`Paths.get`/内部 `parse` | 汉得约 **77.5%** flow 的 `sinkContainer` 不在 `org.srm`/`org.hzero` |
| **CI 串味假流** | 上下文不敏感合并 `String`，多入口汇入同一真实 sink | 数百 Controller → 同一 `JdbcQueryer`；Velocity 162 源汇 1 sink |
| **过宽“终态”规则** | 构造/裸解析被标成高危漏洞 | URL/File/Fastjson/Jackson/Velocity 主导 CRITICAL/HIGH |
| **身份与路径证据不足** | `TaintFlow` 仅 source/sink 端点；`Vulnerability` 丢字段；`isFullFlow=true` 名不副实 | 无法可靠做“同调用链副作用”判断 |
| **severity 与 confidence 混算** | 单一乘法分数 | 高危但证据弱被压成 LOW，或假流拿 CRITICAL |
| **worker auth 失真** | host `VulnScorer` 依赖 `World.get()`，worker 模式下静默 `authBarrier=1.0` | 有鉴权入口被当公开 |

**不在 P0.6 范围**：逻辑漏洞（网关头、权限模型等）；跨方法完整 TFG 路径证明（仅做 worker 内同方法局部证据）；改 Tai-e 内核；对**全部规则**默认做激进 sink-fan-in 压到 ~27（可选调试模式，非默认）。

#### 设计原则（修订后）

1. **默认偏精确，配置可放开召回**：`noise_filter.enabled=false` 必须恢复 raw 数量**与身份**，不能只恢复条数。
2. **包归属是置信度/弱 sink 因子，不是终态 sink 的唯一删除条件**：见 sink 强度矩阵。
3. **`sinkContainer` + `sinkStmtIndex` 定义 sink 位置**；source 是 finding 的 **instances**，不属于 sink identity。
4. **severity 与 confidence 分离**；主 SARIF 按 rank 排序，不把“证据不足”改写成“影响低”。
5. **过滤只发生在统一 FindingPipeline**；`SarifReporter`/`PoCReporter` 只序列化，禁止各写一套过滤。
6. **可解释漏斗**：`raw-flows` / `results-suppressed` / `low-confidence` / `result.sarif` 四层；每条 suppress/demote 有 reason code。
7. **不修改 Tai-e**；需要 IR 证据时在 worker 内、World 存活时写入 `CapturedTaintFlow` 扩展字段。

#### 结果分层（必须先定义，否则 demote 不可验收）

| 产物 | 内容 | 默认是否人工 triage |
|---|---|---|
| `raw-flows.jsonl`（或等价） | 全部 Tai-e/`CapturedTaintFlow`，身份完整 | 否（调试/重放） |
| `results-suppressed.jsonl` | **确定性**抑制：库内部弱 sink、包外弱构造/裸 parse 等 | 否 |
| `low-confidence.jsonl` | 仍有安全意义但证据不足：高 fan-in 模板、无副作用 URL 构造、固定 DTO Jackson 等 | 可选复核 |
| `result.sarif` | 默认主视图：高置信 finding + 聚合后的 sink 位置 | **是** |

约定：

- **suppress** = 不进主 SARIF，进 `results-suppressed`。
- **demote** = 不进主 SARIF 的 HIGH/CRITICAL 队列，默认进 `low-confidence`（可配置 `demote_to_main_as: none|note`）；**不得**把高 severity 终态 sink 仅因 confidence 低改写成“无漏洞”。
- 主 SARIF 默认门槛：`confidence >= 主阈值` **或**（`sinkStrength=TERMINAL_SIDE_EFFECT` 且未 suppress）。具体阈值可配，但必须写入 benchmark。
- `noise_filter` 关闭时：主 SARIF 可退化为近 raw（仍建议 exact dedupe），suppressed/low-confidence 可为空。

#### Sink 强度矩阵（P0.6 核心谓词）

为每条配置 sink / 命中 flow 标注 `sinkStrength`：

| sinkStrength | 示例 | 业务包外 (`outsideFindingPackages`) | 命中库内部弱实现包 |
|---|---|---|---|
| `CONSTRUCTOR` | `new URL`/`URI`/`File`、`Paths.get` | **SUPPRESS** | **SUPPRESS** |
| `PARSER` / `INTERMEDIATE` | Fastjson/Jackson 普通 `parse`/`readValue`（无类型升级证据） | **SUPPRESS** 或 **DEMOTE→low-confidence** | **SUPPRESS** |
| `TERMINAL_SIDE_EFFECT` | `Runtime.exec`、`Statement.executeQuery`、`openStream`/`openConnection`、文件写删、脚本 `eval` 等 | **KEEP**，最多 **降低 confidence**；**禁止仅因包外 hard-drop** | 若容器为库**公开 API 边界**上的终态调用则 KEEP；纯内部 helper 再议 |
| `UNCLASSIFIED` | 未建表 | **DEMOTE**，禁止 hard-drop | **DEMOTE** |

伪代码：

```text
if sinkStrength in {CONSTRUCTOR, PARSER, INTERMEDIATE}
   and (outsideFindingPackages or libraryInternalWeakContainer):
      SUPPRESS  # reason: WEAK_SINK_OUTSIDE_APP / WEAK_SINK_LIBRARY_INTERNAL
elif sinkStrength == TERMINAL_SIDE_EFFECT and outsideFindingPackages:
      KEEP + confidence↓  # reason: TERMINAL_OUTSIDE_APP_PACKAGE
      # 不得 suppress
elif template/JSON 高 fan-in 且 evidenceLevel < LOCAL_DEFUSE:
      DEMOTE → low-confidence
```

`finding_packages` 默认等于 `scan_packages`，允许分离配置。包为空时：**warn**，不得假装“全项目即业务包”；弱 sink 仍可按库内部表 suppress，终态 sink 保留。

库内部表示例（**包 + sink family** 谓词，不是“该包下所有规则一律 suppress”）：

```text
oracle.xml.* + {URL,URI,File,Paths}
com.fasterxml.jackson.databind.* + {URL,URI,File,Paths,readValue-as-weak}
com.alibaba.fastjson.serializer|parser.* + {parse, URL, File}
org.apache.cxf.* / org.apache.ws.commons.* + 构造类弱 sink
```

业务封装如 `org.xxx.report.JdbcQueryer` **禁止**进黑名单。

#### Sink 位置 identity 与聚合（修订 FindingKey）

**禁止**使用缺少语句位置的 key 合并同一方法内两次独立 sink 调用。

```text
SinkLocationKey =
  ruleIdentity
  + sinkRuleSignature
  + sinkIndex
  + sinkContainerSignature
  + sinkStmtIndex          # 必需；已有 CapturedTaintFlow.sinkStmtIndex
  # 可选稳定化：sinkLineNumber 仅作展示，不以 line 为唯一键（重编译漂移）
```

```text
CanonicalFinding:
  sinkLocation: SinkLocationKey
  sinkStrength, evidenceLevel, severityScore, confidenceScore, rankScore
  instances[]:            # 全部保留；主 SARIF 只展示 top N
    sourceContainerSignature
    sourceRuleSignature
    sourceKind, sourceIndex
    routeId?, authSummary?
    localEvidence?
  representativeInstance  # 按下方策略选择，非输入顺序
  sourceCount
  suppression/demotion reasons
```

**source 不属于 SinkLocationKey。** exact dedupe：同一 `SinkLocationKey + source instance` 只保留一次。

**sink-fan-in（默认仅高噪声规则族）**：SQL、模板引擎等；JSON/SSRF 默认 **exact** 或按 `SinkLocationKey` 聚合 instances，**不对所有规则强制压到 ~27**。

主 SARIF 展示 `instances` top N（如 10）；**完整 instances 必须进 sidecar**（finding 旁路文件或 `low-confidence`/`raw` 关联 id），禁止“只留任意前 10 个 source”导致真入口丢失。

**representativeInstance 选择顺序**（固定、可测）：

1. 有精确 route 映射  
2. auth 门槛最低（公开优先）  
3. 局部证据 / path 质量最好  
4. 参数类型与规则语义匹配  
5. 稳定字典序 tie-breaker  

finding 的 **severity 取 instances 中最大**；**confidence 反映关联证据**，不取“随便一个 source”的分数。

#### 语义 demote / 升级（修订：模板串命中不是充分条件）

签名级默认可在 host 完成；**常量 Class、同 receiver 副作用、局部 def-use** 必须在 worker enrichment 后才可作为升级条件。

| 规则族 | 默认 | 进入主 SARIF 高危的**充分**条件（需额外证据） |
|---|---|---|
| Fastjson 裸 parse | demote → low-confidence | autoType/gadget/类型名可控等（P0.6-C / P1） |
| Jackson `readValue(String,Class)` | demote | `Class` 非常量且被污染，或多态 typing 证据 |
| `new URL`/`URI` | 无副作用 → suppress 或 low-confidence | **同方法、同 receiver** 上 `openStream`/`openConnection`/等价网络副作用（汉得 `getPictureBase64`） |
| `new File`/`Paths.get` | 无副作用 → suppress 或 low-confidence | **同方法、同 receiver** 文件读/写/删等 |
| Velocity/FreeMarker 等 | **即使** sinkIndex 命中模板串参数，若 **高 fan-in 且无路径/局部证据** → low-confidence，**禁止 CRITICAL** | 短局部 def-use，或同方法/短调用链可解释，或 fan-in 低且代表 source 可解释，或业务上模板可写入口关联；**禁止**“请求入口 + index=模板串”单独升 CRITICAL |

说明：汉得 162 条 Velocity 全部是 ParamSource + `evaluate` index=3，按旧稿会误升 CRITICAL；修订后必须落入 low-confidence。

**证据等级** `evidenceLevel`：

```text
ENDPOINT_ONLY          # 仅有 source/sink 端点（当前默认）
LOCAL_SIDE_EFFECT      # 同方法同 receiver 副作用
LOCAL_DEFUSE           # 同方法局部 def-use（后续）
INTERPROC_PATH         # 跨方法路径（延后 P1+，非 P0.6 必达）
```

当前 `isFullFlow=true` **不得**解释为 `INTERPROC_PATH`。

#### 评分模型（severity / confidence 分离）

```text
severityScore  = f(sinkImpact, reachability, authBarrier)
confidenceScore = f(packageProvenance, sinkStrength, evidenceLevel,
                      fanInPrecision, sourceSemanticQuality)
rankScore       = combine(severityScore, confidenceScore)  # 用于排序，公式可配
```

SARIF `properties` 至少输出：

```json
{
  "severityScore": 9.5,
  "confidence": 0.35,
  "rankScore": 3.33,
  "sinkStrength": "TERMINAL_SIDE_EFFECT",
  "evidenceLevel": "ENDPOINT_ONLY",
  "sourceCount": 162,
  "packageProvenance": "IN_FINDING_PACKAGES"
}
```

禁止把“公共 RCE + 低 confidence”显示成普通 LOW **影响**；UI/文案应区分“高危候选、证据不足”。

**Auth**：禁止 host 依赖 `World.get()`。P0.6 必须二选一（可并行）：

- API discovery（ASM）把 auth 摘要写入 `ApiRoute`；或  
- worker 捕获 source 方法注解/权限摘要进 `CapturedTaintFlow` / instance。

#### 实现落点与管线

**禁止**继续 `CapturedTaintFlow → Vulnerability` 直接丢字段。引入中间模型（名称可调整）：

```text
CapturedTaintFlow
  → RawFindingEvidence          # 全字段 + sinkStrength 初分
  → provenance annotation       # finding_packages / libraryInternal
  → semantic classification
  → SuppressionDecision | DemotionDecision
  → aggregation by SinkLocationKey
  → severity/confidence/rank
  → reporters (SARIF / PoC / sidecars)
```

建议模块边界：`FindingPipeline`（或等价）独占策略；Reporter 无业务过滤。

**worker 扩展字段（P0.6-C，World 存活时）**，写入 `CapturedTaintFlow`：

```text
sinkStmtIndex (已有)
localFollowingSideEffects[]   # 同方法、同 receiver
sinkArgumentConstants[]       # 如 Class 字面量
sinkArgumentTypes[]
localDefUseConfidence         # 可先粗粒度枚举
authAnnotationsSummary?       # 可选
```

跨方法副作用识别 **不作为 P0.6 必达**。

**离线 replay**：支持仅读 `worker-result.json` 跑 FindingPipeline，便于汉得回归与策略 A/B，不重跑 PTA。

#### 分阶段实施（合并顺序）

**P0.6-A — 结构（默认结果可变可不变，优先零策略）**

1. 全量保留 `CapturedTaintFlow` 字段进入 evidence  
2. `FindingPipeline` + `SinkLocationKey`（含 `sinkStmtIndex`）  
3. source → `instances[]`  
4. reason code 框架  
5. 离线 replay 入口  
6. 单测：同方法两处 `executeQuery` → 两个 finding  

**P0.6-B — 保守过滤（默认可开启）**

1. 包外 + 弱构造/裸 parse → suppress  
2. 库内部 + 弱 sink family → suppress  
3. 包外终态 sink → KEEP + confidence↓，**禁止 drop**  
4. exact dedupe  
5. SQL/模板等高 fan-in：按 `SinkLocationKey` 聚合，sidecar 保留完整 instances  
6. 四层产物与漏斗指标  

**P0.6-C — 语义证据**

1. URL→同方法 `openStream`/`openConnection`  
2. File/Path→同方法读写删  
3. Velocity 明确 template arg + fan-in/evidence 门闩  
4. Jackson Class 是否常量  
5. Fastjson 与版本/autoType/gadget 信息衔接（可部分延后）  

**P0.6-D — 评分、auth、报告**

1. 修复 worker 模式 auth  
2. severity/confidence/rank 分离  
3. 主 SARIF / low-confidence / suppressed  
4. PoC **仅**对精确 route + 选中 instance，不为 fan-in 占位 source 盲目生成  
5. benchmark 在 pipeline **完成之后**写入  

#### 配置草案

```yaml
config:
  finding_packages: []          # 默认 = scan_packages
  noise_filter:
    enabled: true
    # 禁止 “outside_package => drop_all”
    weak_sink_outside_package: suppress      # suppress|demote
    terminal_outside_package: keep_demote_confidence
    library_internal_weak: suppress
    library_package_deny: []                 # 追加；谓词仍是 包+sinkFamily
    demote_plain_json_parse: true
    demote_template_without_path_evidence: true
    constructor_without_side_effect: suppress
    dedupe: exact                            # off|exact
    fan_in_rules: [SQL_Injection, Velocity_Injection, FreeMarker_Injection]
    main_sarif_min_confidence: 0.5
    main_sarif_always_include_terminal: true
    max_instances_in_sarif: 10
    emit_raw_flows: false
    emit_suppressed_file: true
    emit_low_confidence_file: true
  scoring:
    separate_severity_confidence: true
```

#### benchmark 漏斗字段

```text
flowsRaw
flowsSuppressedByReason{...}
flowsLowConfidenceByReason{...}
findingsAfterExactDedupe
findingsAfterFanIn
mainSarifResults
lowConfidenceResults
suppressedResults
# 不变量：可解释的 count 关系（文档化公式，允许 finding 聚合导致非简单相加）
topSinkLocations, topSuppressedPackages
authSource: asm_route|worker|unavailable
```

#### 风险与缓解

| 风险 | 缓解 |
|---|---|
| 包名 hard-drop 漏掉第三方库内 `Runtime.exec` | 强度矩阵：终态包外 KEEP |
| fan-in 丢掉真入口 | 完整 instances sidecar + 代表项选择策略 |
| 同方法多 sink 被合并 | `sinkStmtIndex` 必进 key + 单测 |
| Velocity 条件过松 | 模板串 + 入口 **不充分**；要 evidence/fan-in 门闩 |
| demote 与“降一个数量级”纠缠 | 主 SARIF 门槛 + 三层产物，数量级指 **main SARIF**，不是 raw |
| 双重惩罚 | P1 规则 transfer 化后与 demote 表对齐 |
| Reporter 分叉过滤 | 单一 Pipeline |

#### 完成标准 / 合并门槛（修订）

**结构与正确性**

- [ ] `CapturedTaintFlow` 关键字段进入 pipeline；`Vulnerability` 不再是唯一内部模型。  
- [ ] `SinkLocationKey` 含 `sinkStmtIndex`；同方法两处相同 sink 签名 → **两个** finding。  
- [ ] source 为 `instances[]`；sidecar 可追溯完整列表（>N 不截断丢失）。  
- [ ] 代表 instance 按公开 route / 低 auth / 证据 / 语义 / 字典序选择；severity 取 instance 最大。  
- [ ] `noise_filter.enabled=false` 恢复 raw 数量**与**稳定身份。  
- [ ] scorer **不**依赖 host Tai-e `World`。  
- [ ] Reporter 无独立过滤逻辑；PoC 不对随意代表 source 生成。  

**策略（默认开启 P0.6-B 起）**

- [ ] 包外弱构造/裸 parse → suppressed，不进主 SARIF。  
- [ ] 包外 `Runtime.exec` / `Statement.executeQuery` 等终态 → **合成测试必须保留**（可低 confidence）。  
- [ ] 汉得：库内 `oracle.xml` / `jackson.databind.deser` / `fastjson.serializer` 弱 sink 主 SARIF 为 0。  
- [ ] 汉得：162 条 Velocity 在无路径证据且高 fan-in 时 **不得** CRITICAL（主 SARIF 或仅 low-confidence）。  
- [ ] 汉得：`getPictureBase64` 保留；P0.6-C 后应具备 URL→`openStream` 局部副作用证据。  
- [ ] SQL 按 sink 位置收敛到可审阅代表 finding，instances 完整可查。  

**数量与分层**

- [ ] **主 SARIF** 相对 raw 7,316 显著下降（目标：至少一个数量级，或明确达到可配置 `main_sarif` 门槛后的稳定集合）；验收看 **main**，不看“只做 package filter 后的 1646”。  
- [ ] 下降主要来自：弱 sink suppress + demote 出主视图 + exact/fan-in 聚合，**而不是**删除终态包外 sink。  
- [ ] `main + low-confidence + suppressed` 与漏斗 **可解释一致**（允许因聚合导致 finding 数 < flow 数）。  
- [ ] 离线 replay 汉得 `worker-result.json` 可回归上述断言。  

**测试与文档**

- [ ] 单测覆盖：强度矩阵四象限、stmtIndex 分裂、fan-in 代表项选择、auth 无 World、filter 开关。  
- [ ] 本节可独立实现，无需聊天上下文。  

#### 可行性摘要（评审对照）

| 项 | 结论 |
|---|---|
| 业务包信号 | 有条件：只 hard-drop 弱 sink |
| 库包表 | 有条件：包 + sink family |
| 去重/聚合 | 可行：必须 `sinkStmtIndex` + instances |
| 语义 demote | 部分：签名级 B；副作用/常量 C |
| 评分 | 可行：severity/confidence 分离 |
| source 收紧 | 部分：类型/index 先做；header 名常量证据不足则暂缓 |
| 配置指标 | 可行：四层产物 + 漏斗 |

---

## 4. P1：解除 Tai-e 日志协议依赖并控制 TFG 产物

完成标准：默认结果转换不依赖解析 `tai-e.log`，保留完整 flow identity；最终 JByteScanner 报告目录不保留无需求的全局 TFG。若原版 Tai-e 0.5.4 内部无法通过公开配置跳过 TFG 构建，则暂时接受并单独记录该开销，不为此修改 Tai-e 源码。

### P1.1 直接消费 `capturedTaintFlows`

`JBSScanEntryPointPlugin` 已经捕获 `Set<TaintFlow>`，下一步直接转换为 JByteScanner finding input，保留：

```text
sourceMethod, sourceIndex/sourceKind,
sinkMethod, sinkIndex, sinkStmt, containerMethod,
route candidates, stable statement identity
```

- `tai-e.log` parser 保留为兼容/诊断 fallback，不再作为主结果协议。
- 移除主流程中的 `Files.readAllLines(tai-e.log)`。
- 不再用字符串正则重建已经存在的对象信息。

### P1.2 不修改 Tai-e 的结果桥接和输出控制

当前阶段不在 Tai-e fork/源码中增加 `report-flow-lines`、`dump-tfg` 等开关。替代方案全部在 JByteScanner 内实现：

1. 复用现有 `JBSScanEntryPointPlugin.onFinish()`，从 Tai-e 公开的 solver result 取得 `Set<TaintFlow>`。
2. 进程内模式直接转换该集合；worker 模式由 JByteScanner plugin 在结果清理前写入结构化 JSONL/二进制中间文件，主进程读取该文件。
3. `tai-e.log` parser 仅保留为兼容和诊断 fallback，不再作为主结果协议。
4. 通过 JByteScanner 自己的日志配置抑制不需要的 Tai-e INFO 输出；不得依赖修改 Tai-e logger 调用点。
5. Tai-e 产生的全局 TFG 放入隔离临时目录；默认扫描结束后不纳入正式报告并按保留策略清理。
6. 如果 Tai-e 0.5.4 没有公开开关阻止 TFG 构建，则保留其运行时间并记录为 `upstreamTfgMs`，不承诺通过 JByteScanner 外围改动消除这部分计算。

**qiqin 预期收益与限制**：

- 可以移除读取整个 `tai-e.log`、正则重建 flow 和重复结果转换的开销。
- 可以减少日志文件和最终报告目录体积。
- 在不修改 Tai-e 的前提下，不能把当前约 8.41 秒 TFG 时间列为必然可消除的收益；该项改为观测指标，等待未来上游公开配置支持或用户重新允许 Tai-e 改动后再处理。

---

## 5. P1：规则语义降噪和规则迁移 v4

完成标准：构造/解析 API 不再被直接等同于具有安全副作用的漏洞 sink；规则升级可以安全停用过时的 bundled rule。

### P1.3 Fastjson 普通解析降级为 transfer/intermediate

qiqin 的 7,026 条 Deserialization 中，主要 sink 为：

- `JSONObject.parseObject(String)`：5,764
- `JSON.parse(String)`：1,261

普通 JSON parse 不应默认成为高置信度反序列化漏洞。只有存在以下证据时才升级：

- AutoType/动态类型能力启用。
- type name、`Class` 或 `Type` 参数可控。
- 多态类型元数据可控。
- 到达已知危险类型实例化或 gadget-compatible 行为。

普通 parse 作为 transfer 或低置信度 evidence，不直接产生高危 SARIF result。

### P1.4 URL/URI/File 构造器改为 transfer

- `new URL(String)`、`new URI(String)` 只构造对象，不产生网络请求。
- `new File(String)`、`Paths.get(...)` 只构造路径，不产生文件副作用。

终态 sink 应为：

- SSRF：`connect/openConnection/openStream/execute/send/exchange` 等真实网络执行 API。
- Path Traversal：文件读取、写入、删除、移动、解压落盘等真实文件副作用 API。

### P1.5 规则身份、来源和撤销能力

当前 v3 migration 只会添加或补全规则。如果 v3 将高噪声规则写入项目 `rules.yaml`，未来仅修改 `default_rules.yaml` 不会自动撤销这些规则。

v4 schema 应增加：

```text
rule id
origin: bundled/user
introducedVersion
deprecatedVersion
replacementRuleId/enabled
```

- bundled rule 使用稳定 ID，而不是仅用 signature 判断身份。
- source/sink identity 包含 index/type，支持同一 method 的不同敏感位置。
- migration 可以停用或替换旧 bundled rule，但不得删除用户自定义覆盖。
- migration 写文件使用临时文件 + atomic move；保存失败必须让迁移失败，不能只记录日志后继续使用已升级的内存状态。

### P1.6 Sink pre-scan 精确到 descriptor

将当前 `owner + methodName` key 升级为：

```text
owner + methodName + JVM descriptor
```

避免“应用只调用了某个安全 overload，却激活同名危险 overload 规则”。同时将 sink、persistent source、model accessor、route/secret metadata 的 ASM 扫描合并到统一 class index，避免多轮打开同一 JAR。

---

## 6. P1：Canonical Finding、SARIF 和 PoC

完成标准：一个逻辑问题只报告一次；报告数量由风险语义决定，而不是由原始 flow、route 数或重复 class 数决定。

### P1.7 Finding 聚合

建议 canonical key：

```text
(ruleId, sourceMethod, sourceIndex,
 sinkMethod, sinkIndex, sinkStmt,
 routeId)
```

聚合字段：

```text
flowCount, routeVariants, sourceIndices, sinkIndices,
representativePath, alternativePathCount, confidence
```

qiqin 的阶段性目标：

- 先消除 1,355 条完全相同 SARIF result。
- source/sink 级逻辑结果由 10,826 收敛到约 4,380 量级，再由修正后的规则语义进一步筛选。
- exact duplicate 始终为 0。

### P1.8 SARIF 修正

- 聚合完成后使用 Jackson streaming generator 输出，避免构建完整 DOM。
- 添加稳定 `partialFingerprints`。
- method signature 放在 `logicalLocations`，不能继续作为 `artifactLocation.uri`。
- 有源码映射时再填写文件 URI 和 line/column。
- 默认展示代表路径，完整替代路径按需导出。

### P1.9 Route-aware PoC

当前 `PoCReporter.findRoute()` 通过 class substring 和 method name 返回第一条 route，不能可靠处理 overload 和同方法多路由。

只有满足以下条件才生成 PoC：

1. finding 已聚合。
2. 有精确 Java method/routeId 映射。
3. source index 已知。
4. 参数绑定到 path/query/header/body 的位置已知。
5. payload 可以放入对应请求位置。

同一 finding 对应多个 route 时，输出一个 finding 和多个 request variant，不复制漏洞块。qiqin 当前约 10,739 个 vulnerability block、仅约 634 个 URL，这一比例必须显著改善。

---

## 7. P2：SecretScanner 和增量索引

### P2.1 Secret finding 去重和 suppressor

Canonical key：

```text
(secretType, normalizedValue, class/method/config path)
```

- 按 class byte SHA-256 去重，避免重复 JAR 中同一个 class 被重复扫描。
- 抑制字符表、随机字符集、JSONPath、算法注册名、日志模板、`${ENV}`/`${property}` 占位符。
- Hardcoded Secret 与 Secret Configuration Reference 分开报告。
- 输出 raw、unique、suppressed 数量和 suppress reason。
- 报告改为 buffered streaming。

### P2.2 ClassIndex 持久化和增量缓存

> 最小可用 Unified ClassIndex 已前移到 P0/Milestone A。本阶段是在统一索引协议上增加持久化、跨次扫描复用和完整缓存失效策略，而不是到 P2 才开始统一 ASM。

缓存键：

```text
(path, size, mtime, SHA-256, scannerSchemaVersion)
```

统一索引提供：

- class/package 和 artifact 冲突信息
- route metadata
- source/sink/transfer call-site
- persistent source/model accessor
- secret constant/string candidate

目标是每个唯一 class byte 默认只解析一次，各模块消费结构化索引，不再分别多轮遍历 JAR。

---

## 8. 里程碑和合并门槛

### Milestone A：Large Project Preflight

- [ ] 最小 Unified ClassIndex（每个唯一 class byte 单次解析）
- [ ] Route/entry/source canonicalization
- [ ] application entry 注入去重
- [ ] classpath-preflight.json
- [ ] exact artifact 去重和版本选择记录
- [ ] mixed JAR application scope
- [ ] ecology 可根据预算选择单次或分区模式，不发生无诊断、无结果的失控 OOM
- [ ] **P0.6** 精度管线（修订版）：FindingPipeline、`SinkLocationKey`+`sinkStmtIndex`、instances 聚合、sink 强度矩阵、四层产物、severity/confidence 分离、worker auth 不依赖 host World

### Milestone B：Structured Flow Pipeline

- [ ] 直接消费 `Set<TaintFlow>`
- [ ] source/sink index 全链路保留
- [ ] JByteScanner 默认直接消费结构化 flow，正式报告目录不保留无需求的全局 TFG
- [ ] worker JVM、heap dump、GC 和阶段资源指标
- [ ] 单独记录原版 Tai-e 的 `upstreamTfgMs`；不把约 8 秒 TFG 开销下降设为当前硬门槛

### Milestone C：Semantic Findings

- [ ] Fastjson/URL/URI/File 规则重构（与 P0.6.4 报告层 demote 对齐，最终以规则 transfer/终态分离为准）
- [ ] 模板引擎（Velocity 等）规则：模板串 vs context 语义拆分
- [ ] rules schema v4 和 bundled rule 撤销能力
- [ ] canonical finding 和 exact duplicate=0（在 P0.6 FindingKey_v0 之上升级完整 identity）
- [ ] SARIF streaming/fingerprint/logical location
- [ ] route-aware PoC

### Milestone D：Incremental and Secret Quality

- [ ] SecretScanner 去重和 suppressor
- [ ] artifact/class 持久化增量缓存
- [ ] 缓存 schema/version 和失效策略
- [ ] ClassIndex 扩展点与跨次扫描复用

---

## 9. 固定回归指标

每次对 ecology 和 qiqin 运行后生成 `benchmark.json`，至少包含：

```text
executionMode, resourceBudget
partitionsTotal, partitionsCompleted, partitionsFailed
classCoverage, methodCoverage, entryCoverage, routeCoverage
worldCompleted
worldMs, ptaMs, tfgMs, reportMs
peakHeapBytes, peakRssBytes
appClasspathRaw/Selected
libraryClasspathRaw/Selected
classRaw/Unique
duplicateClassGroups
entryRaw/Unique
sourceRaw/Unique
reachableMethods, callGraphEdges
flowsRaw, flowsSuppressedByReason, flowsLowConfidenceByReason
findingsAfterExactDedupe, findingsAfterFanIn
mainSarifResults, lowConfidenceResults, suppressedResults
canonicalFindings, sarifResults
pocFindings, pocRequestVariants
secretsRaw/Unique/Suppressed
artifactBytes
resultsByRuleAndTopSink
topSinkLocations, topSuppressedPackages
authSource
```

### 发布门槛

**ecology10**：

- 不要求在固定常规内存配置下单次完成全量 PTA；单次全量完成作为压力测试和长期优化指标。
- preflight 必须在分析前给出规模、预计风险和推荐的单次/分区执行模式。
- 不发生无完整诊断、无阶段结果、无恢复信息的失控 OOM。
- 分区模式能够完成用户选择的扫描范围，并报告类、方法、入口和路由覆盖率以及失败批次。
- entry/source canonical duplicate 为 0，重复输入不占用分析预算。
- classpath 选择和 mixed JAR 决策完全可追溯。

**qiqin-srm**：

- JByteScanner 正式报告目录默认不保留全局 DOT；原版 Tai-e 无公开关闭能力时允许在隔离临时目录生成并记录其开销。
- SARIF exact duplicate 为 0。
- PoC 只为有精确 route 和参数位置的 finding 生成。
- 峰值低于当前约 5.6 GB；第一阶段目标不高于约 5.2 GB。
- 结果类别不再由普通 Fastjson parse、URL/URI/File 构造器主导。

**汉得 SRM（P0.6 精度回归，评审修订）**：

- **主 SARIF**（非 raw）在默认 `noise_filter` 下相对 7,316 显著下降；下降不得依赖“删除包外终态 sink”。
- 库内弱 sink（`oracle.xml` / jackson deser / fastjson serializer 等 + 构造/裸 parse）默认进 suppressed，不进主结果。
- 包外终态 sink 合成用例（如库内 `Runtime.exec` / `executeQuery`）必须仍可见（可低 confidence）。
- TP `getPictureBase64` 保留；P0.6-C 后带同方法网络副作用证据。
- Velocity：高 fan-in + 无路径证据时不得 CRITICAL。
- SQL：按 `SinkLocationKey` 聚合；完整 `instances` 可在 sidecar 追溯。
- `benchmark.json` 含 raw / suppressed / low-confidence / main 漏斗与 reason 计数。
- worker 模式 auth 不依赖 host `World`。

## 10. 优先级约束

在 Milestone A 和 B 完成前，原则上不继续大规模增加默认 source、sink、transfer 或 fallback entry，也不再新增独立遍历 JAR 的 ASM 扫描器。当前阶段禁止以完成路线图为由修改 Tai-e 0.5.4 源码或维护私有 fork；与 Tai-e 的适配必须放在 JByteScanner runner、plugin、配置和结果桥接层。新增字节码事实应先扩展统一 ClassIndex；新增规则必须同时提供：

- 正例和反例测试。
- source/sink/transfer 的精确 index。
- 对两个大型样本的结果数量和峰值影响。
- 可迁移、可禁用、可撤销的稳定 rule ID。

**精度与召回（P0.6 修订）**：

- 主 SARIF 优先可人工 triage；raw / suppressed / low-confidence 保留完整线索。
- **禁止**无条件 hard-drop 全部业务包外 flow。
- 扩大召回：关闭 `noise_filter`、放宽 `finding_packages`、降低主 SARIF confidence 门槛或导出 sidecar——**不要**把库内弱构造/裸 parse 重新灌回默认 CRITICAL 队列。
- 实施顺序固定为 **P0.6-A → B → C → D**；未完成 A 不得默认开启 B 的 suppress。
