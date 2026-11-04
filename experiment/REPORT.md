# 汉得 SRM Groovy 脚本注入 A/B 对照实验报告

日期：2026-10-27  
任务：`srm-groovy-01`（Groovy 脚本注入）  
目标：`E:\code\汉得SRM` / `E:\code\汉得SRM_src`  
模型：`opencode/deepseek-v4.1-flash`（两组相同）  
Scanner：JByteScanner 1.5.0，commit `5199a90`，JAR SHA-256 `C55AADB8...B27271CA`

## 1. 结论摘要

这是一次**单任务、单重复**的试点，结论只能作为方向性证据。

- **CLI 没有带来额外正确发现。** B 组通过 JByteScanner CLI 没有得到任何 Groovy 结果；A 组仅靠源码与字节码搜索反而多找到 1 个已核实的存储型 Groovy 根因（`Interface.mappingClass`）。
- **两组都找到了两条可直接触发 Groovy 代码执行的高价值路径**：`application-insts/param-template` 与 `interfaces/param-template`。两条均为已认证接口，不是未授权 RCE。
- **裁决阶段补充发现 1 个两组都漏掉的根因**：`ApplicationInst.mappingClass` 存储型 Groovy 注入。它与 A 组找到的 `Interface.mappingClass` 同属 FreeMarker/Groovy 模板执行链。
- **规则引擎 `POST /v1/rule-engine/run-script` 不是正常网关外部入口**：`@Permission(permissionWithin = true)` 会被网关 `GetPermissionFilter` 拒绝。B 组判定 `likely_not_exploitable` 更准确；A 组标为 `uncertain` 也可接受。直连服务端口/内网 SSRF 仍是残余风险。
- **B 组只用了 5.3 分钟就结束，未用完 30 分钟预算**，因此“B 更快”不能归因于 CLI，也不能据此认为 B 的较低召回是工具造成的。单次运行无法区分模型波动、策略差异和工具增益。
- **工具侧关键缺陷**：预扫描配置中写了 `GroovyClassLoader.parseClass` / `GroovyShell.parse` 等 sink，但生成的 `taint-config.yml` 中没有 Groovy 签名；`diagnose` 对 `GroovyClassLoader.parseClass` 返回 `invocation=no`、`rule=no`、`worker=NOT_RUN`。因此 CLI 在当前流水线下无法帮助发现本任务的 Groovy 依赖库 sink。

## 2. 实验材料与预扫描

| 项目 | 值 |
| --- | --- |
| 部署包 | 20 个 Spring Boot fat jar，25 个文件，约 4.1 GB |
| 反编译源码 | 20 个模块目录 |
| 扫描配置 | `experiment/config/rules.yaml`（复用 CA 规则：`org.hzero`、`org.srm`） |
| 预扫描 API | `2026-10-26 17:29:05` → `17:33:24`，约 4 分 19 秒 |
| 全量扫描 | `17:33:52` → `17:34:48`，约 56 秒 |
| 合并准备成本 | 约 5 分 43 秒 |
| Worker 状态 | `SUCCESS`，exitCode 0 |
| 分析规模 | 1590 条 API 路由，60 个 target app jar，1012 个 lib jar，371 条原始污点流 |
| 主报告 | 74 条；低置信 2 条；抑制 294 条 |
| 主报告构成 | Jackson 反序列化 31、Fastjson 反序列化 42、SSRF 1 |
| Groovy 主报告 | **0** |

预扫描工作区母版最终归档到 `experiment/views/master/.jbytescanner`；A 组运行时目标目录下没有 `.jbytescanner`。B 组使用从母版复制的私有工作区，副本保存在 `experiment/views/B/.jbytescanner`。

## 3. A/B 运行结果

| 指标 | A：搜索基线 | B：搜索 + CLI |
| --- | --- | --- |
| 会话 | `ses_e886...` | `ses_e851...` |
| 提交候选 | 4 | 3 |
| 已核实根因（含条件型） | 3 | 2 |
| 直接完整外部路径 | 2 | 2 |
| 存储型条件路径 | 1 | 0 |
| 误报 | 0 | 0 |
| 正确否定/不确定 | 1 条不确定（规则引擎） | 1 条正确否定（规则引擎） |
| 召回（裁决集 4 个根因） | 3/4 = 75% | 2/4 = 50% |
| 墙钟时间（自报） | 32.1 分钟 | 5.3 分钟 |
| CLI 命令 | 0 | 5 次（含 1 次 diagnose） |
| 结果文件 | `runs/A/srm-groovy-01.json` | `runs/B/srm-groovy-01.json` |

注意：A 组超出 30 分钟约 2 分钟；B 组主动提前结束。两组都不是在严格的 30 分钟截止点被强制终止，因此时间差异不代表工具效率。

## 4. 裁决后的已核实问题

### V1 ApplicationInst 参数模板 Groovy 执行（A、B 均报告，已核实）

- 入口：`POST /v1/{organizationId}/application-insts/param-template`；SITE 变体 `POST /v1/application-insts/param-template`
- 输入：`@RequestBody TemplateDTO.template`，字段无校验
- 链路：
  `ApplicationInstController.testParamReflect` → `ApplicationInstServiceImpl.testParamReflect` → `FreeMarkerHelper.invokeTemplate` → `new GroovyClassLoader().parseClass(template)` → `newInstance()` → `invokeMethod(...)`
- 关键证据：
  - `.../ApplicationInstServiceImpl.java:199-222`
  - `.../hzero-boot-interface-1.9.6.RELEASE_src/.../FreeMarkerHelper.java:69-104`
  - `srm-basic-interface-op.jar` 内确认包含 `hzero-interface-saas`、`hzero-boot-interface`、`groovy-3.0.6`
- 结论：`verified_likely_exploitable`，需要 ORGANIZATION 或 SITE 级接口权限；未执行真实请求。

### V2 Interface 参数模板 Groovy 执行（A、B 均报告，已核实）

- 入口：`POST /v1/{organizationId}/interfaces/param-template`；SITE 变体 `POST /v1/interfaces/param-template`
- 输入：`@RequestBody TemplateDTO.template`；`interfaceId` 可选，为空时仍先编译模板
- 链路：
  `InterfaceServiceImpl.debugParamTemplate` → `FreeMarkerHelper.invokeTemplate(template.getTemplate(), ...)` → `GroovyClassLoader.parseClass` → `newInstance` → `invokeMethod`
- 关键证据：
  - `.../InterfaceServiceImpl.java:1219-1264`
  - `.../InterfaceController.java:238-247`
- 结论：`verified_likely_exploitable`，同 V1 的权限条件。

### V3 Interface.mappingClass 存储型 Groovy（A 报告，已核实根因，触发条件未完全证明）

- 写入：新建/更新接口时，`Interface.mappingClass` 被 `updateOptional` 持久化，实体字段无校验注解。
- 执行：接口调用时 `AbstractInterfaceInvokeTemplate` 读取 `InvokeConfiguration.mappingClass`，交给 `HttpRequestGroovyInjector` / `HttpResponseGroovyInjector`，最终进入 `FreeMarkerHelper.invokeTemplate` → `GroovyClassLoader.parseClass`。
- 关键证据：
  - `.../InterfaceServiceImpl.java:941-949`、`1077-1087`
  - `.../AbstractInterfaceInvokeTemplate.java:120-126`
  - `.../HttpRequestGroovyInjector.java:24`
- 结论：`verified_root_cause_exploitability_conditional`。需要接口编辑权限，并需要一个已发布接口的实际调用作为触发器；`portal-testing` 是合理候选，但本次未逐层证明其一定使用同一 `mappingClass`。

### V4 ApplicationInst.mappingClass 存储型 Groovy（两组均漏，裁决补充）

- 写入：`ApplicationInstController.create` / `ApplicationInstSiteController.create` 接收 `ApplicationInst`，`saveApplication` 在更新时持久化 `mappingClass`（新增时由 `insertSelective` 写入）。
- 执行：复合接口调用时 `CompositeInterfaceInvoker` 对每个 `ApplicationInstDTO` 读取 `mappingClass`，执行 `requestDataConverter` / `responseDataConverter`，同样进入 `FreeMarkerHelper.invokeTemplate`。
- 关键证据：
  - `.../ApplicationInstController.java:70-80`
  - `.../ApplicationInstServiceImpl.java:138-170`
  - `.../CompositeInterfaceInvoker.java:131-136`、`182-186`
- 结论：`verified_root_cause_exploitability_conditional`。两组都没有把它作为独立问题提交；这是本次实验暴露出的覆盖缺口。

### V5 RuleEngine run-script（A 不确定，B 判定不可外部利用，已核实）

- 入口：`POST /v1/rule-engine/run-script`
- 输入：`RuleEngine.script`
- sink：`GroovyShell.parse` + `Script.run`，配置 `SandboxTransformer`、`NoSystemExitSandbox`、`NoRunTimeSandbox`
- 关键约束：控制器 `@Permission(permissionWithin = true)`；网关 `GetPermissionFilter` 对 `within` 接口返回 `PERMISSION_WITH_IN` 并拒绝。
- 结论：`not_externally_exploitable_via_gateway`。沙箱只拦截 `Runtime` 静态调用和 `System.exit`，并未覆盖 `ProcessBuilder`、实例方法等；如果服务端口可被直连或存在内网 SSRF，残余风险仍然存在。B 组的判定比 A 组更精确。

### V6 interface-authorization GroovyHelper（未知，未计入）

两组都提到 `interface-authorization` 的 GroovyHelper/CommonTemplate 使用存储的 `groovyTemplateCode`，但都没有在预算内找到可外部写入公共模板的 HTTP 入口。标为 `unknown`，不作为两组的命中或漏报。

## 5. CLI 行为分析

B 组执行的 5 条 CLI 命令：

1. `query ... scan-status --json` → `SUCCESS`，371 条流，74 条主报告。
2. `query ... findings --limit 500 --json` → 只有反序列化和 SSRF，无 Groovy。
3. `query ... finding --sink '<groovy.lang.GroovyClassLoader: java.lang.Class parseClass(java.lang.String)>' --json` → 0 条，`requiresTargetedDiagnosis=true`。
4. `query ... finding --sink '<groovy.lang.GroovyShell: groovy.lang.Script parse(java.lang.String)>' --json` → 0 条。
5. `diagnose ... --sink '<groovy.lang.GroovyClassLoader: ...parseClass...>' --json --timeout-minutes 4` → `invocation=no`、`rule=no`、`source=yes`、`worker=NOT_RUN`。

对诊断记录 `experiment/runs/B/diagnosis-latest.json` 的核对：

- `invocation`：在 target/dependency application bytecode 中没有找到精确的 `parseClass` 调用点。
- `rule`：sink 已配置但未写入实际生效的 taint 配置。
- `source`：至少一个 source 已写入 Tai-e 配置。
- `entry`/`reachability`/`raw_flow`：因前置阶段失败而 `unknown`。

同时检查母版工作区：

- `taint-config.yml` 有 7333 条 method 条目，但**没有任何 Groovy 签名**。
- `rules.yaml` 中确实存在 `GroovyShell.parse`、`GroovyClassLoader.parseClass` 等配置。
- 这说明当前预扫描流水线没有把依赖库中的 Groovy sink 带入实际分析。对本任务而言，`query finding` 的 0 条结果不是“安全”，而是工具证据边界。

这属于**工具已知未命中**：sink 位于 `hzero-boot-interface` 依赖库，应用代码只调用 `FreeMarkerHelper.invokeTemplate`；当前 Tai-e/规则生成没有把该调用点展开成可观测的 Groovy 污点流。CLI 的 `diagnose` 也明确返回了 `rule=no`/`invocation=no`，没有虚构断点。

## 6. 指标与解释

| 指标 | A | B |
| --- | --- | --- |
| 已核实正确问题数 | 3 | 2 |
| 错误结论 | 0 | 0 |
| `uncertain` | 1 | 0 |
| 已知问题遗漏 | 1（V4） | 2（V3、V4） |
| 召回（4 个裁决根因） | 75% | 50% |
| 正例精确率 | 3/3 = 100% | 2/2 = 100% |
| 首个正确问题耗时 | 未记录 | 未记录 |
| 总墙钟 | 32.1 分钟 | 5.3 分钟 |
| CLI 查询/诊断次数 | 0 | 5 / 1 |
| 预扫描成本 | 5.7 分钟（两组共用） | 5.7 分钟 |

- **精度**：两组都没有把不可利用路径说成可利用；B 对规则引擎的否定判断有直接网关证据，质量更高。
- **召回**：A 多找到 V3；V4 是裁决补充，不计入任何一组。由于没有预先建立的完整真值，这个 75%/50% 只针对本次裁决确认的 4 个根因，不能称为项目整体召回率。
- **时间**：B 提前结束，A 轻微超时。单次运行无法判断时间差异是否来自 CLI；也不能把 B 的低召回归因于 CLI。要做效率结论，必须让两组都跑满固定预算并至少重复 2 次。
- **工具收益**：本任务没有观察到 CLI 带来的正确发现增益。CLI 的可见收益是快速确认“没有 Groovy 结果”和暴露依赖库 sink 的盲区；可见成本是 5.7 分钟预扫描和 74 条与任务无关的反序列化/SSRF 噪声。

## 7. 有效性检查

| 检查项 | 结果 |
| --- | --- |
| 两组使用同一部署包、同一反编译源码 | 通过 |
| 两组使用同一模型、同一任务文本 | 通过 |
| B 组预扫描 Worker 为 `SUCCESS` | 通过 |
| A 组目标目录下无 `.jbytescanner` | 通过（运行前移出） |
| A 组无法访问扫描产物 | 部分通过：目录隔离 + 提示词限制，未做 OS 权限隔离 |
| B 组只通过 CLI 访问扫描产物 | 部分通过：提示词限制；无逐调用工具日志，无法完全证明未直接读取 sidecar |
| 两组预算相同 | 名义通过；B 主动提前结束，A 超出约 2 分钟 |
| 至少 2 次重复 | **未满足**（各 1 次） |
| A/B 顺序随机化 | **未满足**（先 A 后 B） |
| 裁决盲化 | **部分满足**：裁决者知道组别 |
| 工具调用/stdout/退出码完整留档 | **部分满足**：保留了最终 JSON、诊断 JSON、扫描日志；未保留子代理逐次工具调用日志 |
| 任务文本未泄露答案 | 通过 |

因此本次结果应标为**探索性试点**，不能作为“CLI 有/无审计增益”的最终统计结论。

## 8. 建议

### 工具侧

1. 修复依赖库 sink 的规则生成/分析：配置中的 `GroovyClassLoader.parseClass`、`GroovyShell.parse` 必须进入 `taint-config.yml`，并能在应用调用 `FreeMarkerHelper.invokeTemplate` 时展开到库内 sink。
2. 为“应用代码调用依赖库 helper，helper 内部执行 sink”增加回归样本；这类路径是本次 CLI 完全失效的核心原因。
3. 在 `diagnose` 中把“sink 在依赖库、调用点不在应用字节码”与“sink 根本不存在”区分得更清楚；当前 `invocation=no` + `rule=no` 容易被误读为安全。
4. 让 `query findings` 支持按 `vuln_type`/`ruleId` 聚合和摘要，减少 74 条无关反序列化结果对审计 agent 的干扰。

### 实验侧

1. 至少做 2～3 次重复，随机化 A/B 顺序；B 组应被要求用满 30 分钟预算。
2. 使用文件系统快照/只读挂载做 A/B 隔离，并保存子代理的逐次工具调用日志和退出码。
3. 增加负样本（无 Groovy 执行的模块）和“已知未命中”样本，分别评估误报与漏报。
4. 增加一个“给定精确 sink 的漏报诊断”任务，观察 B 组在知道签名时能否利用 `diagnose` 找到本次的 FreeMarker 链路。

### 安全侧

1. 优先修复 `application-insts/param-template` 和 `interfaces/param-template`：禁止请求体直接进入 `GroovyClassLoader.parseClass`，改为固定模板/白名单或强 sandbox。
2. 对 `Interface.mappingClass`、`ApplicationInst.mappingClass` 做写入校验、发布审批和执行 sandbox；不要让数据库中的模板字段成为持久化代码执行入口。
3. `rule-engine/run-script` 保持网关 `within` 限制，并补齐 `ProcessBuilder`、实例方法调用等 sandbox 缺口；不要把“网关拒绝”当作唯一防线。

## 9. 产物

- `experiment/manifest.json`：版本、哈希、扫描与运行元数据
- `experiment/tasks.jsonl`：任务文本
- `experiment/runs/A/srm-groovy-01.json`：A 组原始提交
- `experiment/runs/B/srm-groovy-01.json`：B 组原始提交
- `experiment/runs/B/diagnosis-latest.json`：B 组 `diagnose` 记录
- `experiment/views/master/.jbytescanner`：预扫描母版
- `experiment/views/B/.jbytescanner`：B 组私有工作区副本
- `experiment/adjudication/verdicts.json`：裁决表
- `experiment/target-sha256.json`：部署包文件哈希
- `experiment/logs/`：预扫描 stdout/stderr
