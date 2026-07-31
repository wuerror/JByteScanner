# JByteScanner 迁移至 Tai-e 引擎 — 完成记录

> **状态：已完成** | 适用分支：`feature/taie-migration`

## 1. 迁移概述

本项目已从 Soot 4.5+ 全面迁移至 **Tai-e 0.5.4**（南京大学 OOPSLA'25），同时保留 ASM 用于轻量字节码资产发现。

| 组件 | 迁移前 | 迁移后 |
|---|---|---|
| API 资产发现 | Soot `jb` phase | **OW2 ASM** (AsmRouteExtractor) |
| 语义分析引擎 | Soot SPARK/CHA + 手写 WorklistEngine | **Tai-e 0.5.4** PTA + taint plugin |
| 中间表示 | Soot Jimple | Tai-e SsaIR |
| 调用图构建 | CHA (默认) / SPARK | Tai-e 上下文敏感 PTA (cs:ci) |
| 污点分析 | 手写循环/工作队列 | Tai-e 原生 taint plugin |
| Phantom Class | Soot phantom refs | Tai-e 原生 phantom class |

## 2. 架构设计原则

- **Tai-e 不改源码**：以原版 0.5.4 JAR 作为第三方分析内核，在 JByteScanner runner、plugin 和结果桥接层完成适配。
- **ASM 与 Tai-e 分层**：ASM 负责字节码事实提取（路由、密钥、组件），Tai-e 负责语义可达性判断（指针分析、污点传播）。两者在 classpath 上游共享 `ClasspathPlanner` 的 artifact mediation 结果。
- **Worker 隔离**：Tai-e 的 World 构建、PTA 和 taint 运行在独立 JVM 子进程 (`TaieWorkerLauncher`) 中。

## 3. 迁移完成清单

### 阶段 1-3：环境切换、引擎初始化与 API Mode 适配 ✅
- [x] 引入 Tai-e 0.5.4 依赖 (`pascal-lab:tai-e:0.5.4`)
- [x] 彻底删除 Soot 依赖和 `SootManager.java`
- [x] 保留 `JarLoader.inferBasePackage()` 自动推断业务包能力
- [x] 实现 `TaieManager` / `TaieWorkerLauncher` 上下文构建
- [x] 默认不加载全部 input classes，仅 `targetAppJars` 为 application classes
- [x] **ASM RouteExtractor 重写**：`AsmRouteExtractor` 基于 ASM 提取路由，无需 Tai-e World
- [x] `web.xml` 扫描仅限 `targetAppJars`，不扫描 libJars

### 阶段 4：配置翻译与规则转换 ✅
- [x] 重写 `RuleManager.java`：解析 `rules.yaml` 并生成 Tai-e `taint-config.yml`
- [x] 规则从 JByteScanner 格式转换为 Tai-e 格式 (source/sink/transfer)
- [x] `api.txt` 入口方法翻译为 Tai-e Entry Methods
- [x] 规则版本迁移 (`rules_version`) 支持增量合并

### 阶段 5：污点分析引擎替换 ✅
- [x] 删除手写 Soot 引擎：`WorklistEngine`、`ReachabilityAnalyzer`、`InterproceduralTaintAnalysis` 等
- [x] 重写 `TaintEngine.java`：对接 Tai-e PTA + taint plugin
- [x] `JBSScanEntryPointPlugin` 捕获 `Set<TaintFlow>` 结果
- [x] 结果转换为 JByteScanner `Vulnerability` 模型

### 阶段 6：评分、报告层对接与全链路测试 ✅
- [x] `VulnScorer` 适配新引擎产物
- [x] `AuthDetector` 适配 Tai-e 注解 API
- [x] `SarifReporter` / `PoCReporter` / `PoCGenerator` 正常工作
- [x] FindingPipeline (P0.6) 精度管线接入
- [x] Secret Scanner + GadgetInspector 与 Tai-e 分析管线并行运行

## 4. 附加优化（迁移后持续改进）

- [x] **ClasspathPreflight (P0.2)**：SHA-256 去重、版本冲突调解、mixed JAR 提取
- [x] **Worker 资源预算**：`--max-heap-mb`、`--timeout-minutes`、HOD on OOM
- [x] **Taint Config 分片**：避免 SnakeYAML 文档大小上限
- [x] **Sink 预扫描**：裁剪 Tai-e sink 配置，避免未引用类的 phantom 警告
- [x] **Call-site 污点模式**：改善接口调用和跨库传播
- [x] **Persistent Source 建模**：缓存读取、类型化 model accessor 推断
- [x] **`api.txt` 人工白名单**：`api.txt` 存在即视为用户已编辑，不再自动覆盖
- [x] **GadgetInspector**：400+ Gadget Chain 的依赖检测与推荐
