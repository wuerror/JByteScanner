# JByteScanner 迁移至 Tai-e 引擎计划 (All-in Tai-e 原生污点分析)

## 1. 迁移背景与架构愿景
当前 JByteScanner 基于 Soot 框架进行静态分析，在面对现代混合编译语言（Scala, Kotlin）及复杂框架时，Soot 极其严苛的封闭世界假设导致 `jb` 阶段频发 `resolving level DANGLING` 异常，严重影响资产发现与漏洞扫描的存活率。

南京大学开源的 **Tai-e** 框架原生支持不完整类路径（Phantom Classes）、对 invokedynamic 和 Lambda 支持极佳。

**核心决策：全面拥抱 Tai-e 原生能力 (Route B)**
经过评审，为了彻底摆脱历史包袱并大幅提升分析精度，本项目决定进行**全量迁移**：
1. **API 资产发现 (Asset Discovery)**：完全使用 Tai-e 原生的 `JClass` 和 `Annotation` API 重写，剔除 Soot。
2. **污点分析引擎 (Taint Engine)**：**废弃**原先基于 Soot 和 CHA 手写的 `WorklistEngine`、`ReachabilityAnalyzer` 和 `Leaf Summary` 优化逻辑。**全面转向 Tai-e 官方基于指针分析 (Pointer Analysis) 的高精度污点分析插件。**

这不仅能解决崩溃问题，还能将扫描器的准确率（降低误报）提升到一个全新的维度。

---

## 2. 详细迁移步骤 (AI 接力开发指南)

由于存在多个 AI 接力开发，本计划严格划分为独立、可验证的阶段。**在每个阶段未获人工确认前，严禁越界修改代码。**

### 阶段 1：环境与依赖彻底切换 (Step 1)
*   **目标**：完成依赖树的清理，确保项目能够基于 Tai-e 成功编译。
*   **行动项**：
    1. 修改 `pom.xml`：**彻底删除** `org.soot-oss:soot` 依赖。
    2. 修改 `pom.xml`：引入 Tai-e 官方稳定版依赖 (`net.pascal-lab:tai-e:0.5.2`)。
    3. 清理废弃代码：删除 `src/main/java/com/jbytescanner/core/SootManager.java`。
    4. 修复因删除 Soot 导致的全局编译错误（暂时注释掉报错的方法体，确保 Maven 编译通过）。

### 阶段 2：引擎初始化与上下文构建 (Step 2)
*   **目标**：建立 Tai-e 的全局运行上下文 (`World`)。
*   **行动项**：
    1. 新建 `com.jbytescanner.core.TaieManager` 类。
    2. 实现配置映射：将原先的 `targetAppJars` 映射为 Tai-e 的 `--app-class-path`；将 `libJars` 和 `depAppJars` 映射为 `--class-path`。
    3. 修改 `JByteScanner.java` 的全局初始化逻辑，使其调用 `TaieManager` 初始化引擎。

### 阶段 3：API 资产发现模式重写 (Step 3) - 独立可测
*   **目标**：恢复 `api` 模式的路由提取能力，且输出格式 (`api.txt`) 必须与老版本 100% 一致。
*   **行动项**：
    1. 重写 `RouteExtractor.java`：使用 Tai-e 的 `JClass`, `JMethod`, `Annotation` 替换所有 Soot API (`SootClass`, `AnnotationTag` 等)。
    2. 重写 `DiscoveryEngine.java` 以适配新的 `TaieManager`。
    3. **验证点**：运行 `-m api`，对比生成的 `api.txt` 是否与 Soot 版本完全一致（包括 Spring, JAX-RS, Servlet 路由）。

### 阶段 4：配置翻译与规则转换 (Step 4)
*   **目标**：将 JByteScanner 的规则转换为 Tai-e 污点分析插件可读的配置。
*   **行动项**：
    1. 重写 `RuleManager.java`：解析用户自定义的 `rules.yaml`。
    2. 核心转换：将 JByteScanner 格式的 Sink/Source 转换并动态生成 Tai-e 的 `taint-config.yml` 格式（Tai-e 污点分析依赖特定的 YAML 结构描述 sources, sinks, transfers）。
    3. 将 `api.txt` 中的入口方法签名，翻译为 Tai-e 要求的 `<com.example.Controller: ReturnType methodName(ParamTypes)>` 格式，并注册为 Tai-e 的 Entry Methods。

### 阶段 5：污点分析引擎替换 (Step 5) - 核心重构
*   **目标**：彻底丢弃手写引擎，对接 Tai-e 原生指针分析。
*   **行动项**：
    1. **删除历史资产**：删除原有的 `InterproceduralTaintAnalysis`, `WorklistEngine`, `ReachabilityAnalyzer`, `AnalysisState`, `MethodSummary` 等包和类。
    2. 重写 `TaintEngine.java`：
        *   配置并启动 Tai-e 的分析通道 (Analyses)：依次执行 `cg` (CallGraph, 建议开启上下文敏感的指针分析如 `2-obj` 或默认 `pta`) 和 `taint` (Taint Analysis)。
        *   获取 Tai-e 污点分析的输出结果 (`TaintFlow` 或漏洞报告)。
    3. 结果适配：将 Tai-e 吐出的数据流路径，重新包装为 JByteScanner 的 `com.jbytescanner.model.Vulnerability` 模型。

### 阶段 6：评分、报告层对接与全链路测试 (Step 6)
*   **目标**：确保红队战术模块（Scorer, Secret Scanner, PoC Generator）与新模型完美咬合。
*   **行动项**：
    1. 确保 `VulnScorer` (R-S-A-C 模型) 能够基于新引擎产出的 `Vulnerability` 正确打分。
    2. 确保 `AuthDetector` 能够基于 Tai-e 的 `JMethod.hasAnnotation()` 正确识别鉴权注解。
    3. 确保 `SarifReporter` 和 `PoCReporter` 正常生成文件。
    4. 执行端到端的 `scan` 模式测试，验证从 JAR 输入到 SARIF/PoC 输出的全流程。

---

## 3. 接力开发规范 (AI Handoff Protocol)
1. **单步执行**：每次交互仅执行一个阶段 (Step)。
2. **状态确认**：完成一个阶段后，必须使用 `mvn clean compile`（或相关测试）验证当前阶段的代码已无语法错误，并向人类报告状态。
3. **隔离重构**：如无必要，坚决不动 `SecretScanner`, `PoCGenerator`, `VulnScorer`, `SarifReporter` 等不依赖底层 IR 框架的外围业务代码。