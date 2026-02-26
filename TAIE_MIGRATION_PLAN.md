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

### 阶段 1-3：环境切换、引擎初始化与 API Mode 适配（可合并执行）
*   **目标**：完成 Tai-e 依赖引入，构建全局运行上下文 (`World`)，并在不破坏原有 `JarLoader` 业务包推断能力的前提下，使用 Tai-e 原生能力重写 API 资产发现，同时解决由于配置不当导致的性能和资源占用过高问题。
*   **行动项**：
    1. **依赖调整**：修改 `pom.xml`，引入 Tai-e 官方稳定版依赖 (`net.pascal-lab:tai-e:0.5.2`)。同时彻底删除 `org.soot-oss:soot` 依赖。删除 `src/main/java/com/jbytescanner/core/SootManager.java`。
    2. **保留核心能力（必须严格遵守）**：在重构初始化流程时，**必须完全保留 `JarLoader.java` 中的 `inferBasePackage`（自动推断业务包名）能力**。依然只将推断出的业务包或包含业务代码的 classes 作为 `targetAppJars`（映射到 Tai-e 的 `--app-class-path`），将其他的依赖库（`depAppJars` 和 `libJars`）映射为 `--class-path`。
    3. **上下文构建 (`TaieManager.java`)**：
        *   **【性能优化点 1】避免 `--input-classes all`**：绝对不能添加 `--input-classes all` 参数。Tai-e 默认只会将 `--app-class-path`（即我们的 `targetAppJars`）上的类视为 `application classes`。这样可以保证 `World.get().getClassHierarchy().applicationClasses()` 只返回业务类，避免全量扫描依赖。
        *   **【性能优化点 2】谨慎使用 `-pp`**：如果仅运行 `api` 模式（提取注解），可以暂不添加 `-pp` 参数，避免加载整个 JVM rt.jar，进一步加快构建速度。
    4. **API 资产发现模式重写 (`DiscoveryEngine.java` & `RouteExtractor.java`)**：
        *   **重写 `RouteExtractor.java`**：使用 Tai-e 的 `JClass`, `JMethod`, `Annotation` 替换所有 Soot API。
        *   **【性能优化点 3】避免触发不必要的 IR 构建**：在提取参数名时，不要调用 `sm.getParamName(i)`（该方法会导致当前方法立刻触发 Bytecode 到 Jimple/Tai-e IR 的转换）。直接使用 `"arg" + i` 作为占位符，或者通过捕获异常的方式谨慎处理，以保障扫描极速。
        *   **【性能优化点 4】缩小 `web.xml` 扫描范围**：修改 `DiscoveryEngine.java`，不要把 `libJars` 加入 `scanJars`，让 `WebXmlParser` 仅扫描 `targetAppJars`，避免无意义的全局 JAR 遍历。
        *   **验证点**：运行 `-m api`，对比生成的 `api.txt` 是否与 Soot 版本结构一致。

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