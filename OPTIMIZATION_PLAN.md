# JByteScanner 深度优化与演进计划

本核心文档旨在规划 JByteScanner 的下一阶段优化路径。基于对当前架构的深入分析，我们识别出了关键的性能与稳定性瓶颈，并参考工业级静态分析引擎的最佳实践，制定了以下分阶段演进方案。

目标：**在保证检测准确率的前提下，将分析速度提升一个数量级，并解决在大型项目中因第三方库导致的崩溃和卡顿问题。**

---

## Phase 6: 性能与稳定性修复 (Performance & Stability)

此阶段的目标是解决当前引擎在处理中大型项目时遇到的速度慢、内存占用高和Soot兼容性崩溃的核心问题。

### Phase 6.1: 基础架构优化：结构化状态管理 (`AnalysisState`)

*   **问题**: `visitedStates` 缓存使用 `method.getSignature() + taint.toString()` 作为 Key，导致海量字符串创建、高昂的哈希计算开销和频繁的 GC。
*   **方案**:
    1.  创建 `AnalysisState.java` 类，封装 `SootMethod` 和 `FlowSet<Value>`。
    2.  重写其 `hashCode()` 和 `equals()` 方法，使用对象引用和高效哈希替代字符串比较。
    3.  将 `InterproceduralTaintAnalysis` 中的 `Set<String> visitedStates` 替换为 `Set<AnalysisState> visitedStates`。
*   **收益**: 显著降低内存占用和 CPU 开销，提升分析速度。

### Phase 6.2: 核心优化：智能剪枝 (Smart Pruning)

*   **问题**: 盲目的前向搜索会分析大量无法到达任何 Sink（漏洞点）的代码路径，浪费了 90% 以上的计算资源。
*   **方案**:
    1.  在 `ReachabilityAnalyzer.java` 中实现**反向可达性分析 (`Backward Reachability Analysis`)**。
    2.  从所有已知的 Sink 方法出发，在 Call Graph 上执行反向图遍历（BFS/DFS），标记所有“可能通向 Sink”的方法。
    3.  在 `InterproceduralTaintAnalysis` 的递归入口处增加剪枝判断：如果当前方法不在可达集合内，则直接返回，不再分析。
*   **收益**: 剪除绝大多数无效分析路径，将分析时间缩短一个数量级。

### Phase 6.3: 稳定性修复：强依赖隔离 (Strict Dependency Isolation)

*   **问题**: Soot 对某些第三方库（如 BouncyCastle, Oracle JDBC, iText）的字节码兼容性差，且大型库分析极慢。即使业务 JAR 通过“重打包（Shaded）”夹带了这些库，也会导致 Soot 崩溃或卡死。
*   **方案**:
    1.  **JAR 级降级 (已部分实现)**: 在 `JarLoader.java` 中强化逻辑，当 `scan_packages` 被指定时，未匹配的 JAR 强制降级为 `libJar`。
    2.  **Soot 级白名单 (终极方案)**: 修改 `SootManager.java`，利用 `Options.v().set_include(scanPackages)`，强制 Soot **仅为 `scan_packages` 指定的包生成方法体（Body）**，从根本上无视 JAR 包内的任何“夹带”代码。
*   **收益**: 彻底解决第三方库导致的 Soot 崩溃和卡顿问题，确保大型项目扫描的稳定性。

---

## Phase 7: 高级分析引擎演进 (Advanced Analysis Evolution)

此阶段的目标是引入更高级的分析技术，进一步提升效率和精度。

### Phase 7.1: 可生成摘要的过程内分析器 (Summarizing Intra-procedural Analyzer)

*   **问题**: 高频工具方法（如 `StringBuilder.append`, `String.format`）被重复分析成千上万次。
*   **技术挑战**: 当前的递归分析模型难以“回溯性”地应用摘要结果。
*   **方案 (分解步骤)**:
    1.  创建 `MethodSummary.java` 数据模型和 `SummaryManager.java` 缓存。
    2.  创建独立的 `SummarizingIntraproceduralAnalysis.java` 类，其唯一职责是为单个方法**生成**污点传播摘要。
    3.  在 `InterproceduralTaintAnalysis` 中集成**摘要生成**逻辑：分析完一个方法后，调用新类生成摘要并存入 `SummaryManager`。此阶段**不应用**摘要。
*   **收益**: 为下一步的 Worklist 引擎重构打下基础，并可以验证摘要生成的正确性。

### Phase 7.2: 基于工作列表的分析引擎重构 (Worklist-based Engine Refactoring)

*   **问题**: 递归深度优先（DFS）的分析架构难以应用方法摘要，且容易栈溢出。
*   **方案**:
    1.  将 `InterproceduralTaintAnalysis` 的核心逻辑重构为**基于工作列表（Worklist）的不动点迭代算法**。
    2.  在新的 Worklist 引擎中，当遇到方法调用时，优先查询 `SummaryManager`：
        *   **命中**: 根据摘要规则计算污点影响，若调用方数据流变化，则将其重新加入 Worklist。
        *   **未命中**: 将被调用方加入 Worklist 进行分析。
*   **收益**: 真正实现“一次分析，处处复用”，极大提升大规模代码库的分析效率。
