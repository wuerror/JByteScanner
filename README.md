# JByteScanner (Red Team Edition)

**JByteScanner** 是一款专为 **红队 (Red Team)** 和 **渗透测试人员** 设计的 Java 字节码静态分析工具。

它不同于传统的企业级 SAST 工具（如 SonarQube），不追求代码规范或 100% 的覆盖率。**JByteScanner 的唯一使命是：快速挖掘可实际利用的高价值漏洞。**

无需源代码，直接对部署的 `.jar` 或 `.war` 包进行深度扫描，支持 Spring Boot Fat JAR 自动解压分析。

---

## 🚀 核心特性 (Red Team Features)

*   **无需源码**: 直接分析 Bytecode (字节码)，完美适配现场黑盒/灰盒审计场景。
*   **战术情报**:
    *   **Secret Scanner**: 深度挖掘硬编码密钥、Token 和配置文件中的凭证。
    *   **Offensive SCA**: 识别高危组件（如 Log4j 2.14, Fastjson 1.2.24）并关联 CVE。
*   **可利用性优先**:
    *   **漏洞评分**: 基于可达性（公网 API vs 内部方法）和利用难度（无过滤 vs 强过滤）进行评分。
    *   **PoC 生成**: 自动生成**可直接导入 Burp Suite** 的 Raw HTTP Request 包。
*   **深度利用链挖掘**:
    *   **Gadget suggest**: 根据依赖推荐当前可用的已知gadget。
    *   **Auth Bypass**: 分析 Spring Security 配置与 Controller 映射的差异，发现未授权访问接口。（未实现）
*   **交互式审计**: 提供 REPL Shell，允许专家手动查询调用图（`path source sink`），弥补自动化工具的盲区。（未实现）
*   **高性能引擎**:
    *   **ASM 资产发现**: 无需构建全局 IR 即可快速提取 API、字符串与组件信息。
    *   **Tai-e 0.5.4 新前端**: 使用 OOPSLA'25 的 Java 字节码前端生成 Tai-e IR，不再依赖 Soot 前端。
    *   **原生指针/污点分析**: 基于 Tai-e PTA 与 taint plugin 构建调用图和数据流。
    *   **Phantom Class 容错**: 缺失可选依赖时保留 phantom class 并继续分析。

---

## 🛠️ 快速开始

### 1. 构建项目

确保已安装 Maven 和 **JDK 17+**（Tai-e 0.5.4 的最低运行版本）。

```bash
git clone https://github.com/wuerror/JByteScanner.git
cd JByteScanner
mvn clean package -DskipTests
```

构建完成后，在 `target/` 目录下会生成 `JByteScanner-1.5.0.jar`。

### 2. 运行扫描

使用 `java -jar` 命令运行工具。工具会在扫描的目标目录生成一个`.jbytescanner` 存放生成的报告

**轻量扫描:**

-m api模式，此模式下会完成三项工作：提取api，扫描硬编码，根据现有的依赖推荐java-chains中可以打的gadget

生成api.txt，secrets.txt，gadgets.txt，rules.yaml

```bash
# 仅提取 API 路由列表 (api.txt)
java -jar JByteScanner-1.5.0.jar /path/to/app.jar -m api
```

api.txt格式如下

```
options /path methodsign | paramjson
```

可通过`awk '{print $2;}' test_jars/.jbytescanner/api.txt`获取api路径字典，context路径需要人工补充

**修改source或者sink**

提取的api.txt会作为全量扫描的source来源，对于通过注解鉴权的情况，提供`--filter-annotation`用于选择含有关键词的注解。

比如获取匿名可访问的接口

```
java -jar JByteScanner-1.5.0.jar -m api --filter-annotation AnonymousValidator /path/to/app.jar
```

可存在多个关键词比如：`--filter-annotation aa --filter-annotation AnonymousValidator bb` 是或的关系

也可以人工筛选api.txt条目

对于sink,直接修改生成的rules.yaml。第二次跑，或者再跑全量时会首先加载当前项目目录.jbytescanner下的rules.yaml。也可以通过`-c`选项指定

**全量扫描 (漏洞挖掘):**

-m scan或者什么都不带。如果.jbytescanner目录下已经有api.txt那么会跳过phase2

Tai-e 指针分析和调用图构建阶段在大型项目上可能耗时较久

```bash
# 扫描单个 Jar或者一个目录 (执行完整扫描: 资产发现 + 漏洞分析 + 战术情报)
java -jar JByteScanner-1.5.0.jar /path
```

若存在漏洞，结果会输出到result.sarif文件

生成的示例请求会在generated_pocs.txt。（可能会有错误）

**交互式模式 (未实现):**

```bash
# 扫描结束后进入 REPL Shell
java -jar target/JByteScanner-1.5.0.jar /path/to/app.jar --interactive
```

---

## 📅 开发路线图 (Roadmap)

### 已完成 (Core Engine)
- [x] **Phase 1-5**: 基础架构、配置管理、ASM 资产发现、Tai-e 集成、SARIF 报告。
- [x] **Phase 6**: 性能优化（结构化状态、反向剪枝、强依赖隔离）。
- [x] **Phase 7**: 高级分析引擎（Worklist 迭代引擎、方法摘要、叶子节点优化）。
- [x] **Phase 8: 战术情报 (Tactical Intelligence)**: Secret 扫描、漏洞评分、Smart PoC 生成。

### 进行中 (Advanced Exploitation)
- [ ] **Phase 9: 深度利用链**
  - [ ] **Auth Bypass**: 鉴权绕过检测（Config vs Code）。
  - [ ] **Gadget Miner**: 反序列化利用链挖掘。

- [ ] **Phase 10: 交互与 SCA**
  - [ ] **Offensive SCA**: 攻击型组件指纹识别。
  - [ ] **Interactive Shell**: 内存调用图查询 REPL。

