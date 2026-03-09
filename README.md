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
    *   **Worklist Engine**: 迭代式污点分析，避免栈溢出。
    *   **Leaf Optimization**: 智能摘要生成，大幅提升分析速度。
    *   **Strict Isolation**: 严格隔离业务代码与第三方库，防止分析引擎崩溃。
    *   **Field-Sensitive Propagation**: 支持字段污点传播，覆盖 `setter → field → getter → sink`、`new Obj(tainted)` 和静态字段读写链路；receiver 型 sink 检测按漏洞类别启用，默认不会仅因 tainted `Statement/Connection` 就报 SQLi。

---

## 🛠️ 快速开始

### 1. 构建项目

确保已安装 Maven 和 JDK 11+。

```bash
git clone https://github.com/wuerror/JByteScanner.git
cd JByteScanner
mvn clean package -DskipTests
```

构建完成后，在 `target/` 目录下会生成 `JByteScanner-1.0-SNAPSHOT-shaded.jar`。

### 2. 运行扫描

使用 `java -jar` 命令运行工具。工具会在扫描的目标目录生成一个`.jbytescanner` 存放生成的报告

**轻量扫描:**

-m api模式，此模式下会完成三项工作：提取api，扫描硬编码，根据现有的依赖推荐java-chains中可以打的gadget

生成api.txt，secrets.txt，gadgets.txt，rules.yaml

```bash
# 仅提取 API 路由列表 (api.txt)
java -jar JByteScanner-1.0-SNAPSHOT.jar /path/to/app.jar -m api
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
java -jar JByteScanner-1.0-SNAPSHOT.jar -m api --filter-annotation AnonymousValidator /path/to/app.jar
```

可存在多个关键词比如：`--filter-annotation aa --filter-annotation AnonymousValidator bb` 是或的关系

也可以人工筛选api.txt条目

对于sink,直接修改生成的rules.yaml。第二次跑，或者再跑全量时会首先加载当前项目目录.jbytescanner下的rules.yaml。也可以通过`-c`选项指定

默认规则里，SSRF 更聚焦真正发起外连的通用 URL/HTTP API，例如 `openConnection`、`openStream`、HTTP client `execute(...)`；而 `DriverManager.getConnection(...)` 会单独归类为 `JDBC_Driver_RCE`，具体是否可利用交由人工判断。`new URL(...)` / `new URI(...)` 这类仅构造对象的调用默认不作为高置信 SSRF sink。

**全量扫描 (漏洞挖掘):**

-m scan或者什么都不带。如果.jbytescanner目录下已经有api.txt那么会跳过phase2

soot生成call gragh阶段时间会比较久

```bash
# 扫描单个 Jar或者一个目录 (执行完整扫描: 资产发现 + 漏洞分析 + 战术情报)
java -jar JByteScanner-1.0-SNAPSHOT.jar /path
```

若存在漏洞，结果会输出到result.sarif文件

生成的示例请求会在generated_pocs.txt。（可能会有错误）

**交互式模式 (未实现):**

```bash
# 扫描结束后进入 REPL Shell
java -jar target/JByteScanner-1.0-SNAPSHOT-shaded.jar /path/to/app.jar --interactive
```

---

## 📅 开发路线图 (Roadmap)

### 已完成 (Core Engine)
- [x] **Phase 1-5**: 基础架构、配置管理、资产发现、Soot 集成、SARIF 报告。
- [x] **Phase 6**: 性能优化（结构化状态、反向剪枝、强依赖隔离）。
- [x] **Phase 7**: 高级分析引擎（Worklist 迭代引擎、方法摘要、叶子节点优化）。
- [x] **Phase 8: 战术情报 (Tactical Intelligence)**:
  - [x] 8.1 Secret 扫描（配置文件、常量池、Base64 编码）。
  - [x] 8.2 漏洞评分（R-S-A-C 模型）与认证检测。
  - [x] 8.3 Smart PoC 生成（Burp Suite 可直接导入）。
  - [x] 8.4 Sink 覆盖扩展（JDBC URL / DriverManager.getConnection）。
  - [x] 8.5 字段污点传播（setter 模式、静态字段、sink receiver 检测）。

### 进行中 (Advanced Exploitation)
- [ ] **Phase 8.6**: Summary 完善（`param→this`、`this→return` 摘要生成与消费）。
- [ ] **Phase 9: 深度利用链**
  - [ ] **Auth Bypass**: 鉴权绕过检测（Config vs Code）。
  - [ ] **Gadget Miner**: 反序列化利用链挖掘。

- [ ] **Phase 10: 交互与 SCA**
  - [ ] **Offensive SCA**: 攻击型组件指纹识别。
  - [ ] **Interactive Shell**: 内存调用图查询 REPL。
