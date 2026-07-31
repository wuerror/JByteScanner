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
    *   **ASM 资产发现**: 基于 OW2 ASM 快速提取 API 路由、常量字符串与组件指纹，无需构建全局 IR。
    *   **Tai-e 0.5.4 语义分析**: 使用 OOPSLA'25 原版 Java 字节码前端构建 Tai-e IR 与 World，通过指针分析 (PTA) 和污点分析 (taint) 插件完成调用图与数据流。
    *   **Worker 隔离**: Tai-e 分析在独立 JVM 子进程中运行，主进程负责轻量资产发现与结果后处理，避免 OOM 级联崩溃。
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

`-m api` 模式完成三项工作：提取 API 路由、扫描硬编码密钥、根据依赖库推荐可打的 Gadget Chain。

生成 `api.txt`、`secrets.txt`、`gadgets.txt`、`rules.yaml`

```bash
# 提取 API 路由列表 + 密钥扫描 + Gadget 推荐 (不运行污点分析)
java -jar JByteScanner-1.5.0.jar /path/to/app.jar -m api
```

`api.txt` 格式如下：

```
METHOD /path className methodSignature | {"contentType":"...","params":["arg0:type",...],"annotations":{"arg0":"AnnotationType",...}}
```

示例：
```
GET /api/user com.example.UserController java.lang.String getUser(String) | {"params":["userId:String"],"annotations":{"userId":"PathVariable"}}
POST /api/upload com.example.FileController void upload(MultipartFile) | {"contentType":"multipart/form-data","params":["file:MultipartFile"],"annotations":{"file":"RequestParam"}}
```

可通过 `awk '{print $2;}' .jbytescanner/api.txt` 获取 API 路径字典，context 路径需人工补充。

**修改source或者sink**

提取的 `api.txt` 会作为全量扫描的 source 来源。**一旦 `api.txt` 存在，工具将其视为人工可编辑的白名单——即使 classpath 变化也不会自动覆盖。** 如需重新生成完整路由列表，使用 `-m api`。

对于通过注解鉴权的情况，提供 `--filter-annotation` 用于选择含有关键词的注解。

比如获取匿名可访问的接口

```
java -jar JByteScanner-1.5.0.jar -m api --filter-annotation AnonymousValidator /path/to/app.jar
```

可存在多个关键词比如：`--filter-annotation aa --filter-annotation AnonymousValidator bb` 是或的关系

也可以人工筛选api.txt条目

对于sink,直接修改生成的rules.yaml。第二次跑，或者再跑全量时会首先加载当前项目目录.jbytescanner下的rules.yaml。也可以通过`-c`选项指定

**全量扫描 (漏洞挖掘):**

默认模式 `-m scan`（或不带 `-m`）。如果 `.jbytescanner` 目录下已有 `api.txt`，则跳过 Phase 2 资产发现，直接使用现有 `api.txt`（尊重人工编辑）。

Tai-e 污点分析 (PTA + taint) 在大型项目上可能耗时较久，默认以独立 Worker JVM 运行（`--worker`）。

```bash
# 扫描单个 Jar 或目录 (完整流程: 资产发现 + 密钥扫描 + Gadget + 污点分析)
java -jar JByteScanner-1.5.0.jar /path
```

若存在漏洞，结果输出到 `result.sarif`，生成的 PoC 请求示例在 `generated_pocs.txt`。

**交互式模式 (未实现):**

```bash
# 扫描结束后进入 REPL Shell
java -jar target/JByteScanner-1.5.0.jar /path/to/app.jar --interactive
```

---

## 📅 开发路线图 (Roadmap)

> 详细版见 [ROADMAP.md](./ROADMAP.md)

### 已完成
- [x] **Tai-e 迁移**: 全面迁移至 Tai-e 0.5.4，移除 Soot 依赖。ASM 资产发现 + Tai-e PTA/taint 语义分析。
- [x] **轻重分离**: 轻量 ASM 资产发现（API/Secret/Gadget）独立于重量 Tai-e Worker 进程。
- [x] **Worker 隔离**: Tai-e 分析运行在独立 JVM 子进程，主进程负责结果后处理。
- [x] **Secret Scanner**: 硬编码密钥扫描（配置、常量池、熵分析、Base64）。
- [x] **Gadget Inspector**: 依赖分析 + 反序列化 Gadget Chain 推荐。
- [x] **漏洞评分**: R-S-A-C 模型 + SARIF 报告 + PoC 生成。
- [x] **Classpath Preflight**: SHA/版本校验、重复 artifact 去重、mixed JAR 处理。

### 进行中
- [ ] **P0 精度管线**: FindingPipeline、Sink 强度矩阵、四层产物（raw/suppressed/low-confidence/main SARIF）。
- [ ] **P0 Unified ClassIndex**: 统一 ASM 索引层，消除多模块重复解析。

### 计划中
- [ ] **Auth Bypass**: 鉴权绕过检测（Spring Security 配置 vs Controller 映射差异分析）。
- [ ] **规则迁移 v4**: 构造/解析 API 从终态 sink 分离为 transfer，规则身份与撤销能力。
- [ ] **增量缓存**: ClassIndex 持久化和跨次扫描复用。
- [ ] **交互式 Shell**: 内存调用图查询 REPL。

