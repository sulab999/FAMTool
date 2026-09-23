# macOS 原生系统审计接入

本项目采用 **Endpoint Security 原生 NOTIFY 客户端**，不是解析 `ps`/`lsof` 的推断方案，也不依赖不稳定的 `eslogger` 输出。

## 当前状态与边界

- 接入代码、原生辅助程序、GUI 接收通道、加密入库、历史查询、权限状态及测试均在项目内。
- **代码编译成功不代表已获系统授权。** 开发环境通常没有有效的 Apple 代码签名身份，以普通用户运行辅助程序检查会返回 `not_privileged`；只有在获授权签名的环境下才能完成真实 ES 采集验证。
- Apple 要求 `com.apple.developer.endpoint-security.client` entitlement、适当签名、root 权限以及 TCC 完全磁盘访问许可。仅写入 entitlement plist 或临时签名不能取得 Apple 授权。
- 目前只接入 macOS。Windows/Linux 继续普通文件通知与明确标记的推断，不宣称拥有系统审计身份。

## 管理员密码方式开启审计（OpenBSM 管道）——macOS 26 实测已不可用

> **平台结论(2026-09 实测, macOS 26 / darwin 25)**:Apple 已停用 OpenBSM 审计管线——
> `auditd` 守护进程不再存在(`audit -s` 报 invalid destination port),`/dev/auditpipe`
> 可打开、预选 ioctl 全部成功,但内核不再生成/投递任何记录;`auditon(A_SETCOND)`
> 返回成功后审计开关立即被系统重置回 NOAUDIT。root 身份与正确配置均无法改变。
> 程序检测到此状态时会明确报告"此 macOS 版本已停用 OpenBSM 内核审计",
> 不会假装在采集。完整系统审计只剩 Endpoint Security 通道(需 Apple 授权)。

以下为原设计说明,供旧系统(macOS ≤13 实测内核审计仍工作的版本)或归档参考。



Endpoint Security 需要 Apple 授权签名,本机开发环境通常没有。为此提供第二条审计通道:
`audit-pipe` 辅助进程读取 `/dev/auditpipe`(OpenBSM 内核审计),预选文件类事件
(创建/删除/写入,可选读取),经与 ES 辅助程序相同的加密套接字协议推送给 GUI,
记录同样标注"系统审计"并带权威进程身份(subject 中的 PID/UID + libproc 可执行路径)。

使用方式:主界面 → 监控设置 → 系统审计 → **「以管理员方式启动审计」**。
macOS 弹出原生管理员密码框(应用不接触密码),以 root 启动 `audit-pipe`。
GUI 退出/停止监控时接收位置文件被清理,辅助进程自动退出。

边界:OpenBSM 的身份是审计 subject(euid/auid/ruid + pid),无 ES 的
pid_version/签名/责任进程字段(相应字段留空);进程在事件后立即退出且
可执行路径无法解析时该条记录不推送(协议要求可验证身份)。
`sudo` 手动调试:`sudo target/release/audit-pipe --socket <audit.sock 路径>`。

## 一键申请授权并以 root 启动（macOS 13+）

主界面首次发现审计需要权限时显示授权说明，用户点击“授权并启用”后按以下顺序处理：

1. 验证主应用及辅助程序的 Apple 信任链签名、相同 Team ID 和辅助程序 ES entitlement。默认临时签名开发包在此明确停止，不索取无效的管理员密码。
2. 准备普通用户的审计接收通道，通过 **SMAppService** 注册随应用打包的 LaunchDaemon。
3. 若系统返回 `RequiresApproval`，自动打开“系统设置 → 通用 → 登录项与扩展/后台项目”，由管理员批准。macOS 随后根据 plist 的 `UserName=root` 启动辅助程序，GUI 不提权。
4. 若 root 辅助程序报告 `not_permitted`，自动打开“隐私与安全性 → 完全磁盘访问”，由用户开启权限；不会修改 TCC 数据库或绕过系统许可。
5. 后台服务按系统节流规则重试。只有实际收到 ES 订阅成功握手才显示“系统审计已连接”；后台服务获批本身不等于审计可用。

选择“稍后”后不自动重复询问，可在设置页随时点击“申请权限并启用审计”。“停用后台服务”通过系统接口注销服务。“完全磁盘访问设置”可单独打开授权页面。管理员验证由系统设置完成，应用不接收、保存或自动输入密码。

正式自动授权版本要求主应用和辅助程序正确签名，包含 LaunchDaemon 的应用还需按 Apple 要求公证。建议安装在 `/Applications`。仅 root 身份不能替代 Apple 授予的 ES entitlement 或用户的隐私授权。

### 正式版构建

```bash
WJ_APP_SIGN_IDENTITY='Developer ID Application: 实际名称 (TEAMID)' \
  ./scripts/package.sh macos
```

脚本默认用同一身份签名 ES 辅助程序，并保留其受限 entitlement；主应用最后签名。发布前仍须完成 Apple 公证/装订流程。默认不设置签名环境变量时仍为开发用临时签名，不会假装具备自动 root 审计资格。

`Contents/Library/LaunchDaemons/com.famtool.audit.plist` 指向 `Contents/MacOS/audit-helper --managed`。托管辅助程序只为当前登录用户连接接收器，并使用对端 audit token 验证 GUI 的 Apple 签名、应用标识及相同 Team ID，拒绝其他普通程序冒充 GUI。

接收器位置通过用户数据目录中的 `audit-endpoint.json` 发布，权限为 0600，退出时清理。它仅含 UID 和套接字路由地址，不含密码、密钥或审计事件；日志与配置仍加密保存。root 辅助程序只读取当前用户拥有的、非符号链接、有限大小的路由文件，并核对套接字所有者。GUI 关闭后停止 ES 订阅，服务等待下次连接；用户切换时重新确认登录用户。

以下手动方式保留用于调试或旧系统。

## 架构

`native/audit/main.m` 使用 SDK 正式结构和 API 接收 `NOTIFY_UNLINK`、`NOTIFY_RENAME`、`NOTIFY_CREATE`、`NOTIFY_CLOSE`；启用访问记录时额外订阅 `NOTIFY_OPEN`。不订阅 AUTH 事件，不阻止或修改系统操作。

GUI/CLI 以普通用户运行，在 `<日志位置>.store/audit.sock` 监听。目录 0700、套接字 0600，接收端使用 `getpeereid` 拒绝非 root 对端；辅助程序验证 GUI 套接字的所有者和对端 UID。监控范围由 GUI 通过通道传递，辅助程序和 Rust 接收端都进行路径过滤。每帧最多 64 KiB、协议版本校验、心跳超时、有限队列及缺口诊断防止无界积压。辅助程序只发送事件元数据，不读取目标文件内容，不把原始审计内容写成明文日志。

执行进程来自 `es_message_t.process`，UID/PID 从 audit token 提取。父进程/责任进程的可执行路径通过 `proc_pidpath_audittoken` 查询，避免按复用的 PID 猜测。进程已退出或系统未提供字段时保持未知。文件属主与操作用户分别保存。

接收到的系统审计记录直接进入现有加密事务写入线程，不参与会丢失进程边界的时间窗口归因合并。FSEvents 继续提供普通观察，两类来源分别标注。操作数量、通知数量和唯一文件数量不能混为一谈。

## 启用步骤（需要管理员及已获授权的签名）

### 1. 取得 Apple 授权并构建正式签名辅助程序

向 Apple 申请 Endpoint Security entitlement，准备相应开发者签名身份及其要求的签名/描述文件。环境变量必须使用本机实际存在且已获授权的身份：

```bash
WJ_AUDIT_SIGN_IDENTITY='Developer ID Application: 实际名称 (TEAMID)' \
  ./scripts/build_audit_macos.sh ./target/audit/famtool-audit-signed
codesign --verify --strict ./target/audit/famtool-audit-signed
codesign -d --entitlements :- ./target/audit/famtool-audit-signed
```

默认 GUI 构建附带临时签名的辅助程序，用于编译验证和权限诊断；**默认程序没有受限 ES entitlement，不能投入真实采集**。正式部署应使用上面的独立、获授权签名文件，避免被日常 GUI 的临时签名打包流程覆盖。

### 2. 安装到 root 管理的位置

先核验正式签名，再由管理员安装。不要把长期以 root 运行的程序放在普通用户可改写的开发目录：

```bash
sudo mkdir -p /Library/PrivilegedHelperTools
sudo install -o root -g wheel -m 755 \
  ./target/audit/famtool-audit-signed \
  /Library/PrivilegedHelperTools/com.famtool.audit
```

手动模式才需要此安装步骤。一键模式由 SMAppService 管理应用内的辅助程序，不复制任意用户指定程序到系统目录，也不设置 setuid 位。

### 3. 授予完全磁盘访问并检查

在“系统设置 → 隐私与安全性 → 完全磁盘访问权限”中完成授权。TCC 的责任归属与启动方式有关：从终端启动时可能需要对实际启动终端授权，独立部署时需要对辅助程序授权。以系统返回的错误为准。

```bash
sudo /Library/PrivilegedHelperTools/com.famtool.audit --check
```

只有返回 `state: "ready"` 才表示此次 ES 客户端初始化检查通过。常见返回值：

| 状态 | 处理方式 |
|---|---|
| `not_entitled` | 检查 Apple ES 授权及正式代码签名 |
| `not_permitted` | 完成 TCC 完全磁盘访问授权 |
| `not_privileged` | 只将辅助程序以 root 启动，勿把 GUI 以 root 运行 |
| `too_many_clients` | 检查系统现有 ES 客户端数量 |

GUI 的“检查权限”以普通用户身份执行打包程序，供诊断，不会自动弹出 sudo 或绕过系统许可，因此可能仍返回 `not_privileged`；**是否在采集以 GUI 的“系统审计已连接”状态为准**。

### 4. 连接 GUI 接收器

在 GUI 中启用“系统审计接收”、保存并开始监控。设置页显示实际套接字路径；若修改过日志位置，请替换下面的路径。

```bash
sudo /Library/PrivilegedHelperTools/com.famtool.audit \
  --socket "$HOME/Library/Application Support/famtool/famtool.log.store/audit.sock" \
  --uid "$(id -u)"
```

`--uid` 是运行 GUI 的普通用户 UID，不是 0；命令替换在 sudo 启动前由用户 shell 展开。前台辅助程序支持 GUI 暂停/重启后的断线重连；断开时注销 ES 订阅，等待重新连接。Ctrl+C/SIGTERM 可结束辅助程序。

手动模式不是防篡改 System Extension 部署。一键模式提供由系统批准和管理的 LaunchDaemon；本项目仍不宣称具备 System Extension 的防篡改保护。

### 5. 验证删除来源

待 GUI 显示“系统审计已连接”后，用独立测试目录验证，避免删除真实文件：

```bash
wj_audit_test_dir="$(mktemp -d "$HOME/Desktop/wj-audit-check.XXXXXX")"
touch "$wj_audit_test_dir/audit-delete-test.txt"
/bin/rm "$wj_audit_test_dir/audit-delete-test.txt"
```

确保该目录在监控范围内且未被排除。在历史中搜索 `audit-delete-test.txt`，找到标注“系统审计”的删除记录，执行文件应为 `/bin/rm`，并可查看当时的 PID、UID 和可取得的父/责任进程。没有采集到的旧事件不能追溯补齐身份。

## 验证与限制

```bash
./scripts/test_audit_macos.sh
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
npm test
```

原生编码测试使用合成 SDK 消息，验证中文路径、unlink、rename、拒绝事件过滤和身份编码；Rust 测试验证非 root 对端拒绝、协议/范围校验、加密持久化、历史搜索及旧记录兼容。这些测试不冒充真实内核采集测试。

- 文件修改以 CLOSE 的 `modified` 标记为准；内存映射等情况不保证覆盖所有变化。
- ES 序列缺口或队列溢出写入 `system_audit_gap`，不保证零丢失。
- 权限失败、协议异常、断线写入 `system_audit_error`；普通通知继续运行。
- 端点只把 root 对端当作信任边界，不抵抗已掌握 root 权限的攻击者。

参考：[Apple ES 客户端要求](https://developer.apple.com/documentation/endpointsecurity/es_new_client(_:_:))、[ES entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.endpoint-security.client)。
