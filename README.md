# Codex 账号授权与额度工具

QQ 交流群：`1039349479`

[点击链接加入群聊【AI 技术资源交流群】](https://qm.qq.com/q/G7DvyIlLgc)

这是一个本地运行的 Codex 重新授权工具，用于管理已有 ChatGPT/Codex 账号的授权状态，执行 Token 验活与额度查询，并按需导出或同步授权凭据。

## 界面示例

![Codex 账号授权与额度控制台示例](docs/dashboard-example.png)

## 工作流程

1. 导入已有 ChatGPT 账号及必要的邮箱验证信息。
2. 可选择开通账号自身的 ChatGPT TOTP 2FA，密钥会保存到本地账号记录。
3. 完成登录验证和 Codex 重新授权，保存授权凭据。
4. 定时检查 Token 有效性，并查询账号额度和套餐状态。
5. 按需导出授权结果，或同步到已配置的服务。

## 功能范围

- 本地网页控制台，统一查看账号、授权任务、Token、额度和上传状态。
- 支持已有账号的密码登录、邮箱 OTP 验证和已配置 TOTP 密钥的登录 2FA。
- 支持通过“开通 2FA”批量申请并自动激活 ChatGPT TOTP，已配置或没有密码的账号会跳过并显示原因。
- 支持代理池、代理租约、失败冷却和代理凭据脱敏显示。
- 支持批量重新授权、批量额度查询和批量删除。
- 支持 Free、Plus、Pro、Team 等可识别套餐展示。
- 支持 5h、Weekly、Monthly 等额度窗口及重置时间统计。
- 支持定时 Token 验活，并只对明确失效的账号自动加入重新授权队列。
- 支持邮箱四段 TXT、CPA ZIP 和 Sub2API ZIP 导出。
- 支持授权成功后自动上传 CPA/CLIProxyAPI 或 Sub2API。

## 环境要求

- Python 3.11 或更高版本。
- Node.js 18 或更高版本，用于登录授权相关运行时。
- 能够访问 ChatGPT、Outlook 以及已配置上传服务的网络环境。
- 推荐使用 Windows 10/11；macOS 和 Linux 可以通过 Uvicorn 命令运行。

## 安装与启动

### Windows PowerShell

```powershell
git clone https://github.com/QinJiapeng/codex_account_tool.git
Set-Location codex_account_tool

py -3.11 -m venv .venv
.venv\Scripts\python.exe -m pip install --upgrade pip
.venv\Scripts\python.exe -m pip install -r requirements.txt

Copy-Item .env.example .env
.\run.ps1
```

也可以双击 `start.vbs` 启动：首次运行会打开一个服务控制台；以后再次运行时，会在原来的控制台中重新启动服务，不会重复打开窗口。启动失败时会弹出错误提示。也可以双击 `start.bat` 直接打开服务控制台。

启动后访问：

```text
http://127.0.0.1:10717
```

### macOS / Linux

```bash
git clone https://github.com/QinJiapeng/codex_account_tool.git
cd codex_account_tool

python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

cp .env.example .env
python -m uvicorn app.main:app --host 127.0.0.1 --port 10717
```

## 首次使用

### 1. 配置代理策略

默认启用代理池。第一次使用时请先完成以下任一操作：

- 打开“代理池”页面并导入至少一个可用代理；
- 或打开“设置”，关闭“使用代理池”，让授权、验活和额度查询使用本机网络。

代理支持以下格式，每行一个，也可以使用逗号或分号分隔：

```text
host:port
username:password@host:port
http://username:password@host:port
https://username:password@host:port
socks4://host:port
socks5://username:password@host:port
socks5h://username:password@host:port
```

网页代理列表只显示协议、主机和端口，不返回代理用户名或密码。

### 2. 导入已有账号

进入“授权工作台”，点击“导入账号”，每行填写一个账号：

```text
邮箱----ChatGPT账号密码----Outlook客户端ID----Outlook邮箱refresh_token
```

示例：

```text
user@example.com----chatgpt-password----outlook-client-id----outlook-refresh-token
```

字段说明：

- 邮箱：已有 ChatGPT/Codex 账号使用的邮箱。
- ChatGPT 账号密码：登录步骤要求密码时使用；不会自动生成或猜测密码。
- Outlook 客户端 ID：用于刷新 Outlook 邮箱访问令牌。
- Outlook refresh token：用于读取该邮箱收到的 OpenAI 登录验证码。

没有 Outlook 邮箱凭据、只使用登录 2FA 的账号使用三段格式：

```text
user@example.com----chatgpt-password----JBSWY3DPEHPK3PXP
```

仍需要 Outlook 邮箱接收登录验证码的 2FA 账号，在四段格式末尾追加 Base32 TOTP 密钥：

```text
user@example.com----chatgpt-password----outlook-client-id----outlook-refresh-token----JBSWY3DPEHPK3PXP
```

邮箱单列、两段、六段或缺少必要字段都会被计为无效行。重复导入同一邮箱会更新其本地凭据。三段格式账号如果登录还要求邮箱验证码，会因缺少 Outlook 邮箱凭据而失败。TOTP 密钥只保存在本地运行数据库中，不会出现在账号列表、OAuth 导出或上传内容中。

### 3. 重新授权

账号导入后：

1. 点击“重新授权”会处理全部账号，程序会根据服务端验证步骤自动使用邮箱验证码或 TOTP。
2. 点击“开通 2FA”会处理全部尚未配置 TOTP 且保存了密码的账号。
3. 勾选一个或多个账号后，上述按钮只处理选中的账号。
4. 页面下方“最近任务”会显示排队、代理领取、登录授权、Token 保存和最终结果。
5. 重新授权和开通 2FA 遇到可重试错误时会自动重试，最多执行 10 次；明确封禁、停用或缺少必要凭据的账号会立即结束。
6. “失败任务类型”下拉框可配合共用的重试按钮，手动重试已经达到自动重试上限的任务。
7. 账号列表可按“成功、失败、已禁用、授权中、待处理”筛选；已禁用账号会自动跳过。
8. 明确识别为已删除或已禁用的账号会保留在列表中，可点击“一键清理禁用账号”统一删除。

### 4. 开通 2FA

在账号操作区域点击“开通 2FA”：

1. 不勾选账号时，会处理全部尚未配置 TOTP 且保存了 ChatGPT 密码的账号。
2. 勾选账号后，只处理选中的符合条件账号；已配置 TOTP、没有密码或已禁用账号会跳过并显示数量。
3. 工具会登录已有账号，查询当前 2FA 状态，申请新密钥，生成当前验证码并自动激活；任务成功后只在本地保存密钥，不在普通任务事件中显示密钥。
4. 开通成功后，后续点击“重新授权”时会自动使用已保存的 TOTP 密钥（如果服务端要求 2FA）。
5. 开通任务遇到可重试错误时会自动重试，最多执行 10 次；仍失败的任务可通过“重试开通 2FA 失败”再次提交。

点击“一键验活”可以立即检查全部账号，或只检查当前选中的账号。Token 明确失效时会加入重新授权队列；临时网络异常、限流等可重试错误会自动检查最多 10 次，仍失败后将账号标记为失败。
账号列表中的“验活状态”显示最近一次结果；授权成功保存新 Token 后会先标记为“有效”，后续模型列表验活会更新为实际结果。

授权流程会自动从账号自己的 Outlook 邮箱读取验证码。成功后，本地数据库会保存新的 Codex OAuth Token。

删除账号会同时清理本地 Token、额度、任务和上传状态；如需保留凭据，请先完成导出。

### 5. 查询额度

点击“查询全部额度”或先勾选账号再查询。查询结果会展示：

- 账号套餐，例如 Free、Plus、Pro 或 Team；
- Credit 余额和估算金额；
- 使用率；
- 5h、Weekly、Monthly 等限额窗口；
- 剩余额度和预计重置时间；
- 额度已用完、限流或临时失败状态。

每个额度查询失败的账号会自动重试最多 10 次，仍失败后将账号标记为失败。点击“查询失败额度账号”可再次提交最近一次额度请求失败的已授权账号；没有匹配账号时不会发起请求。

### 6. 启用定时验活

打开“设置”后：

1. 勾选“启用定时验活”。
2. 设置执行频率，范围为 5–10080 分钟。
3. 点击“保存设置”。保存后定时器会立即按新配置重新计时。

程序会定期检查已保存授权的可用性，仅对明确失效的账号重新加入授权队列；临时网络异常或服务限流不会直接删除本地凭据。

### 7. 导出授权结果

在“导出与上传”区域选择格式后点击“导出授权结果”：

- 邮箱四段 TXT：导出最新的邮箱、密码、Outlook 客户端 ID 和 Outlook refresh token。
- 2FA 三段 TXT：导出已配置 TOTP 的邮箱、密码和 2FA 密钥，格式为 `邮箱----密码----TOTP 密钥`；此格式不要求账号已有 OAuth Token。
- CPA ZIP：每个账号生成一个包含 Codex OAuth 凭据的 JSON 文件。
- Sub2API ZIP：每个账号生成一个可直接在 Sub2API 数据导入中使用的认证 JSON 文件，并打包下载。

只有已经保存 OAuth Token 的账号会进入 CPA 和 Sub2API 导出；2FA 三段 TXT 只导出本地已保存 TOTP 密钥且有密码的账号。导出文件包含可用凭据，应当按密码文件保护，禁止上传到公开网盘或提交到 Git。

### 8. 上传到 CPA / CLIProxyAPI

打开“设置”，在“CPA / CLIProxyAPI”区域填写：

- 服务地址；
- 管理员密码或管理密钥；
- 请求超时时间。

保存后，可以在授权工作台手动上传，也可以开启“授权成功后自动上传 CPA”。

### 9. 上传到 Sub2API

打开“设置”，在“Sub2API”区域填写：

- Sub2API 服务地址；
- 管理员 API Key；
- 可选的默认分组 ID（需提前在 Sub2API 中创建分组）；
- 请求超时时间。

保存后可以手动上传，也可以开启“授权成功后自动上传 Sub2API”。填写分组 ID 后，新上传和重新上传的账号都会挂到该分组；留空则不指定分组。一个账号是否最终属于多个分组，以 Sub2API 的分组设置为准。

自动上传失败不会回滚本地已保存的授权结果。账号列表会分别记录 CPA 和 Sub2API 的未上传、已上传或失败状态。

### 10. 重复上传保护

普通上传会按平台检查本地“已上传”状态，只发送未上传或上次失败的账号，并在结果中显示跳过数量。账号重新授权保存新 Token 后，两个平台的本地上传状态会自动重置为“未上传”，从而允许新凭据再次同步。

如果需要忽略本地记录再次发送，请在“设置”中开启“上传时强制重传”。该设置同时作用于手动上传、授权成功后的自动上传以及 CPA/Sub2API 两个平台；关闭时会按平台检查本地“已上传”状态。强制上传只绕过本地保护，不代表远端一定会覆盖同名账号；CPA 和 Sub2API 的远端去重/覆盖行为由各自服务决定。因此不建议先删除远端账号再上传，避免上传中途失败造成原账号丢失。

## 配置文件与环境变量

复制 `.env.example` 为 `.env` 后可以调整以下配置：

| 配置项 | 默认值 | 说明 |
| --- | --- | --- |
| `APP_HOST` | `127.0.0.1` | 本地监听地址 |
| `APP_PORT` | `10717` | 网页端口 |
| `DATA_DIR` | `./data` | SQLite 数据目录 |
| `REAUTH_WORKERS` | `20` | 重新授权线程数（1–200），修改后需重启 |
| `USE_PROXY_DEFAULT` | `true` | 是否默认使用代理池 |
| `PROXY_LEASE_SECONDS` | `1200` | 代理租约时长 |
| `PROXY_COOLDOWN_SECONDS` | `60` | 代理失败后的冷却时间 |
| `PROXY_LIST` | 空 | 启动时导入的代理列表 |
| `PROXY_LIST_FILE` | 空 | 从文件读取代理列表 |
| `SCHEDULED_LIVENESS_ENABLED` | `true` | 是否启用定时验活 |
| `SCHEDULED_LIVENESS_INTERVAL_MINUTES` | `5` | 验活间隔，范围 5–10080 分钟 |
| `OUTLOOK_IMAP_HOST` | `outlook.office365.com` | Outlook IMAP 地址 |
| `OUTLOOK_IMAP_PORT` | `993` | Outlook IMAP 端口 |
| `OTP_POLL_SECONDS` | `5` | 邮箱验证码轮询间隔 |
| `OTP_TIMEOUT_SECONDS` | `180` | 邮箱验证码等待超时 |
| `AUTO_UPLOAD_CPA` | `true` | 授权成功后自动上传 CPA |
| `AUTO_UPLOAD_SUB2API` | `false` | 授权成功后自动上传 Sub2API |
| `FORCE_UPLOAD` | `false` | 上传时是否忽略本地已上传记录并强制重传 |
| `CLI_PROXY_API_URL` | 空 | CPA/CLIProxyAPI 服务地址 |
| `CLI_PROXY_MANAGEMENT_KEY` | 空 | CPA/CLIProxyAPI 管理密钥 |
| `CLI_PROXY_API_TIMEOUT_SECONDS` | `30` | CPA/CLIProxyAPI 请求超时 |
| `SUB2API_API_URL` | 空 | Sub2API 服务地址 |
| `SUB2API_ADMIN_API_KEY` | 空 | Sub2API 管理员 API Key |
| `SUB2API_API_TIMEOUT_SECONDS` | `30` | Sub2API 请求超时 |
| `SUB2API_GROUP_ID` | 空 | 可选的默认 Sub2API 分组 ID |

上传地址、管理员密码或密钥既可以写入 `.env`，也可以通过网页“设置”保存。网页保存值会进入本地数据库，接口只返回“是否已配置”，不会回显密码和密钥。未配置对应地址和凭据时，不会向远端发送请求，自动上传任务会记录配置错误。

## 免责声明

本项目仅供学习、研究和管理本人账号使用，不隶属于 OpenAI，也未获得 OpenAI 背书。使用者应自行遵守 OpenAI 服务条款、相关平台规则以及所在地法律法规。因接口变更、账号限制、数据泄露或不当使用造成的后果由使用者自行承担。

## 更新日志

版本变化和升级说明请查看 [CHECKME.md](CHECKME.md)。

## License（开源许可证）

[MIT](LICENSE)
