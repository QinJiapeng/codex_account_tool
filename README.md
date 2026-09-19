# Codex 账号授权与额度工具

QQ 交流群：`1039349479`

[点击链接加入群聊【AI 技术资源交流群】](https://qm.qq.com/q/G7DvyIlLgc)

这是一个本地运行的 Codex 重新授权工具，用于管理已有 ChatGPT/Codex 账号的授权状态，执行 Token 验活与额度查询，并按需导出或同步授权凭据。

## 界面示例

![Codex 账号授权与额度控制台示例](docs/dashboard-example.png)

## 工作流程

1. 导入已有 ChatGPT 账号及必要的邮箱验证信息。
2. 完成登录验证和 Codex 重新授权，保存授权凭据。
3. 定时检查 Token 有效性，并查询账号额度和套餐状态。
4. 按需导出授权结果，或同步到已配置的服务。

## 功能范围

- 本地网页控制台，统一查看账号、授权任务、Token、额度和上传状态。
- 支持已有账号的密码登录和邮箱 OTP 验证。
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

进入“授权工作台”，点击“导入账号”，每行填写一个四段账号：

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

当前只接受严格四段格式。邮箱单列、三段、六段或缺少任一字段都会被计为无效行。重复导入同一邮箱会更新其本地凭据。

### 3. 重新授权

账号导入后：

1. 不勾选账号时，点击“重新授权全部”会处理全部账号。
2. 勾选一个或多个账号后，按钮会变成“重新授权选中”，只处理选中账号。
3. 页面下方“最近任务”会显示排队、代理领取、登录授权、Token 保存和最终结果。
4. 账号列表可按“成功、失败、已禁用、授权中、待处理”筛选；点击“重新授权失败账号”可只重试最近一次授权失败的账号，已禁用账号会自动跳过。
5. 明确识别为已删除或已禁用的账号会保留在列表中，可点击“一键清理禁用账号”统一删除。

授权流程会自动从账号自己的 Outlook 邮箱读取验证码。成功后，本地数据库会保存新的 Codex OAuth Token。

删除账号会同时清理本地 Token、额度、任务和上传状态；如需保留凭据，请先完成导出。

### 4. 查询额度

点击“查询全部额度”或先勾选账号再查询。查询结果会展示：

- 账号套餐，例如 Free、Plus、Pro 或 Team；
- Credit 余额和估算金额；
- 使用率；
- 5h、Weekly、Monthly 等限额窗口；
- 剩余额度和预计重置时间；
- 额度已用完、限流或临时失败状态。

点击“查询失败额度账号”可只重新查询最近一次额度请求失败的已授权账号；没有匹配账号时不会发起请求。

### 5. 启用定时验活

打开“设置”后：

1. 勾选“启用定时验活”。
2. 设置执行频率，范围为 5–10080 分钟。
3. 点击“保存设置”。保存后定时器会立即按新配置重新计时。

程序会定期检查已保存授权的可用性，仅对明确失效的账号重新加入授权队列；临时网络异常或服务限流不会直接删除本地凭据。

### 6. 导出授权结果

在“导出与上传”区域选择格式后点击“导出授权结果”：

- 邮箱四段 TXT：导出最新的邮箱、密码、Outlook 客户端 ID 和 Outlook refresh token。
- CPA ZIP：每个账号生成一个包含 Codex OAuth 凭据的 JSON 文件。
- Sub2API ZIP：每个账号生成一个可直接在 Sub2API 数据导入中使用的认证 JSON 文件，并打包下载。

只有已经保存 OAuth Token 的账号会进入 CPA 和 Sub2API 导出。导出文件包含可用凭据，应当按密码文件保护，禁止上传到公开网盘或提交到 Git。

### 7. 上传到 CPA / CLIProxyAPI

打开“设置”，在“CPA / CLIProxyAPI”区域填写：

- 服务地址；
- 管理员密码或管理密钥；
- 请求超时时间。

保存后，可以在授权工作台手动上传，也可以开启“授权成功后自动上传 CPA”。

### 8. 上传到 Sub2API

打开“设置”，在“Sub2API”区域填写：

- Sub2API 服务地址；
- 管理员 API Key；
- 可选的默认分组 ID（需提前在 Sub2API 中创建分组）；
- 请求超时时间。

保存后可以手动上传，也可以开启“授权成功后自动上传 Sub2API”。填写分组 ID 后，新上传和重新上传的账号都会挂到该分组；留空则不指定分组。一个账号是否最终属于多个分组，以 Sub2API 的分组设置为准。

自动上传失败不会回滚本地已保存的授权结果。账号列表会分别记录 CPA 和 Sub2API 的未上传、已上传或失败状态。

### 9. 重复上传保护

普通上传会按平台检查本地“已上传”状态，只发送未上传或上次失败的账号，并在结果中显示跳过数量。账号重新授权保存新 Token 后，两个平台的本地上传状态会自动重置为“未上传”，从而允许新凭据再次同步。

如果需要忽略本地记录再次发送，请在“设置”中开启“上传时强制重传”。该设置同时作用于手动上传、授权成功后的自动上传以及 CPA/Sub2API 两个平台；关闭时会按平台检查本地“已上传”状态。强制上传只绕过本地保护，不代表远端一定会覆盖同名账号；CPA 和 Sub2API 的远端去重/覆盖行为由各自服务决定。因此不建议先删除远端账号再上传，避免上传中途失败造成原账号丢失。

## 配置文件与环境变量

复制 `.env.example` 为 `.env` 后可以调整以下配置：

| 配置项 | 默认值 | 说明 |
| --- | --- | --- |
| `APP_HOST` | `127.0.0.1` | 本地监听地址 |
| `APP_PORT` | `10717` | 网页端口 |
| `DATA_DIR` | `./data` | SQLite 数据目录 |
| `REAUTH_WORKERS` | `20` | 重新授权线程数，修改后需重启 |
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
