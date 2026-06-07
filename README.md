# Lighthouse Firewall Auto Allow

中心管控、Agent 上报模式的腾讯云 Lighthouse 防火墙自动放通服务。

## 功能

- FastAPI Web 管控页，SQLite 持久化。
- OIDC 登录，支持 `/.well-known/openid-configuration` 自动发现。
- 每个客户端 ID 独立 token，并绑定一个或多个 Lighthouse `region + instance_id`。
- Agent 上报 hostname、IPv4、IPv6 后，中心端按 `[AUTO] {client_id}` 描述维护规则。
- 支持 Linux systemd/cron、macOS launchd、Windows Task Scheduler 安装脚本。

## 本地运行

```powershell
uv sync
$env:APP_SECRET_KEY="change-me"
$env:PUBLIC_BASE_URL="http://127.0.0.1:8000"
uv run uvicorn lighthouse_firewall_auto_allow.main:app --reload
```

未配置 `OIDC_ISSUER` 时会进入本地开发登录模式，访问 `/login` 即可进入后台。

## Docker

```bash
docker compose up -d --build
```

关键环境变量：

- `APP_SECRET_KEY`
- `PUBLIC_BASE_URL`
- `OIDC_ISSUER`
- `OIDC_CLIENT_ID`
- `OIDC_CLIENT_SECRET`
- `OIDC_SCOPE`，默认 `openid profile email`；如果 OIDC 网关返回的 `id_token` 不包含
  `nonce`，可设为 `profile email`，让应用改用 userinfo 获取用户资料。
- `OIDC_HTTP_TIMEOUT`，默认 `15` 秒，用于 discovery、token、userinfo 等 OIDC HTTP 请求。
- `ADMIN_EMAILS`
- `TENCENTCLOUD_SECRET_ID`
- `TENCENTCLOUD_SECRET_KEY`

## Agent 上报接口

```http
POST /api/v1/report/{client_id}
Authorization: Bearer <token>
Content-Type: application/json

{
  "hostname": "host-a",
  "ipv4": "1.2.3.4",
  "ipv6": "2402:4e00::1",
  "agent_version": "0.1.0"
}
```

删除客户端后接口返回 `410`，Agent 会执行自我卸载。
