# Stargate Tunnel Token 设计文档

本文档描述如何在 **尽量少改 Stargate 现有认证主链路** 的前提下，为 `vertex-tunnel` / `tunnelcli` 提供一套可复用、通用、面向机器客户端的短期令牌能力。

目标不是把 Stargate 改造成 tunnel 专用认证服务，而是在现有：

- `Warden` 白名单
- `Herald / TOTP` 二次验证
- Cookie / Session 登录态
- `Traefik ForwardAuth`

之上，补一层通用的 **Authenticated Session Token Exchange** 能力，使 Stargate 可以为 CLI、WebSocket、长连接、后续其它 API 客户端签发短期 JWT。

---

## 1. 背景与问题

当前 Stargate 的认证成功产物是 **Session**，不是可供 CLI 使用的 Bearer Token。

当前 Stargate 的主要流程是：

1. 用户通过 `/_login`
2. 使用 `Warden` 校验用户身份和状态
3. 使用 `Herald` 验证验证码，或使用 `Herald TOTP` 验证 6 位动态码
4. 登录成功后，将用户信息写入 session
5. 后续由 `/_auth` 检查 session，并给后端添加身份头

这种模式非常适合：

- 浏览器访问
- Traefik / Nginx ForwardAuth
- 多域名 Web 应用

但不适合：

- `tunnelcli`
- WebSocket 长连接
- SSH / TCP over WebSocket
- 需要短期 Bearer Token 的机器客户端

当前 `vertex-tunnel` 依赖 `vertex-proxy` 的原因正是在这里：

- `vertex-proxy` 提供 appauth / OAuth 风格登录端点
- `vertex-proxy` 将外部访问令牌转换成内部 assertion
- `vertex-tunnel` 只校验 assertion

本设计的目标是：**让 Stargate 直接成为 tunnel 令牌的身份源，从而移除 `vertex-proxy` 对 tunnel 的依赖。**

---

## 2. 设计目标

### 2.1 必须满足

1. 不改变当前 Web 登录主链路
2. 不要求 `vertex-tunnel` 理解浏览器 session 细节
3. 支持 CLI / WebSocket / 长连接场景
4. 支持短期、可限定 audience 的 JWT
5. 允许未来扩展到除 tunnel 外的其它机器客户端
6. 保持与现有 `Warden + Herald/TOTP` 的一致身份来源

### 2.2 明确不做

1. 不在第一阶段把 Stargate 改造成完整 OIDC Provider
2. 不在第一阶段引入 device code 全套标准协议
3. 不在第一阶段改动现有 `/_auth`、`/_login`、`/_session_exchange` 行为
4. 不在第一阶段改变现有浏览器用户的 session 语义

---

## 3. 核心思路

新增一层通用能力：

**Authenticated Session Token Exchange**

含义是：

- 用户先通过现有 Stargate 完成人类登录
- 已认证 session 再换取一个短期 JWT
- 该 JWT 面向指定 audience / purpose
- `vertex-tunnel` 只校验这个 JWT

也就是说：

- **Stargate 继续负责“认证人”**
- **新令牌能力负责“把已认证人转成机器可用凭证”**
- **vertex-tunnel 只消费凭证，不依赖 Stargate session**

---

## 4. 现状与目标架构

### 4.1 当前架构

```text
tunnelcli
  -> vertex-proxy appauth
  -> vertex-proxy 校验 token / session
  -> vertex-proxy 签 assertion
  -> vertex-tunnel 校验 assertion
  -> 目标 TCP / SSH 服务
```

### 4.2 目标架构

```text
browser/user
  -> Stargate 登录 (Warden + Herald/TOTP)
  -> 得到 session

tunnelcli
  -> 通过已认证 session / 交换流程获取 tunnel JWT
  -> Traefik
  -> vertex-tunnel
  -> 目标 TCP / SSH 服务
```

对应职责：

- `Stargate`: 身份认证 + JWT 签发
- `Traefik`: TLS / Host / WebSocket 转发
- `vertex-tunnel`: JWT 校验 + 隧道建立 + 目标授权

---

## 5. 为什么不直接复用现有 Session

不建议让 `vertex-tunnel` 直接认 Stargate session cookie，原因如下：

1. CLI 不适合长期持有浏览器 Cookie
2. WebSocket 重连不适合依赖浏览器登录态
3. `vertex-tunnel` 不应该耦合到 Fiber session / session-kit 实现
4. Session 更适合浏览器；JWT 更适合机器客户端

因此，本设计明确采用：

- **Session 用于 Web 登录**
- **JWT 用于 tunnel / CLI**

---

## 6. 新增通用能力

### 6.1 新增端点

建议新增：

- `POST /_token`

这是通用端点，不限定只给 tunnel 使用。

### 6.2 基本语义

该端点用于：

- 读取当前请求中的有效 Stargate session
- 基于 session 中已认证的用户信息
- 签发一个短期 JWT

签发行为不重复做 Warden / TOTP 登录，只消费现有登录结果。

### 6.3 请求格式

建议支持 `application/json`：

```json
{
  "audience": "tunnel.mrlin.space",
  "scope": ["forward"],
  "ttl_seconds": 300,
  "resource": {
    "kind": "tunnel"
  }
}
```

字段说明：

- `audience`: 必填，JWT 的 `aud`
- `scope`: 可选，请求方期望的 scope
- `ttl_seconds`: 可选，请求有效期，服务端应有上限
- `resource`: 可选，未来扩展字段

### 6.4 响应格式

```json
{
  "token": "<jwt>",
  "token_type": "Bearer",
  "expires_in": 300,
  "issued_at": 1711111111
}
```

### 6.5 服务端校验规则

签发前必须满足：

1. 当前 session 已认证
2. session 中存在有效 `user_id`
3. `audience` 在允许列表中
4. `ttl_seconds` 不超过服务端上限
5. 请求的 `scope` 不得超出 session 代表的用户权限
6. 可选：对高风险 audience 强制要求包含 `totp` 的 `amr`

---

## 7. Token 类型识别

### 7.1 不是“自动猜测”

Stargate 不应在登录完成时自动决定“签哪类 token”，因为当前认证成功产物仍应保持为 session。

应该由：

- 调用哪个 endpoint
- 传入什么 `audience`

来明确决定签发哪类 token。

### 7.2 推荐方式

通过显式 `audience` 区分：

- `aud = tunnel.mrlin.space`
- 将来可扩展为：
  - `aud = api.example.com`
  - `aud = cli.example.com`

这样 Tunnel 只是第一个使用者，不会把设计做成 tunnel 专属协议。

---

## 8. JWT Claims 设计

### 8.1 推荐 Claims

```json
{
  "iss": "auth.mrlin.space",
  "sub": "u_952e6ee5e707049e",
  "aud": "tunnel.mrlin.space",
  "iat": 1711111111,
  "nbf": 1711111111,
  "exp": 1711111411,
  "jti": "01HXYZ...",
  "scope": ["forward"],
  "role": "admin",
  "amr": ["warden", "totp"],
  "email": "linjiang1205@qq.com",
  "phone": "19926646812"
}
```

### 8.2 可选扩展 Claims

对于 tunnel 更推荐加显式目标约束：

```json
{
  "allow": [
    {"proto": "tcp", "host": "192.168.50.127", "port": 22},
    {"proto": "tcp", "host": "192.168.50.220", "port": 443}
  ]
}
```

或：

```json
{
  "allow_upstreams": ["mac-mini-ssh", "homelab-https"]
}
```

第一阶段如果不做细粒度授权，也至少应保留：

- `aud`
- `scope`
- `sub`
- `exp`
- `amr`

### 8.3 Token 生命周期

建议：

- 默认 `ttl = 300s`
- 上限不超过 `900s`

建议策略：

- token 只用于“建链”
- 连接建立后，不强制中途断开
- 断线重连时必须重新提供有效 token

这样兼顾：

- 安全性
- SSH / 长连接稳定性

---

## 9. 签名与密钥管理

### 9.1 建议

使用一套独立于 session cookie 的 JWT 签名密钥。

建议新增配置：

- `TOKEN_SIGNING_KEY`
- `TOKEN_SIGNING_KID`
- `TOKEN_ISSUER`
- `TOKEN_MAX_TTL_SECONDS`
- `TOKEN_ALLOWED_AUDIENCES`

### 9.2 JWKS 暴露

建议新增：

- `GET /.well-known/jwks.json`
  或
- `GET /_jwks`

用于给 `vertex-tunnel` 拉取公钥。

### 9.3 不建议复用的内容

不建议复用：

- session cookie 密钥
- Herald HMAC 密钥
- Warden API Key

这些职责不同，不应混用。

---

## 10. vertex-tunnel 对接方式

### 10.1 新认证模式

`vertex-tunnel` 新增 Bearer JWT 模式：

1. 读取 `Authorization: Bearer <token>`
2. 校验签名
3. 校验 `iss`
4. 校验 `aud`
5. 校验 `exp / nbf`
6. 校验 `scope`
7. 可选校验 `allow`

### 10.2 兼容旧模式

迁移期间建议同时支持：

- 旧模式：`x-vertex-auth-assertion`
- 新模式：`Authorization: Bearer`

优先级建议：

1. Bearer JWT
2. 旧 assertion

这样可以分阶段迁移 `tunnelcli`，避免一次性切断旧链路。

---

## 11. tunnelcli 对接方式

### 11.1 第一阶段目标

不要求 `tunnelcli` 一步实现完整 OIDC / device code。

第一阶段只需要：

1. 让用户完成 Stargate 登录
2. 调 `POST /_token` 获取 tunnel JWT
3. 用 `Authorization: Bearer` 建立 WebSocket

### 11.2 可行交互模式

建议优先实现其中一种：

#### 模式 A：本地浏览器辅助

1. `tunnelcli` 打开浏览器到 Stargate 登录页
2. 登录成功后，用户在浏览器中获取/确认 token 交换
3. `tunnelcli` 读取 token 并建链

#### 模式 B：本地回调

1. `tunnelcli` 打开本地临时回调端口
2. 浏览器完成登录后，回调给本地 CLI
3. CLI 用 session 交换 token

#### 模式 C：后续再支持 device flow

这是后续增强，不是第一阶段必需。

---

## 12. 建议新增的 Stargate 内部抽象

为了保持通用性，建议不要把实现写死在 tunnel handler 里，而是增加一层独立抽象：

- `internal/token`

建议职责：

- Token 请求模型
- Claims 构造
- 签名与校验辅助
- audience 白名单
- TTL 限制
- 未来可能的刷新 / 吊销接口

建议目录：

```text
src/internal/token/
  claims.go
  signer.go
  issuer.go
  config.go
```

对应 handler：

```text
src/internal/handlers/token.go
```

---

## 13. session 到 token 的信息映射

当前 session 已写入这些核心字段：

- `user_id`
- `user_phone`
- `user_mail`
- `user_scope`
- `user_role`
- `user_name`
- `user_amr`

因此 `/_token` 不需要重新调用 Warden / Herald，只需要：

1. 检查 session 已认证
2. 从 session 读取上述字段
3. 生成 JWT

这是本设计“少改现有逻辑”的关键。

---

## 14. 与现有认证主链路的关系

### 14.1 一致的部分

用户认证身份的来源保持一致：

- `Warden` 决定用户是谁、是否 active
- `Herald / TOTP` 决定二次验证是否通过
- 成功后 session 是唯一可信登录态

### 14.2 新增的部分

新增的是：

- 已登录 session 派生短期 JWT

因此它不是一套新的认证体系，而是：

- **现有认证体系的机器客户端扩展**

---

## 15. 安全边界

### 15.1 必须控制 audience

不允许任意 audience。

必须有白名单，例如：

- `tunnel.mrlin.space`

### 15.2 必须限制 TTL

不允许客户端请求无限期 token。

### 15.3 建议对高风险 audience 强制 AMR

例如 tunnel 类 audience 应要求：

- `amr` 包含 `totp`

即用户必须通过 TOTP，不能只靠密码。

### 15.4 建议支持显式资源限制

对于 tunnel，更推荐将允许的目标范围编码进 token，而不是让拿到 token 的客户端能访问任意内网 IP。

---

## 16. 迁移计划

### 阶段 1：Stargate 增加通用 token 签发能力

- 增加配置
- 增加 signer / claims 抽象
- 增加 `POST /_token`
- 增加 JWKS 端点

### 阶段 2：vertex-tunnel 同时支持新旧认证模式

- 保留 assertion
- 新增 Bearer JWT 校验

### 阶段 3：tunnelcli 支持 token 交换

- 优先做最小交互流程
- 不强求一开始就 device flow

### 阶段 4：Traefik 直接接 `tunnel.mrlin.space`

- 仅负责 TLS / WSS 转发
- `vertex-proxy` 不再承接 tunnel 公网入口

### 阶段 5：下线 `vertex-proxy` 的 tunnel 相关职责

- 移除旧 assertion 依赖
- 移除 appauth / provider / jwks 旧链路

---

## 17. 备选方案与取舍

### 方案 A：直接改 Stargate，新增 `/_token`

优点：

- 能力最通用
- 只新增一层通用 session-to-token 交换
- 对接其它 CLI / API 客户端也有价值

缺点：

- 需要修改 Stargate 代码

### 方案 B：做一个独立 token broker

优点：

- 几乎不改 Stargate 本体

缺点：

- 增加一个新服务
- 仍要理解 Stargate session
- 架构更绕

### 当前建议

本项目更推荐 **方案 A**。

原因：

- 需求本身具有通用性，不是 tunnel 私货
- 实现边界清晰
- 比单独再维护一个 broker 更容易长期维护

---

## 18. 建议的最小落地范围

第一版只做以下最小能力：

1. `POST /_token`
2. `GET /_jwks`
3. JWT 签名与基础 claims
4. 基于 session 的签发
5. audience 白名单
6. TTL 限制

先**不做**：

1. refresh token
2. token 吊销列表
3. device code flow
4. 多 audience 多 resource 细粒度策略中心

这些都可以留到第二阶段。

---

## 19. 实施后的收益

完成后将得到：

1. Web 与 tunnel 共用同一身份体系
2. 去除 `vertex-proxy` 对 tunnel 的核心依赖
3. Stargate 获得面向 CLI / 长连接的通用能力
4. `vertex-tunnel` 只专注于隧道本身
5. 后续其它机器客户端也可以复用 `/_token`

---

## 20. 最终结论

推荐在 Stargate 中新增一层通用能力：

**Authenticated Session Token Exchange**

该能力：

- 不改变 Stargate 现有 Web 认证主链路
- 以 session 为可信根
- 为指定 audience 签发短期 JWT
- 让 `vertex-tunnel` 直接消费 JWT

这是在“保持 Stargate 通用性”和“支持自有 tunnel 场景”之间最平衡的设计。
