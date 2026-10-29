# 远程 OAuth 接入

本项目是 OAuth **资源服务器**：验证访问令牌，不提供用户注册、登录、同意页或签发令牌。预览模式的随机令牌不是 OAuth。推荐对接已维护的身份服务；不要为了演示自行发明一个生产授权服务器。

## 必须分别配置的三端

1. 身份服务：HTTPS issuer、授权码流程、PKCE S256、授权/令牌端点、公开签名 JWKS；签发 JWT 的 `iss` 精确匹配 issuer，`aud` 包含豆坊公开 MCP URL，`scope` 包含 `forge:use`。授权及换码处理 `resource` 参数。使用可配置、真实用户的 `sub`，不要拿 client_id 当作用户身份。
2. 豆坊：`http.auth_mode=jwt`，填写 `issuer_url`、`resource_url`、`jwks_url`，并把**实际用户 sub**放进 `principals`。只授权必要的主机和命名动作。禁止为了登录方便移除 audience/scope 检查。
3. 客户端：选择预注册（provided）、CIMD 或身份服务支持的 DCR。初始发行建议先验收一个明确预注册的客户端；这不是要求所有提供商必须使用预注册。回调地址从当前 OpenAI 配置页取得并精确注册，不能通配，更不能猜旧文档的 callback。客户端密钥只放提供商和平台的秘密字段，不进仓库或镜像。

`compose.jwt.yaml` 是资源服务器配置覆盖层，并不会替你安装上述身份服务。公开访问要配置独立 HTTPS 入口，转发 MCP 路径及 `/.well-known/oauth-protected-resource...` 路径。元数据端点可匿名读取，MCP 工具仍须 Bearer 校验。

## 安装前的只读自检

在已经审查过的管理员配置上运行（不要接受模型传来的任意配置 URL）：

```sh
douforge --config /path/to/config.json oauth-check --registration provided
```

自建 CA 可显式指定 `--ca-file /path/to/trusted-ca.pem`，不支持关闭 TLS 校验。检查器不发送令牌或 client secret、不发起登录、不修改提供商、不跟随重定向，不读取环境代理凭据。只访问配置中确定的资源端点、issuer 元数据和 JWKS。

scopes_supported 是 RFC 9728 可选字段；缺失或未完整列出 forge:use 时
会出现 warnings，建议检查初始 401 的 WWW-Authenticate scope，
不能因此跳过令牌的实际 scope 校验。若该字段存在但为空数组或不是非空字符串数组，仍阻断自检。

输出 `metadata_ready` 仅表示所检查的公开元数据相符；它**不验证签发、PKCE 实际执行、JWT 签名、登录同意、刷新、撤销、用户映射或 ChatGPT 接入**。返回值保留 `login_verified=false` 和 `chatgpt_verified=false`。这些必须通过真实交互另行验收。

## 实际验收顺序

先用无凭据请求验证 MCP 返回401且能够发现受保护资源元数据；验证 issuer 发现和签名公钥。再完成授权码+PKCE登录，确认访问令牌绑定正确 resource；错误audience、scope、过期令牌和未授权subject必须拒绝。最后在普通 ChatGPT 新建测试连接，调用 `bus_hosts`，仅授权只读测试，记录版本、时间、请求回执和退出码。没有走最后一步，不标记“ChatGPT端到端通过”。

受保护资源自检与原生/容器 SSH 是不同验收项。禁止用旧私人豆坊的成功记录代替新社区版。

## 身份服务选择说明

Keycloak 有官方 MCP 接入说明，但不同版本对 resource indicators 和 CIMD 的支持及特性开关不同。不要仅因文档上出现 MCP 就承诺某镜像版本完全兼容；选择固定版本，对实际生成的 metadata、`resource` 处理和 token audience 做端到端验收。本次未部署或验收外部身份服务。

## 官方参考（2026-10-22 查阅）

- OpenAI 身份验证：https://developers.openai.com/plugins/build/auth
- MCP 授权规范：https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/docs/specification/2025-11-25/basic/authorization.mdx
- Keycloak MCP：https://www.keycloak.org/securing-apps/mcp-authz-server

这些是动态文档。具体回调和注册方式以当前客户端配置页、所用规范版本和实际授权服务能力为准。
