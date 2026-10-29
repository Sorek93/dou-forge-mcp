# Docker / Compose 私有 Alpha 安装

适用范围：社区核心 `0.1.0a4`。镜像内安装同一个 Python 包；不包含 CUDA、模型、私人主机、Git 历史或任何生产凭据。暂不代表公开发行。

## 本地只读 Doctor

在已有的配置下运行 douforge --config /config/config.json --state /data doctor；
在容器外检查时，应改成容器外可访问的配置路径。
Doctor 只读取配置与文件元数据，不运行 SSH、不读取令牌、不改数据库；
offline_preflight_only 绝不代表 ChatGPT OAuth 或目标机 SSH 已验收。
元数据预检 oauth-check 现在将 RFC9728 可选的 scopes_supported 缺失/不完整
记录为 warning，而非误判为协议失败；实际 JWT 的 forge:use 仍强制校验。

## 本机预览

在本目录运行，需要 Python 3（仅初始化脚本）、Docker Engine 28+ 与 Compose 2.24.4+。使用独立目录，不在现网仓库内运行。

```sh
python3 tools/init_docker_preview.py
# 初次构建需要访问镜像源、Debian 软件源和 Python 包源。
docker compose up --build --detach --wait
curl --fail http://127.0.0.1:9384/healthz
docker compose logs --tail=50 forge
```

初始没有主机，执行关闭。初始化脚本拒绝覆盖任何已有 runtime 目录，不读取你已有的 ~/.ssh。
令牌仅存在 `runtime/preview.token`；不要粘贴进聊天、Dockerfile、Git 或命令行参数。
用 Bearer 令牌调用 `/mcp`；缺失/错误令牌应被拒绝。健康检查只报告进程/配置可用，不证明 SSH、身份服务或 ChatGPT 已接通。

容器内部需要监听 `0.0.0.0`，Compose 仅发布宿主机 `127.0.0.1:9384`。
`--container-preview` 是显式例外，程序不能替你验证 Docker 的端口映射或宿主机防火墙。
**禁止把预览模式通过公网隧道/反向代理暴露出去；不要改成 `9384:9384` 或 host network。**
同一容器网络中的进程及宿主机管理员仍属于信任边界。使用专用 Docker 网络/主机。

## 配置、凭据与状态

- 配置：`runtime/config.json` 只读挂载；只添加你明确授权的主机和操作。
- SSH：`runtime/ssh` 只读挂载到 `/home/douforge/.ssh`。需要操作者单独准备经核验的 known_hosts 和最小权限账号，不自动导入宿主机的整套 ~/.ssh。
- 使用独立 SSH 私钥时，确保容器 UID 10001 可读取，文件 owner/权限满足 OpenSSH 要求。不要把私钥 chmod 为全员可读；可由管理员安排 owner=10001、mode=0400 的专用副本或合适的 secret 管理。
- 预览令牌文件模式0444、父目录0700：父目录限制宿主机普通用户遍历，单文件只读挂载让非root容器可读。Compose 本地文件型 secret 不是加密保险箱，Docker/宿主机管理员仍可访问。
- 计划和回执：命名卷 `forge_state`；容器 UID/GID=10001，首次卷初始化目录0700。已有不兼容卷应单独迁移，不要以放宽权限绕过检查。
- 不挂载 Docker socket；容器无 GPU、无 privileged，根文件系统只读，限制 CPU/内存/PID，日志轮转。它仍然不是对远程 SSH 命令的沙箱。

本地审批使用与服务相同的配置与数据卷，仍不向 MCP 客户端暴露自审批：

```sh
docker compose exec forge douforge --config /config/config.json --state /data approve PLAN_ID
```

停止服务保留数据：`docker compose down`。不要随意加 `--volumes`。
修改预览令牌或 HTTP 鉴权配置后需要重建/重启服务；不要依赖热加载实现令牌轮换。

## 面向远程客户端的 JWT 部署

先将 `runtime/config.json` 改为有效的 JWT 配置（受信 HTTPS issuer、JWKS、resource URL、调用者授权），再使用覆盖文件：

```sh
docker compose -f compose.yaml -f compose.jwt.yaml config
docker compose -f compose.yaml -f compose.jwt.yaml up --build --detach --wait
```

覆盖文件移除 preview secret 与 `--container-preview`，而不是把预览口开放到公网。默认仍仅绑定宿主机回环，由操作者管理 HTTPS 反向代理与 OAuth 2.1 授权服务。反向代理须正确保留已配置 resource 的 Host；不要盲目信任客户端提供的代理头。
**此包没有内置 OAuth 登录/同意页；ChatGPT 完整 OAuth 接入仍是独立验收项。**

## 测试与多架构

```sh
docker build --target test -t dou-forge-test:local .
docker build --target runtime -t dou-forge-mcp:0.1.0a4-local .
# 在全新测试目录初始化，端口与测试脚本保持一致：
python3 tools/init_docker_preview.py --port 19384
python3 tools/container_smoke.py --project douforge-test-local --port 19384 --report smoke.json
```

Dockerfile 不硬编码 CPU 架构，可供 Buildx 构建 amd64/arm64；是否实际通过以测试记录为准。
基镜像目前使用可更新的 `python:3.13-slim-bookworm` 标签，传递依赖未全部锁版本；**不声称位级可复现或已完成供应链审计**。正式发布前固定验证的基镜像digest、依赖锁和扫描结果。

GitHub 放源码，GHCR 发镜像的路线不变；当前不推镜像、不使用私人 Git 历史公开发版。包与镜像的许可证/发布权审核仍未完成。

## 参考

- Docker构建建议：https://docs.docker.com/build/building/best-practices/
- Compose secrets：https://docs.docker.com/compose/how-tos/use-secrets/
- 端口发布：https://docs.docker.com/engine/network/port-publishing/
