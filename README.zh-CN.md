# 豆坊 MCP 社区核心

**让 AI 会话操作你自己的机器，而不是另租一台临时电脑。**

当前为 Apache-2.0 社区候选版 `0.1.0a4`，尚未正式公开发布。仓库根目录包含 Apache-2.0 许可证；此目录是独立安装的社区核心，不是私人版全部工具的脱敏副本。许可证只适用于经过审查的社区树，不适用于私人父仓及其历史。

已实现接口：`bus_hosts` 主机目录、`bus_plan` 计划、`bus_exec` 执行、`bus_receipt` 回执。
协议层使用官方 MCP Python SDK；执行层使用系统 OpenSSH；计划和请求回执保存在本机 SQLite。
不依赖任何外部私有知识库、源码仓、协作服务或 GPU 设备；这些能力本版尚未接入。

## 使用

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
douforge --config examples/config.json check
python -m pytest -q
```

默认没有主机、关闭执行、关闭任意 Shell。安装者需要显式配置自己的 SSH 别名和调用者权限。
默认动作必须经过控制机上的 `douforge ... approve PLAN_ID` 审批；该入口不在 MCP 工具列表中。
对话中的 `confirm=true` 不是人类审批证明。管理员可对明确的命名动作提供持续授权。

HTTP 默认只绑定回环地址，匿名请求拒绝。预览令牌模式只用于本机联调，不能拿去公网部署。
真实远程接入采用已有 OAuth 身份服务签发的 JWT，校验签名、签发者、受众、有效期、scope 和调用者权限。
本包不替用户搭登录服务。**新版的 ChatGPT OAuth 全流程仍待验收，不把私人版的成功记录算给它。**

配置错误时拒绝执行；执行计划绑定调用者和配置摘要；一个计划只能消费一次；相同请求返回原回执。
进程崩溃产生不确定结果时，系统拒绝自动重跑。SSH 超时只保证处理本机 SSH 进程，不保证远端所有子进程已停止。
状态库包含命令及返回内容，属于敏感运行数据；不能上传 GitHub。

完整安装和身份服务配置见 [英文说明](README.md)，安全边界见 [SECURITY.md](SECURITY.md)。
发布仍需许可证/权属确认、完整扫描、异机 SSH 与 ChatGPT 新版联调；不会把“测试通过”写成“生产安全保证”。

## Docker 安装

见 [Docker / Compose 安装与边界](DOCKER.zh-CN.md)。本机预览与远程 JWT 部署分开；不把容器启动成功当成 ChatGPT 完整接入。

## OAuth 接入前检查

远程身份服务的配置与验收见 [OAUTH.zh-CN.md](OAUTH.zh-CN.md)。`douforge --config CONFIG oauth-check` 只检查公开元数据，不能代替真正的登录与普通 ChatGPT 连接验收。
