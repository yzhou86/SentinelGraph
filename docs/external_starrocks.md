# 接入第三方 StarRocks

平台可连接自建、托管或已有的 StarRocks 集群。它使用 MySQL 协议端口（通常为 `9030`），不会要求数据先复制到本地 Docker 容器。

## 1. 配置运行时连接

将以下内容写入部署环境、Kubernetes Secret 或本地 `.env`（从 `.env.example` 复制）。不要将真实密码提交到 Git。

```bash
STARROCKS_HOST=starrocks.company.internal
STARROCKS_PORT=9030
STARROCKS_USER=ocskg_writer
STARROCKS_PASSWORD=replace-me
STARROCKS_DATABASE=security_lakehouse
STARROCKS_SSL_ENABLED=true
STARROCKS_SSL_VERIFY=true
# 当托管集群使用私有 CA 时：
# STARROCKS_SSL_CA=/run/secrets/starrocks-ca.pem
```

为避免本地启动一套额外的 StarRocks，可使用专用编排文件。应用和 bootstrap 服务会使用同一个配置，因此建表、API 摄入、图查询和检测均指向第三方集群。

```bash
# 首次：对外部集群创建 OCSF 表和可选 HNSW 索引
docker compose --env-file .env -f docker-compose.external.yml run --rm bootstrap

# 后续：仅启动平台 API，不会创建本地 StarRocks 容器
docker compose --env-file .env -f docker-compose.external.yml up --build api
```

## 2. 先进行只读连通性验证

网页首页的“连接外部集群”只做一次 `VERSION()` / `CURRENT_USER()` / `DATABASE()` 握手；密码不被保存或返回。也可从运行环境执行：

```bash
sentinelgraph check-connection
```

握手成功后，再由具备 DDL 权限的账号初始化 schema：

```bash
sentinelgraph bootstrap --vector-index
```

若使用的集群没有启用 StarRocks 实验性向量索引，去掉 `--vector-index` 并设置 `VECTOR_SEARCH_ENABLED=false`；流批接入、图谱和检测仍然可用。

使用 `docker-compose.external.yml` 时，可在 `.env` 中设置 `ENABLE_VECTOR_INDEX=false`，使 bootstrap 自动跳过 HNSW 创建。若设置了 `STARROCKS_SSL_CA`，该路径是 **API 容器内** 的证书路径；请通过 Docker/Kubernetes Secret 将 CA 只读挂载到该位置。

## 权限与网络

- 运行账号需要目标数据库的 `SELECT`、`INSERT`，规则/初始化账号还需要 `CREATE`、`ALTER`；建议分开配置并采用最小权限。
- 允许应用网络访问 FE 的 MySQL 协议端口；不需要暴露 BE 节点。
- 对互联网或跨 VPC 连接启用 TLS、校验证书、使用私网连通性和 Secret 管理器。
- 页面连接测试是运维辅助入口；生产环境必须放在受认证、RBAC、审计和 HTTPS 保护的网关之后。
