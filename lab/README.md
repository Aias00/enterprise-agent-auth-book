# 随书实验

这是可控教学 issuer、工具代理、双租户业务服务，加一条真实 Keycloak 工作负载接入。教学接口不是 OAuth/OIDC，`/delegate` 不是 RFC 8693，`/state` 不是 RFC 7662。所有凭据公开；不要部署到公网或接真实退款。监听固定环回，全部状态内存保存。

## 本地（Go 1.24+，无 Docker）

在解压后的根目录执行：

```sh
go test -race -v ./lab
go run ./lab
```

第一次下载 Go 依赖，需要访问 Go module proxy。`TestRealKeycloakWorkload` 缺少环境变量时明确 SKIP，其他测试全部执行。9101 身份、9102 代理、9103 业务。另开终端执行 `sh lab/demo.sh`，完成读取、获取审批、退款与拒绝重放；令牌仅保存在子进程变量中，不输出。

公开开发凭据：alice/public-alice-pass（acme）、bob/public-bob-pass（beta）、svc-reader/public-svc-pass（acme）；管理员 `public-local-admin-do-not-deploy`，代理 `public-local-proxy-do-not-deploy`，审批渠道 `public-local-approver-do-not-deploy`。这些固定材料只能用于隔离教学。

## 真实 Keycloak（Docker 或 CI）

```sh
docker run --rm -d --name book-keycloak \
 -p 127.0.0.1:9180:8080 \
 -v "$PWD/lab/keycloak-realm.json:/opt/keycloak/data/import/book.json:ro" \
 quay.io/keycloak/keycloak:26.2.5 start-dev --import-realm
curl --fail http://127.0.0.1:9180/realms/book/.well-known/openid-configuration
KEYCLOAK_REALM_URL=http://127.0.0.1:9180/realms/book \
 go test -race -run TestRealKeycloakWorkload -v ./lab
docker stop book-keycloak
```

等待 discovery 可用后执行测试。真实 realm 的 accessTokenLifespan=12 秒供到期实验使用；测试等待真实时间。两个客户端 secret 均为 `public-keycloak-dev-secret`，仅在容器实验。真实服务令牌会通过固定 discovery/JWKS、RSA验签、issuer/audience/expiry、azp与realm角色检查，映射到本地 svc-reader 的 Acme 订单只读权限，再真实HTTP访问业务。此映射是适配器，不是用户委托或标准token exchange。

CI 会执行此路径，不能用本地 SKIP 代替。未运行：用户登录/Code+PKCE、refresh token、logout、DPoP、完整OAuth token exchange、数据库、支付渠道、多级真人审批、不可变审计。撤权在检查边界生效，检查后在途请求存在竞态窗口。
