# 第3章 用成熟身份服务建立真实凭据入口

## 先区分身份协议与业务授权

OpenID Connect 在 OAuth 2.0 之上提供认证层。ID Token 面向客户端表达认证结果，Access Token 面向资源服务器表达访问凭据。二者即便都使用 JWT，也不能交换使用。业务 API 应验证面向自己的访问令牌，不应因为 ID Token 看起来有用户名字就接受它。OAuth 也不会自动替你决定某张订单是否属于当前租户。

本书没有实现完整 OIDC Provider。教学 issuer 的 `/login` 是方便本地实验的公开密码入口，缺少标准授权端点、授权码、客户端注册、同意、登录会话、刷新、注销和协议一致性能力。因此它只能帮助复现验证失败，不能拿去接企业登录。成熟身份接入由 Keycloak 的单独路径提供，二者在代码、实验说明和结论中分别标记。

## 真实 Keycloak 路径运行什么

仓库包含 `lab/keycloak-realm.json`，在隔离容器中导入 book realm、两个机密客户端和服务账户。两个服务账户都获得 agent-order-reader 角色，但只有 agent-tool 被允许映射；角色通过显式请求的可选 roles scope 进入令牌。两个客户端都关闭标准浏览器流程和密码授权，只开启服务账户。我们实际请求 `/protocol/openid-connect/token` 的 client_credentials，随后从 discovery 确认 issuer 和固定 JWKS URI，下载 RSA 公钥并验签。

令牌的 audience 由显式 audience mapper 加入 tool-proxy。服务身份适配器检查 RS256、issuer、audience、expiry、issued-at、非空 subject、authorized party 和业务角色，然后执行 Acme 订单只读策略。对于相同的真实签发令牌，更改预期 audience 必须失败；请求其他 realm 也必须失败。测试等待十二秒的实验令牌真实到期，确认随后被拒绝，再获取新令牌恢复成功。

容器启动和测试命令见实验 README 与工作流。关键运行命令如下：

```sh
KEYCLOAK_REALM_URL=http://127.0.0.1:9180/realms/book \
 go test -race -run TestRealKeycloakWorkload -v ./lab
```

如果没有这个环境变量，该测试明确标记为跳过，绝不使用教学签发器替代成功。GitHub Actions 会启动真实 Keycloak，并设置变量执行，因此 CI 中这条路径必须实际通过。

## 浏览器登录还需要什么

面向真实员工的交互式登录通常应使用 Authorization Code + PKCE，并校验 state、redirect URI、issuer 与 ID Token 的 nonce 等适用约束。浏览器中的长期机密不可靠，前端代码不能保守一个共享 client secret。授权码被截获、重定向地址过宽、登录 CSRF 和令牌混淆都需要协议级处理。RFC 9700 总结了现代 OAuth 的安全实践；工程上应使用成熟客户端库和身份平台集成。

这些用户登录能力在本书没有运行。我们不把服务账户令牌解释成用户认证证据，也不把“Keycloak 能做”写成“本项目已经测过”。如果你替换成自己的企业登录，验收必须新增浏览器跳转、PKCE、会话续期、退出、跨标签页与账户切换测试；仅凭本章测试不足以批准该上线范围。

## 失败案例与实验边界

一个团队接入 OIDC 后，将用户 ID Token 直接转给订单服务。订单服务只验签，没有检查 audience。结果另一应用获取的合法 ID Token 也能访问订单接口。这不是 RSA 的问题，而是接收者错误地接受了不属于自己的凭据。运行 `TestSignedHTTPBoundaries` 能在教学环境复现同类受众错误；真实 Keycloak 测试另行证明成熟签发方的访问令牌也必须检查受众。

discovery 是配置发现工具，不是从任意用户输入学习信任根的机制。本书把 realm URL 固定在测试环境配置中，并要求 discovery 返回精确匹配的 issuer 与预期 certs 路径。生产环境还需 HTTPS、证书验证、域名与出口策略、缓存及配置变更管理。本地 HTTP 只用于环回实验，没有跨网络机密性保证。

练习：在公司身份平台中找到一次实际 Access Token，离线查看其声明结构，但不要把令牌上传到第三方解码网站。记录 issuer、audience、有效期、客户端标识与角色来源。再找到对应的 ID Token，解释为何两者不能因为“都是 JWT”就混用。

## 为什么还要验证客户端与角色

一个 realm 通常包含多个应用。只验证 issuer 会让同一 realm 中任何合法令牌都有机会到达你的代理；只验证 audience，又可能让被错误配置 audience mapper 的客户端混进来。本书进一步检查 authorized party 与角色，明确只有 agent-tool 服务账户具备本地映射资格。untrusted-tool 同样得到真实签名、相同角色和 tool-proxy 受众，却因为客户端不匹配被拒绝；agent-tool 不请求 roles scope 时，客户端匹配但角色缺失，也必须拒绝。

这不是建议所有产品都机械使用同样字段。不同身份平台对于客户端标识、服务账户和角色的声明有不同语义，应以实际文档和令牌样本为准。映射的本质是把外部身份事实转换成内部权限边界，并让该转换可审核。客户端凭据授权尤其需要注意，它表达的是应用自身，不能因为令牌含有一个 subject 就解释成真人登录。

实际接入时还应记录 realm 导入版本、容器版本、客户端配置和角色映射。身份产品升级可能改变默认 scope、声明位置或算法偏好；只保留一张登录成功截图无法发现这些变化。本书把 realm 配置和集成测试提交到同一仓库，正是为了让身份配置成为可回归的构建输入。
