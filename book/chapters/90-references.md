# 附录一：来源、术语与复现实验索引

## 官方来源与取读范围

本书参考以下官方资料。取读日期为 2026 年 10 月 21 日；具体下载字节数与 SHA-256 存在 book/sources.json，原始网页只作本地研究缓存，不进入公开仓库。标准用于解释协议语义，运行结论仅来自本书实验。动态产品文档可能更新，读者应结合当前版本再次核对。

1. [RFC 9700：OAuth 2.0 Security Best Current Practice](https://www.rfc-editor.org/rfc/rfc9700.html)。用于授权码保护、受众限制、令牌泄漏与现代 OAuth 设计讨论。相关章节为第3、4、6、8章。它不证明本书运行了所有推荐能力。
2. [RFC 8725：JWT Best Current Practices](https://www.rfc-editor.org/rfc/rfc8725.html)。用于算法限制、issuer/subject/audience 检查、跨 JWT 混淆与互斥验证规则，见第4、12章。
3. [RFC 9068：JWT Profile for OAuth 2.0 Access Tokens](https://www.rfc-editor.org/rfc/rfc9068.html)。用于区分标准访问令牌 profile 与项目自定义教学 JWT。本书没有声明教学令牌符合整个 profile。
4. [RFC 8693：OAuth 2.0 Token Exchange](https://www.rfc-editor.org/rfc/rfc8693.html)。用于委托、模拟和 act 语义讨论，见第2、6章。实验 `/delegate` 是自定义协议。
5. [RFC 7662：OAuth 2.0 Token Introspection](https://www.rfc-editor.org/rfc/rfc7662.html)。用于在线状态查询概念。教学 `/state` 不实现标准 introspection 请求或响应。
6. [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)。用于 ID Token、认证层和访问令牌区别，见第3章。用户登录流程未在本项目运行。
7. [Keycloak OIDC layers](https://www.keycloak.org/securing-apps/oidc-layers) 与 [Server Administration Guide](https://www.keycloak.org/docs/latest/server_admin/)。用于 discovery、certs、client credentials、服务账户和客户端配置。CI 使用明确版本容器，动态文档不代替版本回归。
8. [MCP Authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization) 与 [Security Best Practices](https://modelcontextprotocol.io/specification/2025-11-25/basic/security_best_practices)。用于受保护资源、令牌透传、混淆代理、会话和 SSRF 讨论，见第7、8、13章。本书不含完整 MCP SDK 实现。
9. [RFC 9449：DPoP](https://www.rfc-editor.org/rfc/rfc9449.html)。用于理解发送者约束令牌的补充方向。DPoP 没有在实验实现，也不会被本书当作已经具备的重放防护。

## 术语表

| 术语 | 本书含义 |
| --- | --- |
| subject | 业务责任主体，实验中为 alice、bob 或 svc-reader |
| actor | 实际执行程序，教学业务凭据为 agent-demo |
| issuer | 受信签发方的精确标识，不从未验证输入推导 |
| audience | 令牌预期接收者，代理与业务使用不同值 |
| scope | 动作资格上限，不能取代对象、状态和审批判断 |
| epoch | 主体授权版本，变化后旧凭据与旧审批失效 |
| JWKS | 公钥集合；kid 只在受信集合中选择密钥 |
| 审批绑定 | 将最终参数摘要、主体、actor、租户、版本和有效期绑定 |
| 幂等 | 同一业务请求重复提交不产生额外副作用，并能确定恢复结果 |
| 撤权窗口 | 权限撤回至各执行边界停止接受旧授权的最大时间 |
| client credentials | 应用代表自身获得访问令牌的 OAuth 授权类型 |
| PKCE | 保护授权码流程的机制；本项目没有运行该流程 |

## 实验矩阵

| 实验 | 真实运行内容 | 明确边界 |
| --- | --- | --- |
| 教学身份链 | 三服务HTTP、Ed25519、JWKS、受众、时限、在线状态 | 非OAuth/OIDC产品 |
| 对象授权 | 双租户订单/工单、scope、状态与对象键 | 无真实数据库与复杂组织关系 |
| 审批 | 参数和身份绑定、过期、版本、一次消费、并发 | 无真人登录与多级审批 |
| 撤权/轮换 | epoch、父子凭据失效、键集重叠/退休、故障关闭 | 检查边界生效，不保证跨服务瞬时栅栏 |
| 恶意输入 | 固定目标、未知字段拒绝、note无执行语义、脱敏 | 不承诺提示注入免疫 |
| Keycloak | 真实discovery/JWKS、服务令牌、受众、到期、角色映射 | 无用户PKCE、刷新、DPoP或标准token exchange |
| 出版 | 源文/网页/EPUB全文一致、实验包哈希、移动端与无JS | 完整性检查不自动评价内容质量 |

## 建议练习路线

先完成第1章的边界图，再完成第5章对象不变量与第9章审批摘要。随后做第10章故障恢复和第11章撤权窗口计算，最后选择第16章的一种语言迁移。对每项练习都应给出合法对照、攻击输入、当前授权事实和预期副作用。不要只写“返回403”，还要说明拒绝依据和对象最终状态。

如果把本书实验接入真实支付、客户数据或企业身份平台，请在独立环境创建新的凭据和数据。公开开发材料只适合环回或隔离 CI。迁移后的新能力需要新的运行记录；原实验通过不能继承为未运行组件的证据。
