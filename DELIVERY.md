# 交付记录：v1.0.1

2026-10-21 实际交付，作者及原创权利人 Aias00。Apache ShenYu PMC 仅是作者个人背景。

## 成品

- 在线阅读：https://aias00.github.io/enterprise-agent-auth-book/
- EPUB：https://aias00.github.io/enterprise-agent-auth-book/downloads/enterprise-agent-auth-book.epub
- GitHub：https://github.com/Aias00/enterprise-agent-auth-book
- 公开 Release：https://github.com/Aias00/enterprise-agent-auth-book/releases/tag/v1.0.1
- 实验包：https://aias00.github.io/enterprise-agent-auth-book/downloads/lab.zip
- 封面：https://aias00.github.io/enterprise-agent-auth-book/assets/cover.svg

18章正文，按源文U+4E00–U+9FFF计25,303汉字；另有前言、来源/术语/练习与自动生成的完整Go代码附录，共21篇阅读单元。副标题为“从真实身份、业务对象到可撤销执行的工程实践”。

## 唯一发布来源

内容提交：`49b91ead9094e13554cbc700d12f33617b1d44a9`。

成功CI：https://github.com/Aias00/enterprise-agent-auth-book/actions/runs/39588610889

- 创建：2026-10-21 10:59:31 UTC。
- build成功：11:01:09 UTC；deploy成功：11:01:52 UTC。
- book-downloads artifact ID：`12340583379`，artifact ZIP digest：`sha256:75e40092640682de0378afade9bc599f79414486c3e092307cc8bcab6c6eea3b`。
- github-pages artifact ID：`12340368637`，artifact digest：`sha256:7b56579279a25a5e9add8517dd82bf1051c1370ac0803988e55c8cd0fe18c798`。

Release全部附件直接由该run的book-downloads artifact下载并上传，没有本地重建。发布后使用匿名HTTPS再次下载Release EPUB，与同run CI EPUB和Pages EPUB逐字节比较。

三处一致的EPUB SHA-256：

```text
3c1f8dfede767cb72c84253fc65b23ce15b59cba40aa88e87df474f056547265
```

EPUB大小：116,259字节。EPUBCheck5.4报告为0 fatals、0 errors、0 warnings、0 infos，报告同在Pages与Release附件。

v1.0.0已撤为非公开draft，未覆盖其附件。唯一公开的完成版本为个人署名及版权更正后的v1.0.1。

## 实际验收

CI实际运行Go1.24.3的 `go test -race -count=1 -v ./lab`：真实三服务HTTP、Ed25519签名/JWKS验签、issuer/audience/expiry/nbf、跨租户与scope拒绝、审批参数/主体/合法actor绑定、过期与旧审批重放、撤权epoch、短凭据、重叠/退休密钥、身份依赖故障关闭、恶意输入和审计脱敏。

独立审阅后补充的退款验收从业务HTTP读取持久结果，拒绝后为paid/0，合法及10并发后为refunded/1200，重放无额外修改。临时删除退款两条赋值的mutation使对应测试失败，之后还原生产代码。审批审计通过实际GET /audit证明approved/executed具有同一非空摘要，原approval ID未泄漏。

真实Keycloak26.2.5容器在最终CI运行。TestRealKeycloakWorkload于11:00:17–11:00:30 UTC通过，耗时12.27秒，包含真实令牌到期等待。实际验证discovery/JWKS、RSA签名、issuer/audience/expiry、client credentials服务身份、显式本地主体映射与业务代理授权。azp与角色各有独立拒绝样本且先验证其前提：有角色但客户端不匹配；客户端匹配但不请求roles scope。

构建完整性逐章证明源Markdown、EPUB、静态网页全文一致。实验ZIP包含Go源文件、go.mod/sum、realm配置、演示脚本、README和LICENSE；对归档精确文件清单及每个字节校验，CI在新目录解压后再次运行实验。首次Go依赖下载需要网络。

最终公网再次验收全部21篇320/390px，包含全部章节无JavaScript阅读、目录、翻页、浅色默认、低饱和深色、搜索、字号、存储不可用降级、下载与无JS异常。另真实跨《AI 网关与模型路由实战》页面验证aias-reader-theme的跨书持久化与标签页同步。报告见evidence/public-reader-v1.0.1.json。公网每篇article正文独立抓取，与当前源文规范化渲染逐篇比较通过，见evidence/public-fulltext-v1.0.1.json。

直接打开最终CI EPUB的OPF，creator=Aias00，rights为“Copyright © 2026 Aias00. 保留所有权利。第三方项目、规范与引用资料保留其各自权利。”；嵌入SVG封面作者为Aias00。实验ZIP的LICENSE、README及metadata.json已实际检查个人署名和保留权利声明。

## 真实边界

教学issuer不是OAuth授权服务器或OIDC Provider，/delegate不是RFC8693，/state不是RFC7662。Keycloak路径是服务账户接入及显式本地权限映射，不是用户委托交换；未运行用户Code+PKCE登录、refresh/logout、DPoP或完整token exchange。没有完整MCP transport/SDK互操作测试；MCP只作协议接入设计解释。

业务对象、审批与审计为内存实现；未连接数据库或支付渠道，没有跨进程事务、结果重放式幂等、真人审批认证/职责分离或不可变审计。撤权在在线检查边界生效，检查后的在途提交有竞态窗口。外部Keycloak角色变更没有在线introspection保证，服务令牌在实验12秒有效期内按签发声明验证。本项目不承诺提示注入免疫。

全部开发凭据公开，只用于固定环回监听或隔离CI。官方资料真实取读，链接、日期及哈希在book/sources.json，原始研究缓存未发布。原创正文、代码、工具及图形归Aias00，第三方资料保留其各自权利。

本记录及evidence目录不参与产品构建，提交这些证据不会重触发发布CI。
