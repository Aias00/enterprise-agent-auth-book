# 企业 Agent 工具接入：身份委托、授权与审计

作者：Apache ShenYu PMC。面向 Go、Java、网关与 Agent 工程师，18章中文正文超过25000汉字，前言、官方来源/术语/练习与构建时生成的完整代码附录。

- [在线阅读](https://aias00.github.io/enterprise-agent-auth-book/)
- [EPUB下载](https://aias00.github.io/enterprise-agent-auth-book/downloads/enterprise-agent-auth-book.epub)
- [实验下载](https://aias00.github.io/enterprise-agent-auth-book/downloads/lab.zip)
- [版本发布](https://github.com/Aias00/enterprise-agent-auth-book/releases)

书中讨论 Agent 代表谁、对哪个租户的哪个业务对象执行什么，以及审批、撤权、短期委托与审计。执行沙箱、模型网关和RAG文档ACL分别承担其他边界。MCP仅作为接入协议讨论，不是接口目录，不承诺提示注入免疫。

## 真实实验

```sh
go test -race -v ./lab
go run ./lab
```

Go1.24+。三个环回HTTP服务：身份9101、工具代理9102、双租户订单/工单9103；真实Ed25519签名/JWKS验签、issuer/audience/expiry、对象授权、审批摘要与身份绑定、一次消费、撤权版本、密钥轮换、恶意输入和审计脱敏。独立Keycloak容器路径实际执行discovery/JWKS、client_credentials、服务身份角色映射、业务代理授权与真实到期；[实验说明](lab/README.md)提供运行方法，CI会实际执行。

**明确范围：**教学issuer不是OAuth/OIDC产品，`/delegate`不是RFC8693，`/state`不是RFC7662。Keycloak路径使用工作负载身份，未运行用户登录/Code+PKCE、refresh、logout、DPoP或完整token exchange。内存状态、公开开发密钥、固定环回监听，不能部署为生产退款服务。撤权在检查边界生效，检查后在途请求存在竞态。审批实验没有真人认证或职责分离。完整边界见正文与来源附录。

## 阅读与构建

默认浅色，低饱和深色可切换，`aias-reader-theme`与同域其他书共享；目录、全文搜索、字号、无JavaScript阅读，全部章节320/390px验收。源Markdown、网页、EPUB全文逐章一致。下载实验包包含全部Go代码、模块校验、realm配置、README、LICENSE与演示脚本，解压可测试。

依赖Python3、Pandoc3.12.1、Java21、Go1.24；浏览器验收用Playwright1.64.1。构建过程不抓取研究资料。

```sh
python3 scripts/build.py
python3 scripts/verify.py
sh scripts/epubcheck.sh
python3 -m http.server 8767 --bind 127.0.0.1 --directory site
# 另一个终端：node scripts/browser-check.cjs
```

EPUBCheck5.4以警告即失败模式运行。CI还会解压实验包再次测试。Release附件来自同次成功CI artifact，Pages/Release/CI EPUB哈希应一致；精确交付证据保存在DELIVERY.md。该证据文件不触发重新发布。

## 授权

原创正文使用 [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)，署名Apache ShenYu PMC；代码及通用出版工具使用Apache-2.0，见LICENSE。第三方规范和产品文档保留各自权利；引用链接与取读哈希在book/sources.json，本仓库不发布其原始缓存。本书为作者技术作品，不代表Apache软件基金会的官方安全保证。
