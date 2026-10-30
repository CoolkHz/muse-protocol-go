# 来源与第三方许可

本仓库从本地 muse2api Go 实现中提取登录、HTTPS 会话引导、Noise/Hatch、对话和媒体协议代码。根目录的 [MIT License](LICENSE) 适用于本仓库作者有权许可的原创贡献，不替代第三方内容的许可，也不授予 Muse 或 Meta 的商标、服务或账号访问权。

## 协议研究与实现参考

原项目记录了以下协议研究与实现参考，本仓库保留其归属：

| 项目 | 参考范围 |
| --- | --- |
| [minhquan130599/MuseAI-API](https://github.com/minhquan130599/MuseAI-API) | Muse / Hatch 协议研究，Noise XX、protobuf 和会话引导实现 |
| [its-benjamin/muse2api-http](https://github.com/its-benjamin/muse2api-http) | 网页协议的 HTTP 引导、VM 唤醒、Noise/Hatch 封装、对话历史及媒体流程 |

截至 2026-10-30 整理时，上述两个仓库的默认分支文件树和项目元数据中未发现明确的许可文件或许可声明。公开可读不等于获得 MIT 授权；本仓库的 MIT License 不对这些项目的作品重新授权。本说明保留已知参考来源，不声称参考仅限于字段或行为，也不证明实现的独立创作来源。复用这些项目的代码或其他内容时，应另行核实其授权。

## Noise 测试向量

`hatch/vector_test.go` 的六条消息及 `hatch/noise_test.go` 的固定测试密钥、prologue 和握手哈希来自 Cacophony 的 `Noise_XX_25519_AESGCM_SHA256` 公开向量。这些固定值仅用于测试，不是实际账号凭据。

- [向量文件](https://github.com/haskell-cryptography/cacophony/blob/8ee9d41e34a1a596cfa3ab12aa4069ff87dc1247/vectors/cacophony.txt)
- [该版本的 Unlicense](https://github.com/haskell-cryptography/cacophony/blob/8ee9d41e34a1a596cfa3ab12aa4069ff87dc1247/LICENSE)
- [随仓库保留的 Unlicense 全文](LICENSES/cacophony-Unlicense.txt)

## Go 模块依赖

依赖通过 `go.mod` / `go.sum` 引用，未将其源码复制到 vendor 目录。

| 模块 | 版本 | 许可及版权 |
| --- | --- | --- |
| `golang.org/x/crypto` | v0.45.0 | [BSD-3-Clause](https://github.com/golang/crypto/blob/v0.45.0/LICENSE)，Copyright 2009 The Go Authors. |
| `golang.org/x/sys`（间接依赖） | v0.38.0 | [BSD-3-Clause](https://github.com/golang/sys/blob/v0.38.0/LICENSE)，Copyright 2009 The Go Authors. |

这两个版本随附的许可文本相同，完整文本保留于 [LICENSES/go-BSD-3-Clause.txt](LICENSES/go-BSD-3-Clause.txt)。分发包含这些依赖的二进制时，应保留相应版权、许可条件和免责声明。
