# muse-protocol-go

从 muse2api 提取的纯 Go Muse 协议库，提供密码 / 邮箱验证码登录、HTTPS 会话引导、Noise/Hatch 加密通道、对话及图片 / 视频生成方法，可供自己的反代服务调用。

**密码和验证码由使用者自行提供。** 本库不提供账号、注册、密码获取、收件箱、接码平台或验证码代取服务。验证码登录的协议会请求上游发码，然后调用你的 `GetOTP` 回调；密码登录接收你的 `Password` 参数。

这是非官方协议实现。需要已有且可用的 Muse 账号；上游新增验证或改变协议时可能需要调整。首次公开版的验证使用本地模拟服务，不表示所有真实账号均能登录。

## 安装

要求 Go 1.24.0 或更新版本。

```sh
go get github.com/CoolkHz/muse-protocol-go
```

| 包 | 提供的能力 |
| --- | --- |
| `login` | `Login`、`Options`、密码加密与验证码提交、登录后会话验证 |
| `muse` | `NewClient`、`Chat`、`Generate`、`RenewSession`、`Diagnose` |
| `hatch` | `Connect`、`Do`、`OpenContext`、Noise XX、protobuf 封装与流复用 |

无需浏览器。仓库不包含账号池、管理后台或完整的 OpenAI / Anthropic HTTP 服务；可在现有服务中调用以上方法构建反代。

## 密码登录

```go
result, err := login.Login(ctx, login.Options{
    Email:    email,    // 由调用方提供
    Password: password, // 保留原始内容，包括首尾空格
    Proxy:    "direct",
})
if err != nil {
    return err
}
// result.Cookies 用于后续协议调用；不要写入日志。
```

`Password` 与 `GetOTP` 互斥。协议初始化账号时可能由上游发送验证码邮件，密码流程仍使用加密密码确认，不读取验证码，也不会自动改用验证码方式。

## 验证码登录

```go
result, err := login.Login(ctx, login.Options{
    Email: email,
    GetOTP: func(ctx context.Context, sentAt time.Time) (string, error) {
        // 等待你的 UI、终端或已有业务系统提供本次登录的验证码。
        // 自行实现 waitForUserCode，并响应 ctx 取消/超时。
        return waitForUserCode(ctx, sentAt)
    },
})
```

`GetOTP` 在上游确认发码后调用一次。`sentAt` 标记本次发码请求的开始时间；验证码格式校验和提交由库处理，验证码来源由调用方实现。两种登录方式均未配置时会直接返回配置错误。

`login.Options` 还支持 `Timeout`（默认 4 分钟）、`Region`、`OnStage` 和自定义 `Transport`。`OnStage` 只报告固定阶段名称。库不会保存账号密码或验证码；登录结果中的 Cookie 和有效期不参与 JSON 序列化。

## 对话和媒体

```go
client := muse.NewClient(muse.Config{DataDir: "data"})
defer client.Close()

account := &muse.Account{
    ID:            "account-1", // 每个账号使用稳定且唯一的 ID
    Cookies:       result.Cookies,
    CookieExpires: result.CookieExpires,
}
reply, err := client.Chat(ctx, account, "你好", nil, func(delta string) {
    fmt.Print(delta)
})
if err != nil {
    return err
}
_ = reply.Text

files, err := client.Generate(ctx, account, muse.GenRequest{
    Kind: "image", // 或 "video"
    Prompt: "生成一张山间日出图片",
    N: 1,
})
```

媒体保存到 `DataDir/media`，返回文件信息和可识别的宽高、时长。`N` 只限制最多返回的文件数；请求多张时需在 prompt 表达数量，并检查实际 `len(files)`。参考图通过 `[]muse.RefImage{{Data: imageBytes, Mime: "image/png"}}` 提供；对话使用 `Chat` 的 `refs` 参数，生成使用 `GenRequest.Refs`。

每次调用使用账号配置的不可变快照；并发期间不要直接修改其 Cookie map。`SetHooks` 可通知 Cookie 轮换和会话变化，调用方自行同步并持久化后续请求使用的快照。需要长期运行时可 `go client.Janitor(ctx)` 定期回收空闲连接，退出时调用 `Close()`。本库不含账号任务调度、自动重放或额度管理。

代理支持 HTTP(S)、SOCKS5/SOCKS5H；`Account.Proxy` 优先于 `Config.Proxy`，空值继承环境代理，`direct` 表示直连。无效代理会报错。

## 可运行示例

```sh
go build -o bin/muse-protocol ./cmd/muse-protocol
export MUSE_EMAIL='user@example.com'
export MUSE_PROXY=direct

# 成功请求发码后，从终端输入自行获取的验证码。
./bin/muse-protocol --auth otp --mode chat --prompt '你好'

# 密码由你通过环境变量 MUSE_PASSWORD 提供。
./bin/muse-protocol --auth password --mode chat --prompt '你好'

# 生成图片 / 视频；文件写入 ./data/media。
./bin/muse-protocol --auth otp --mode image --prompt '山间日出'
./bin/muse-protocol --auth otp --mode video --prompt '一朵云缓缓飘过天空'

# 只验证登录，或使用自行提供的 MUSE_COOKIE。
./bin/muse-protocol --auth password --mode login
./bin/muse-protocol --auth cookie --mode chat --prompt '你好'
```

示例每次运行独立登录，仅在进程内保存会话，不打印密码、验证码、Cookie 或令牌。`.env.example` 只列出变量；程序不会自动加载 `.env`。完整 SDK 调用参考 [examples/basic](examples/basic/main.go)。

## 协议与验证

- [协议流程和字段](docs/protocol.md)：登录、会话引导、Noise 握手、protobuf、对话轮询和媒体下载。
- [开源整理说明](docs/release-scope.md)：提取范围、脱敏边界与已知限制。
- [来源与许可说明](THIRD_PARTY_NOTICES.md)。本仓库原创代码使用 [MIT License](LICENSE)，第三方内容遵循其自身许可。

```sh
go test -race ./...
go vet ./...
go build ./...
```

测试使用合成账号数据和本地 HTTP / WebSocket 网关，覆盖两种登录、密码加密、Noise 向量、RPC、对话、媒体、并发取消和隐私回归，不需要真实凭据。
