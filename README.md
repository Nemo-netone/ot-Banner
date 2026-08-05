# Banner 指纹识别系统

一个 Go 实现的批量 Banner 指纹识别系统，采用独立 Client + Server 架构。Server 提供 HTTP API，Client 读取本地 JSON 并提交识别；识别规则存放在独立 JSON 文件中，服务启动时校验并编译。

## 能力

- 识别 SSH/OpenSSH、HTTP/nginx/Apache/Jetty/Microsoft-IIS、MySQL、Redis、FTP。
- 提取产品版本和 Banner 中显式出现的 Ubuntu、Debian、CentOS、Windows 提示。
- 支持非标准端口，端口只作为候选加分，不作为唯一识别依据。
- 无法识别时返回稳定的 `protocol: "unknown"`，不会因为单条异常输入导致整批失败。
- 支持 `banner_base64` 传递二进制 Banner，也兼容文本中的 `\\xNN` 转义。

## API

### `GET /health`

规则加载成功后返回：

```json
{"status":"ok"}
```

### `POST /fingerprint`

请求体必须是 JSON 数组：

```json
[
  {"ip":"1.2.3.4","port":22,"banner":"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"}
]
```

返回字段固定为 `ip`、`port`、`protocol`、`product`、`version`、`os_hint`、`confidence`。

请求限制：默认最大请求体 8 MiB、最大批量 1000 条、单条 Banner 64 KiB。方法、Content-Type、JSON 尾部数据和超限请求均有明确 HTTP 错误码。

## 本地运行

```bash
go run ./cmd/server
go run ./cmd/client --file testdata/input.json --server http://localhost:8080
```

也可以先构建：

```bash
go build -o bin/server ./cmd/server
go build -o bin/client ./cmd/client
```

## Docker Compose

生产 Compose 默认只把 Server 放在内部网络，不发布宿主机端口：

```bash
docker compose up -d --build
docker compose ps
docker compose --profile client run --rm client
```

Client 通过 Compose 服务名 `http://server:8080` 访问 Server。容器使用多阶段构建、静态二进制、distroless nonroot、只读文件系统、`cap_drop: ALL`、`no-new-privileges` 和真实 HTTP 健康检查。

如需从宿主机调用，可临时执行：

```bash
docker compose run --rm -p 127.0.0.1:8080:8080 server
```

## 规则

规则文件为 `configs/fingerprints.json`，启动时会检查版本、ID 唯一性、必填字段、置信度、正则和命名捕获组。修改规则后重启 Server 即可生效，无需修改 Go 识别逻辑。

规则支持：

- `priority`：候选优先级。
- `pattern`：Go 正则表达式。
- `version_group`、`os_group`：命名捕获组。
- `confidence`：基础置信度，最终值始终限制在 `[0,1]`。
- `port_hint`：同等候选的轻量加分。
- `os_hints`：独立 OS 提示规则。

标准 JSON 不支持 `\\xNN` 转义。推荐使用 `\\u0000`，或使用：

```json
{"banner":"","banner_base64":"FgMBAKUBAAC="}
```

## 验证

```bash
go test ./...
go test -race ./...
go vet ./...
```

测试覆盖规则识别、版本提取、OS hint、未知输入、非法 JSON 尾部和 Fuzz 不变量。
