# Banner 指纹识别系统

## 任务说明

使用 Golang 语言开发一个 Banner 指纹识别系统，能力为接收一批网络扫描原始数据（ip、port、banner），识别出对应的协议、软件与版本信息，并以 client + server 架构、Docker Compose 一键启动的方式交付。系统输出的识别深度至少要达到示例所示。

## 架构说明

### 整体架构

```
┌─────────────────────────────────────────────┐
│                  Server                      │
│  (Docker Compose 服务)                      │
│  ┌──────────────────────────────┐           │
│  │     API Gateway              │           │
│  │  (Gin + Middleware)          │           │
│  │                              │           │
│  │  ┌──────────────────────┐    │           │
│  │  │   Banner Service     │    │           │
│  │  │  (Golang 指纹识别)   │    │           │
│  │  │                      │    │           │
│  │  └──────────────────────┘    │           │
│  │                              │           │
│  │  ┌──────────────────────┐    │           │
│  │  │   Database Service   │    │           │
│  │  │  (SQLite/Postgres)   │    │           │
│  │  │                      │    │           │
│  │  └──────────────────────┘    │           │
│  └──────────────────────────────┘           │
└─────────────────────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────┐
│                  Client                      │
│  (CLI Tool)                                 │
│  ┌──────────────────────┐                   │
│  │   指纹识别命令行     │                   │
│  │  (Golang CLI)        │                   │
│  │                      │                   │
│  └──────────────────────┘                   │
└─────────────────────────────────────────────┘
```

### 核心组件说明

1. **Server 端**
   - API Gateway：接收 HTTP 请求，使用 Gin 框架
   - Banner Service：核心指纹识别逻辑，处理协议识别、软件版本判断
   - Database Service：存储识别结果和历史数据

2. **Client 端**
   - 命令行工具：提供 `banner scan`、`banner identify` 等命令
   - 支持批量处理网络扫描数据

3. **Docker Compose**
   - 一键启动包含 Server 和 Client 的完整环境
   - 支持开发模式和生产模式

### 数据处理流程

1. Client 接收网络扫描原始数据（ip:port:banner 格式）
2. 通过 HTTP API 提交到 Server
3. Server 进行协议识别、软件版本判断
4. 返回识别结果（JSON 格式）
5. Client 展示最终结果

### 输出要求

识别深度至少达到示例所示（具体示例请参考后续提供的测试数据格式）。

## 开发命令

### 项目初始化
```bash
# 克隆项目（如果需要）
git clone <project-url> banner-fingerprint
cd banner-fingerprint/Banner

# 初始化 Go 模块
go mod init github.com/yourname/banner-fingerprint
go mod tidy
```

### 开发命令
```bash
# 运行服务器（开发模式）
go run cmd/server/main.go

# 运行客户端
go run cmd/client/main.go

# 构建所有二进制文件
go build -o bin/ ./cmd/...

# 运行测试
go test ./... -v

# 运行特定测试
go test ./internal/fingerprint -v -run TestProtocolIdentification

# 格式化代码
go fmt ./...
gofmt -s -w .

# 静态检查
golangci-lint run

# 编译为 Docker 镜像
docker build -t banner-fingerprint/server .
```

### Docker Compose
```bash
# 启动完整服务
docker-compose up -d

# 停止服务
docker-compose down

# 查看日志
docker-compose logs -f

# 进入容器
docker-compose exec server bash
```

## 代码结构

```
banner-fingerprint/
├── cmd/
│   ├── server/          # Server 端主程序
│   │   └── main.go
│   └── client/         # Client 端主程序
│       └── main.go
├── internal/
│   ├── fingerprint/     # 指纹识别核心逻辑
│   │   ├── protocol.go     # 协议识别
│   │   ├── service.go      # 识别服务
│   │   └── models/         # 数据模型
│   ├── api/                # API 相关
│   │   └── handler.go
│   └── database/           # 数据库操作
├── pkg/                    # 共享包
│   └── utils/              # 工具函数
├── config/                 # 配置文件
│   └── config.yaml
├── docker/
│   └── compose.yml         # Docker Compose 配置文件
└── tests/                  # 测试数据和测试用例
    └── test_data.json
```

## 后续步骤

1. 完成核心指纹识别功能（协议识别、软件版本判断）
2. 实现 Server API 接口
3. 开发 Client 命令行工具
4. 编写 Docker Compose 配置
5. 准备测试数据和测试用例
6. 完成文档和示例运行

请提供测试数据后，我将按照这个架构逐步实现。