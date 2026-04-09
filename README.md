# Run

Run 是一个面向现代代理场景的开源代理核心，融合了多种主流项目的优点：

- 类 Clash/Mihomo 的规则路由和分组模型
- 类 sing-box 的模块化配置与协议抽象
- 类 V2Ray/Xray 的多协议节点兼容（SS/VMess/VLESS/Trojan/Hy2）
- 内置 DNS、Fake-IP、Dashboard API、订阅拉取能力

当前版本为可运行 MVP，重点是架构清晰和可扩展，便于后续继续增强协议细节。

## 已实现能力

- 入站
- SOCKS5
- HTTP/HTTPS CONNECT

- 出站协议
- DIRECT / REJECT
- Shadowsocks（AEAD）
- VMess（基础实现）
- VLESS（基础实现）
- Trojan（基础实现）
- Hysteria2（接口占位，待接入 quic-go）

- 分组
- `select`
- `url-test`
- `fallback`
- `load-balance`

- 规则
- DOMAIN / DOMAIN-SUFFIX / DOMAIN-KEYWORD
- IP-CIDR / IP-CIDR6 / GEOIP / GEOSITE（接口预留）
- PROCESS-NAME / SRC-IP-CIDR / DST-PORT / SRC-PORT / MATCH

- DNS
- UDP/TCP DNS
- DoT/DoH
- Fake-IP 地址池
- Hosts 与缓存

- 控制面
- REST API（模式切换、节点状态、Selector 切换）
- 订阅定时拉取（原文保存）

## 目录结构

- `main.go` 启动入口
- `config/` 配置模型与解析
- `core/` 引擎组装、路由、隧道
- `proxy/inbound/` 入站实现
- `adapter/` 出站协议与分组
- `rules/` 规则引擎
- `dns/` DNS 与 Fake-IP
- `api/` Dashboard REST API
- `subscription/` 订阅管理
- `config/example.yaml` 示例配置

## 快速开始

1. 准备 Go 1.21+
2. 安装依赖

```bash
go mod tidy
```

3. 运行

```bash
go run . -f config/example.yaml
```

4. 检查配置

```bash
go run . -f config/example.yaml -t
```

## API 简要

- `GET /version`
- `GET /configs`
- `PATCH /configs` body: `{"mode":"rule|global|direct"}`
- `GET /proxies`
- `PUT /proxies/:name` body: `{"proxy":"节点名"}`

如设置了 `general.secret`，请求需携带：

`Authorization: Bearer <secret>`

## 说明

- 当前版本重点在架构完整性与模块边界，部分协议实现仍是基础版。
- `hysteria2` 已保留扩展点，后续接入 `quic-go` 可补齐完整能力。
- 若你需要，我可以下一步继续补：
- 完整 WS/gRPC 传输层
- TUN 栈与 UDP 全链路
- GeoIP/GeoSite 数据库接入
- Dashboard 前端页面
