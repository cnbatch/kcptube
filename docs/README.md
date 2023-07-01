# KCP Tube

## 模式介绍

### 支持的模式
目前支持 3 种模式：
- 客户端模式
- 服务端模式
- 中继节点模式

## 用法

### 命令行
`kcptube config.conf`
或
`kcptube config1.conf config2.conf`
如果有多个文件，可以接着补充。

如果想在连接前测试一下连接是否畅通，可以加上 ``--try`` 选项

```
kcptube --try config1.conf
```
或
```
kcptube config1.conf --try
```

#### 客户端与服务端模式示例
请前往[常规配置](client_server_zh-hans.md)介绍页面

#### 中继节点模式示例
请前往[中继模式配置](relay_mode_zh-hans.md)介绍页面

## 参数介绍
请前往[参数列表](parameters_zh-hans.md)

## 配置文件生成器

若需要配置文件生成器，请前往此处：[KCPTube Generator](https://github.com/cnbatch/KCPTubeGenerator)