# 2c2a主机端自动化部署程序

这是一个用于在Windows主机上进行一次性自动化初始化的脚本，它会配置WinRM服务以支持远程管理，并在完成后自毁，实现ZeroAgent架构。

## 描述

2c2a主机端自动化部署程序是一个用于在Windows主机上进行一次性自动化初始化的工具。它会配置WinRM服务以支持远程管理，并在完成后自毁，实现ZeroAgent架构。

## 功能特性

- 启用并配置WinRM服务
- 安装CA根证书和服务器证书
- 配置WinRM HTTPS监听器
- 设置防火墙规则
- 向C端报告初始化状态
- 脚本自毁功能

## 使用方法

### 直接运行Python脚本

```bash
python h_side_init.py <secret>
```

其中 `<secret>` 是从C端获取的包含C端URL和认证令牌的Base64编码字符串。

### 使用可执行文件

运行构建后的exe文件：

```bash
h_side_init.exe <base64_encoded_secret>
```

### Dry Run模式

可以使用 `--dry-run` 参数查看将要执行的操作而不实际执行：

```bash
python h_side_init.py --dry-run <base64_encoded_secret>
```

## 构建可执行文件

### 本地构建

运行构建脚本：

```bash
python build_exe.py
```

这将自动安装依赖并使用Nuitka构建exe文件。

### 使用Nuitka直接构建

```bash
pip install nuitka
python -m nuitka --standalone --onefile --windows-disable-console --output-filename=h_side_init.exe h_side_init.py
```

## GitHub Actions自动构建

本项目配置了GitHub Actions工作流，当推送到main或master分支时，会自动：
- 安装依赖
- 使用Nuitka构建exe文件
- 上传构建产物

当创建标签（tag）时（如 `v1.0.0`），会自动构建exe并将其发布到GitHub Release页面。

## ZeroAgent架构

脚本在执行完成后会自动删除自身文件，不留任何长期运行的代理程序，符合ZeroAgent设计原则。

## 安全注意事项

- 脚本只在Windows系统上运行
- 需要管理员权限来配置WinRM和安装证书
- 脚本执行完后会自毁，不留痕迹

## 构建目录

- `.nuitka-build/` - 存放Nuitka构建过程中的中间文件