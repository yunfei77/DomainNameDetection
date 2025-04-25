# 域名信息检测工具 (Domain Information Detection Tool)

这是一个功能强大的域名信息检测工具，可以帮助用户快速获取和分析域名的各种相关信息。

## 功能特点

1. **WHOIS信息查询**
   - 注册商信息
   - 域名创建时间
   - 域名到期时间
   - 最后更新时间
   - 域名状态
   - 域名服务器信息

2. **DNS记录查询**
   - A记录（IPv4地址）
   - AAAA记录（IPv6地址）
   - MX记录（邮件服务器）
   - NS记录（域名服务器）
   - TXT记录
   - CNAME记录（别名）

3. **SSL证书状态检查**
   - SSL证书有效性验证
   - HTTP状态码检查
   - 连接状态监测

4. **智能URL解析**
   - 支持直接输入完整URL
   - 自动提取域名进行检测
   - 支持多种URL格式

## 安装要求

1. Python 3.6 或更高版本
2. 必需的Python包：
```bash
pip install python-whois
pip install dnspython
pip install requests
pip install colorama
```

## 使用方法

1. **直接运行脚本**：
```bash
python DomainNameDetection.py
```

2. **输入格式支持**：
   - 直接输入域名：`example.com`
   - 输入完整URL：`https://www.example.com/path?query=1`
   - 带端口的URL：`example.com:8080`
   - 带认证信息的URL：`user:pass@example.com`

3. **使用示例**：
请输入域名或URL: https://www.baidu.com/s?wd=test
从URL中提取的域名: www.baidu.com
正在检测域名: www.baidu.com
## 输出信息

1. **WHOIS信息**
   - 显示域名的注册和所有权信息
   - 包含重要的日期信息
   - 显示域名当前状态

2. **DNS记录**
   - 显示所有可用的DNS记录
   - 清晰的记录类型分类
   - 详细的记录值信息

3. **SSL状态**
   - SSL证书有效性
   - 连接状态
   - HTTP响应代码（如果可用）

## 错误处理

工具包含完善的错误处理机制：
- 域名格式验证
- 网络连接错误处理
- DNS解析错误处理
- SSL证书验证错误处理
- 超时处理

## 注意事项

1. 确保有稳定的网络连接
2. 某些域名可能因为权限限制无法获取完整的WHOIS信息
3. SSL检查可能受到网络条件的影响
4. 部分DNS记录可能因为服务器配置而无法获取

## 开发者信息

- 工具使用Python开发
- 采用面向对象的设计方式
- 支持跨平台运行
- 代码注释完善，易于维护和扩展

## 更新日志

### v1.0.0
- 初始版本发布
- 支持基本的域名信息检测
- 实现URL智能解析功能
- 添加彩色输出支持
