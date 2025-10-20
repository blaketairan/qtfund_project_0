# QTFund 认证系统部署指南

## 📋 概述

本文档详细说明如何部署和维护QTFund认证系统，包括认证服务、nginx配置和系统集成。

## 🏗️ 系统组件

### 认证服务 (Project_0)
- **位置**: `/data/terrell/workspace/qtfund_project_0`
- **端口**: 9000
- **功能**: JWT认证、用户管理、Cookie设置

### nginx反向代理
- **配置文件**: `qtfund_project_0/nginx/qtfund.com.conf`
- **功能**: auth_request、SSL终端、请求路由

### 管理工具
- **nginx管理脚本**: `manage_nginx.sh`
- **功能**: 配置同步、测试、重新加载

## 🚀 快速部署

### 1. 准备环境

```bash
# 确保已安装必要软件
sudo apt update
sudo apt install python3 python3-venv python3-pip nginx openssl

# 进入项目目录
cd /data/terrell/workspace/qtfund_project_0
```

### 2. 设置Python环境

```bash
# 创建虚拟环境
python3 -m venv venv
source venv/bin/activate

# 安装依赖
pip install -r requirements.txt
```

### 3. 初始化数据

```bash
# 创建数据目录
mkdir -p data

# 初始化用户数据
python3 -c "
import os, json, bcrypt
from datetime import datetime

# 创建数据目录
os.makedirs('data', exist_ok=True)

# 初始化用户数据
users_data = {
    'users': {},
    'next_id': 1,
    'version': '1.0',
    'last_updated': datetime.utcnow().isoformat() + 'Z'
}

# 创建管理员
password_hash = bcrypt.hashpw('admin123'.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
users_data['users']['1'] = {
    'id': 1,
    'username': 'admin',
    'password_hash': password_hash,
    'email': 'admin@qtfund.local',
    'real_name': '系统管理员',
    'role': 'admin',
    'status': 'active',
    'created_at': datetime.utcnow().isoformat() + 'Z',
    'updated_at': datetime.utcnow().isoformat() + 'Z',
    'login_count': 0
}
users_data['next_id'] = 2

with open('data/users.json', 'w') as f:
    json.dump(users_data, f, indent=2, ensure_ascii=False)

# 创建其他数据文件
for filename in ['login_logs.json', 'permissions.json', 'token_blacklist.json']:
    with open(f'data/{filename}', 'w') as f:
        json.dump({
            'data': [],
            'last_updated': datetime.utcnow().isoformat() + 'Z'
        }, f, indent=2)

print('✅ 数据初始化完成')
print('👤 管理员账号: admin/admin123')
"
```

### 4. 启动认证服务

```bash
# 开发模式启动
python simple_auth.py

# 或者后台运行
nohup python simple_auth.py > logs/auth_service.log 2>&1 &
```

### 5. 部署nginx配置

```bash
# 使用管理脚本部署
./manage_nginx.sh deploy

# 或者手动部署
sudo cp nginx/qtfund.com.conf /etc/nginx/conf.d/
sudo nginx -t
sudo nginx -s reload
```

### 6. 验证部署

```bash
# 检查认证服务
curl -s http://localhost:9000/health

# 检查nginx配置
./manage_nginx.sh test

# 测试完整认证流程
curl -s https://qtfund.com/api/auth/login -k \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123","use_cookie":true}' \
  -c /tmp/test_cookies.txt

curl -s https://qtfund.com/api/users -k -b /tmp/test_cookies.txt
```

## 🔧 nginx管理

### 使用管理脚本

```bash
# 显示帮助
./manage_nginx.sh help

# 部署项目配置到系统
./manage_nginx.sh deploy

# 备份系统配置到项目
./manage_nginx.sh backup

# 比较配置差异
./manage_nginx.sh diff

# 测试配置语法
./manage_nginx.sh test

# 重新加载配置
./manage_nginx.sh reload

# 查看nginx状态
./manage_nginx.sh status
```

### 手动操作

```bash
# 测试配置文件
sudo nginx -t

# 重新加载配置
sudo nginx -s reload

# 查看nginx日志
sudo tail -f /var/log/nginx/qtfund.com.access.log
sudo tail -f /var/log/nginx/qtfund.com.error.log
```

## 📊 监控和维护

### 健康检查

```bash
# 认证服务健康检查
curl -s http://localhost:9000/health

# nginx健康检查
curl -s https://qtfund.com/nginx-health -k

# 认证服务健康检查(通过nginx)
curl -s https://qtfund.com/auth-health -k
```

### 日志查看

```bash
# 认证服务日志
tail -f logs/auth_service.log

# nginx访问日志
sudo tail -f /var/log/nginx/qtfund.com.access.log

# nginx错误日志
sudo tail -f /var/log/nginx/qtfund.com.error.log
```

### 系统状态

```bash
# 查看认证服务进程
ps aux | grep simple_auth

# 查看nginx状态
systemctl status nginx

# 查看端口监听
netstat -tlnp | grep -E "(9000|80|443)"
```

## 🔐 SSL证书管理

### 当前配置

```bash
# 证书位置
SSL_CERT="/data/terrell/workspace/ssl/qtfund.com.crt"
SSL_KEY="/data/terrell/workspace/ssl/qtfund.com.key"

# 检查证书有效期
openssl x509 -in $SSL_CERT -text -noout | grep -A 2 "Validity"
```

### 更新证书

```bash
# 更新证书文件后重新加载nginx
sudo nginx -s reload

# 或使用管理脚本
./manage_nginx.sh reload
```

## 🚨 故障排除

### 常见问题

1. **认证服务无法启动**
   ```bash
   # 检查端口占用
   netstat -tlnp | grep 9000

   # 检查Python依赖
   pip list | grep -E "(flask|jwt|bcrypt)"

   # 查看错误日志
   python simple_auth.py
   ```

2. **nginx配置错误**
   ```bash
   # 测试配置语法
   sudo nginx -t

   # 查看错误详情
   sudo journalctl -u nginx -f

   # 比较配置差异
   ./manage_nginx.sh diff
   ```

3. **认证失败**
   ```bash
   # 检查认证服务响应
   curl -v http://localhost:9000/api/v1/auth/validate \
     -H "Cookie: token=your_token_here"

   # 查看认证服务日志
   tail -f logs/auth_service.log
   ```

4. **Cookie设置问题**
   ```bash
   # 测试Cookie登录
   curl -s https://qtfund.com/api/auth/login -k \
     -H "Content-Type: application/json" \
     -d '{"username":"admin","password":"admin123","use_cookie":true}' \
     -c /tmp/debug_cookies.txt -v

   # 查看Cookie内容
   cat /tmp/debug_cookies.txt
   ```

### 应急恢复

```bash
# 恢复nginx配置
sudo cp nginx/qtfund.com.conf.backup.* /etc/nginx/conf.d/qtfund.com.conf
sudo nginx -t && sudo nginx -s reload

# 重启认证服务
pkill -f simple_auth.py
source venv/bin/activate
python simple_auth.py &

# 重启nginx
sudo systemctl restart nginx
```

## 📈 性能优化

### 认证服务优化

```bash
# 使用Gunicorn启动(生产环境)
pip install gunicorn
gunicorn -w 1 -b 0.0.0.0:9000 simple_auth:app
```

### nginx优化

```nginx
# 在qtfund.com.conf中添加缓存配置
location /api/auth/ {
    # 缓存认证响应
    proxy_cache_valid 200 1m;
    proxy_cache_methods GET HEAD;
}
```

## 🔄 版本更新

### 更新认证服务

```bash
# 停止服务
pkill -f simple_auth.py

# 更新代码
git pull  # 如果使用git

# 重新安装依赖
pip install -r requirements.txt

# 重启服务
python simple_auth.py &
```

### 更新nginx配置

```bash
# 备份当前配置
./manage_nginx.sh backup

# 部署新配置
./manage_nginx.sh deploy

# 验证配置
./manage_nginx.sh test
```

## 📞 联系支持

如遇到问题，请提供以下信息：

1. 错误日志输出
2. 系统状态 (`./manage_nginx.sh status`)
3. 配置文件差异 (`./manage_nginx.sh diff`)
4. 认证服务健康检查结果

---

**QTFund 认证系统部署指南** - 确保系统稳定可靠运行 🔐