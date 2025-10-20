# QTFund 认证服务项目

基于 Flask 的轻量级统一认证服务，配合 Nginx auth_request 模块为 QTFund 系统提供集中化用户认证和授权管理。

## 🏗️ 系统架构概览

```
┌─────────────────────────────────────────────────────────────┐
│                         nginx (反向代理)                      │
│                      https://qtfund.com                     │
└─────────────────────────┬───────────────────────────────────┘
                          │
          ┌───────────────┼───────────────┐
          │               │               │
          ▼               ▼               ▼
┌─────────────────┐ ┌─────────────┐ ┌─────────────┐
│   认证服务       │ │  前端服务    │ │ 后端API服务  │
│  (Project_0)    │ │ (Project_1) │ │ (Project_2) │
│  端口: 9000     │ │ 端口: 3000  │ │ 端口: 8000  │
│                 │ │             │ │             │
│ • 用户管理      │ │ • 登录页面   │ │ • 业务API   │
│ • JWT生成验证   │ │ • 前端页面   │ │ • 数据处理   │
│ • Cookie设置    │ │ • 静态资源   │ │             │
└─────────────────┘ └─────────────┘ └─────────────┘
```

## 🔐 认证流程详解

### 1. 用户访问前端页面流程

```
用户访问 https://qtfund.com/dashboard
                   ↓
            nginx检查Cookie
                   ↓
        ┌──────────┴──────────┐
        │                     │
    有Cookie               无Cookie
        │                     │
        ▼                     ▼
    验证Cookie              跳转登录页
        │                 /login?redirect=/dashboard
        ▼                     │
  ┌─────┴─────┐              ▼
  │           │          用户登录
 有效       无效            │
  │           │              ▼
  ▼           ▼        认证服务验证账密
正常访问    跳转登录           │
页面        页面              ▼
            │            设置HttpOnly Cookie
            │                 │
            └─────────────────▼
                     跳转到原页面(/dashboard)
```

### 2. 前端调用后端API流程

```
前端页面调用 fetch('/api/users')
            ↓
    nginx收到请求 (自动携带Cookie)
            ↓
    执行 auth_request /auth
            ↓
    转发Cookie给认证服务验证
            ↓
        认证服务返回:
        - 200 + 用户信息Headers
        - 401 (认证失败)
            ↓
    ┌───────┴───────┐
    │               │
   200             401
    │               │
    ▼               ▼
nginx提取用户信息   返回401 JSON
并转发到后端API      给前端
    │
    ▼
后端API收到请求 + 用户信息Headers:
- X-User-ID: 1
- X-User-Role: admin
- X-User-Name: admin
```

## 🍪 Cookie认证机制

### Cookie设置 (认证服务)

```python
# 登录成功后设置Cookie
response.set_cookie(
    'token',
    jwt_token,
    max_age=3600,      # 1小时有效期
    secure=True,       # 仅HTTPS传输
    httponly=True,     # 防止XSS攻击
    samesite='Strict'  # 防止CSRF攻击
)
```

### Cookie验证 (nginx + 认证服务)

```nginx
# nginx配置
location = /auth {
    internal;
    proxy_pass http://qtfund_auth/api/v1/auth/validate;
    proxy_set_header Cookie $http_cookie;  # 转发Cookie
}

location /api/ {
    auth_request /auth;  # 验证认证
    # 提取用户信息
    auth_request_set $user_id $upstream_http_x_user_id;
    auth_request_set $user_role $upstream_http_x_user_role;
    # 转发到后端API
    proxy_pass http://qtfund_api;
    proxy_set_header X-User-ID $user_id;
    proxy_set_header X-User-Role $user_role;
}
```

## 🚀 API端点说明

### 认证相关API (认证服务 - Project_0)

| 端点 | 方法 | 说明 | 认证要求 |
|------|------|------|----------|
| `/api/auth/login` | POST | 用户登录，可设置Cookie | 无 |
| `/api/auth/logout` | POST | 用户登出，清除Cookie | 无 |
| `/api/v1/auth/validate` | ALL | 内部验证端点 (nginx使用) | 内部 |
| `/health` | GET | 健康检查 | 无 |

### 登录请求示例

```javascript
// 使用Cookie方式登录
fetch('/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
        username: 'admin',
        password: 'admin123',
        use_cookie: true  // 启用Cookie模式
    })
});

// 后续API调用自动携带Cookie
fetch('/api/users');  // nginx自动验证Cookie
```

## 🛡️ 安全特性

1. **HttpOnly Cookie** - 防止JavaScript访问，避免XSS攻击
2. **Secure标志** - 仅通过HTTPS传输
3. **SameSite=Strict** - 防止CSRF攻击
4. **JWT Token** - 有状态认证，1小时自动过期
5. **nginx auth_request** - 统一认证入口，集中控制
6. **用户信息Headers** - 安全传递用户身份给后端

## 📂 项目结构

```
qtfund_project_0/  (认证服务)
├── README.md                 # 本文档
├── simple_auth.py           # 简化认证服务
├── run.py                   # 完整认证服务启动器
├── app/                     # 完整应用结构
├── config/                  # 配置文件
├── data/                    # 数据存储
│   ├── users.json          # 用户数据
│   ├── login_logs.json     # 登录日志
│   └── ...
├── nginx/                   # nginx配置文件
│   └── qtfund.com.conf     # 主配置文件
└── requirements.txt         # Python依赖
```

## 🔧 部署说明

### 1. 启动认证服务
```bash
cd qtfund_project_0
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python simple_auth.py  # 或 python run.py
```

### 2. 配置nginx
```bash
# 复制配置文件
sudo cp nginx/qtfund.com.conf /etc/nginx/conf.d/
sudo nginx -t
sudo nginx -s reload
```

### 3. 测试认证流程
```bash
# 登录获取Cookie
curl -s https://qtfund.com/api/auth/login -k \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123","use_cookie":true}' \
  -c cookies.txt

# 使用Cookie访问API
curl -s https://qtfund.com/api/users -k -b cookies.txt
```

## 📞 管理员账号

- **用户名**: admin
- **密码**: admin123
- **角色**: admin

## 🔄 更新nginx配置

项目维护nginx配置文件，使用以下命令同步到系统：

```bash
# 从项目更新到系统
sudo cp qtfund_project_0/nginx/qtfund.com.conf /etc/nginx/conf.d/
sudo nginx -t && sudo nginx -s reload

# 从系统备份到项目
sudo cp /etc/nginx/conf.d/qtfund.com.conf qtfund_project_0/nginx/
```