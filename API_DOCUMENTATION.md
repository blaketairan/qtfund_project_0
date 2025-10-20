# QTFund 认证服务 API 接口文档

## 接口概览

认证服务提供以下主要功能的API接口：
- 用户认证 (登录、注册、登出)
- Token管理 (验证、刷新、撤销)
- 用户管理 (信息查询、修改)
- 管理功能 (用户管理、权限控制)
- Nginx auth_request 集成

**基础URL**: `http://localhost:9000`
**API版本**: v1
**数据格式**: JSON
**字符编码**: UTF-8

---

## 通用响应格式

### 成功响应
```json
{
    "code": 200,
    "message": "success",
    "data": {
        // 具体数据内容
    },
    "timestamp": "2024-10-19T12:00:00Z"
}
```

### 错误响应
```json
{
    "code": 400,
    "message": "error description",
    "error": "ERROR_CODE",
    "details": {
        // 详细错误信息
    },
    "timestamp": "2024-10-19T12:00:00Z"
}
```

### 状态码说明
- `200`: 成功
- `201`: 创建成功
- `400`: 请求参数错误
- `401`: 未认证或认证失败
- `403`: 权限不足
- `404`: 资源不存在
- `409`: 资源冲突 (如用户名已存在)
- `429`: 请求频率限制
- `500`: 服务器内部错误

---

## 1. 认证接口

### 1.1 用户登录

**POST** `/api/v1/auth/login`

获取访问令牌以进行后续API调用。

**请求参数**:
```json
{
    "username": "string",     // 必填，用户名
    "password": "string",     // 必填，密码
    "remember_me": false      // 可选，是否记住登录状态
}
```

**成功响应** (200):
```json
{
    "code": 200,
    "message": "登录成功",
    "data": {
        "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
        "token_type": "Bearer",
        "expires_in": 86400,
        "refresh_token": "refresh_token_string",
        "user": {
            "id": 1,
            "username": "testuser",
            "email": "test@example.com",
            "real_name": "测试用户",
            "role": "user",
            "last_login": "2024-10-19T12:00:00Z"
        }
    }
}
```

**错误响应** (401):
```json
{
    "code": 401,
    "message": "用户名或密码错误",
    "error": "INVALID_CREDENTIALS"
}
```

**限流**: 5次/分钟

### 1.2 用户注册

**POST** `/api/v1/auth/register`

创建新用户账号。

**请求参数**:
```json
{
    "username": "string",     // 必填，3-20字符
    "password": "string",     // 必填，8-50字符
    "email": "string",        // 可选，邮箱地址
    "real_name": "string"     // 可选，真实姓名
}
```

**成功响应** (201):
```json
{
    "code": 201,
    "message": "注册成功",
    "data": {
        "user_id": 123,
        "username": "newuser",
        "email": "new@example.com"
    }
}
```

**错误响应** (409):
```json
{
    "code": 409,
    "message": "用户名已存在",
    "error": "USERNAME_EXISTS"
}
```

### 1.3 用户登出

**POST** `/api/v1/auth/logout`

撤销当前访问令牌。

**请求头**:
```
Authorization: Bearer <access_token>
```

**成功响应** (200):
```json
{
    "code": 200,
    "message": "登出成功"
}
```

### 1.4 刷新Token

**POST** `/api/v1/auth/refresh`

使用refresh_token获取新的access_token。

**请求参数**:
```json
{
    "refresh_token": "string"  // 必填
}
```

**成功响应** (200):
```json
{
    "code": 200,
    "message": "Token刷新成功",
    "data": {
        "access_token": "new_jwt_token",
        "expires_in": 86400
    }
}
```

---

## 2. Nginx Auth Request 接口

### 2.1 认证验证

**GET/POST/PUT/DELETE** `/api/v1/auth/validate`

供Nginx auth_request模块调用的验证接口。

**请求头** (由Nginx传递):
```
X-Original-URI: /api/user/profile
X-Original-Method: GET
Authorization: Bearer <token>
Cookie: auth_token=<token>
X-Real-IP: 192.168.1.100
X-Forwarded-For: 192.168.1.100, 10.0.0.1
```

**成功响应** (200):
```
HTTP Status: 200
Headers:
    X-User-ID: 123
    X-User-Role: user
    X-User-Name: testuser
    X-Permissions: read,write
    X-Token-Expires: 1640995200
```

**失败响应**:
- `401`: 未认证或Token无效
- `403`: 权限不足
- `500`: 服务器错误

### 2.2 权限检查规则

认证服务会根据以下规则检查权限：

```json
{
    "rules": [
        {
            "path": "/api/admin/*",
            "methods": ["*"],
            "required_role": "admin"
        },
        {
            "path": "/api/user/*",
            "methods": ["*"],
            "required_role": "user"
        },
        {
            "path": "/api/public/*",
            "methods": ["GET"],
            "required_role": null
        }
    ]
}
```

---

## 3. 用户管理接口

### 3.1 获取用户信息

**GET** `/api/v1/user/profile`

获取当前用户的详细信息。

**请求头**:
```
Authorization: Bearer <access_token>
```

**成功响应** (200):
```json
{
    "code": 200,
    "data": {
        "id": 1,
        "username": "testuser",
        "email": "test@example.com",
        "real_name": "测试用户",
        "role": "user",
        "status": "active",
        "created_at": "2024-01-01T00:00:00Z",
        "updated_at": "2024-10-19T12:00:00Z",
        "last_login": "2024-10-19T11:30:00Z",
        "login_count": 156
    }
}
```

### 3.2 更新用户信息

**PUT** `/api/v1/user/profile`

更新当前用户的基本信息。

**请求参数**:
```json
{
    "email": "newemail@example.com",
    "real_name": "新名称"
}
```

**成功响应** (200):
```json
{
    "code": 200,
    "message": "用户信息更新成功"
}
```

### 3.3 修改密码

**PUT** `/api/v1/user/password`

修改当前用户密码。

**请求参数**:
```json
{
    "old_password": "string",
    "new_password": "string"
}
```

**成功响应** (200):
```json
{
    "code": 200,
    "message": "密码修改成功"
}
```

### 3.4 获取登录历史

**GET** `/api/v1/user/login-history`

获取当前用户的登录历史记录。

**查询参数**:
- `page`: 页码 (默认1)
- `size`: 每页数量 (默认10)

**成功响应** (200):
```json
{
    "code": 200,
    "data": {
        "logs": [
            {
                "id": 1,
                "ip_address": "192.168.1.100",
                "user_agent": "Mozilla/5.0...",
                "login_time": "2024-10-19T12:00:00Z",
                "success": true,
                "location": "北京市"
            }
        ],
        "pagination": {
            "total": 50,
            "page": 1,
            "size": 10,
            "pages": 5
        }
    }
}
```

---

## 4. 管理员接口

### 4.1 用户列表

**GET** `/api/v1/admin/users`

获取系统用户列表 (仅管理员)。

**查询参数**:
- `page`: 页码
- `size`: 每页数量
- `role`: 角色筛选
- `status`: 状态筛选
- `search`: 搜索关键词

**成功响应** (200):
```json
{
    "code": 200,
    "data": {
        "users": [
            {
                "id": 1,
                "username": "testuser",
                "email": "test@example.com",
                "real_name": "测试用户",
                "role": "user",
                "status": "active",
                "created_at": "2024-01-01T00:00:00Z",
                "last_login": "2024-10-19T11:30:00Z"
            }
        ],
        "pagination": {
            "total": 100,
            "page": 1,
            "size": 10,
            "pages": 10
        }
    }
}
```

### 4.2 更新用户角色

**PUT** `/api/v1/admin/users/{user_id}/role`

修改指定用户的角色。

**路径参数**:
- `user_id`: 用户ID

**请求参数**:
```json
{
    "role": "admin" | "user" | "readonly"
}
```

**成功响应** (200):
```json
{
    "code": 200,
    "message": "用户角色更新成功"
}
```

### 4.3 更新用户状态

**PUT** `/api/v1/admin/users/{user_id}/status`

启用或禁用指定用户。

**请求参数**:
```json
{
    "status": "active" | "disabled"
}
```

### 4.4 删除用户

**DELETE** `/api/v1/admin/users/{user_id}`

删除指定用户 (软删除)。

**成功响应** (200):
```json
{
    "code": 200,
    "message": "用户删除成功"
}
```

### 4.5 系统统计

**GET** `/api/v1/admin/stats`

获取系统统计信息。

**成功响应** (200):
```json
{
    "code": 200,
    "data": {
        "total_users": 1000,
        "active_users": 850,
        "disabled_users": 150,
        "admin_users": 5,
        "today_logins": 120,
        "failed_logins_today": 15,
        "top_ips": [
            {"ip": "192.168.1.100", "count": 50},
            {"ip": "192.168.1.101", "count": 30}
        ]
    }
}
```

---

## 5. 权限管理接口

### 5.1 权限规则列表

**GET** `/api/v1/admin/permissions`

获取所有权限规则。

**成功响应** (200):
```json
{
    "code": 200,
    "data": {
        "rules": [
            {
                "id": 1,
                "path_pattern": "/api/admin/*",
                "method": "*",
                "required_role": "admin",
                "description": "管理员API",
                "enabled": true
            }
        ]
    }
}
```

### 5.2 添加权限规则

**POST** `/api/v1/admin/permissions`

添加新的权限规则。

**请求参数**:
```json
{
    "path_pattern": "/api/special/*",
    "method": "GET",
    "required_role": "user",
    "description": "特殊API访问权限"
}
```

### 5.3 更新权限规则

**PUT** `/api/v1/admin/permissions/{rule_id}`

更新指定的权限规则。

### 5.4 删除权限规则

**DELETE** `/api/v1/admin/permissions/{rule_id}`

删除指定的权限规则。

---

## 6. 系统接口

### 6.1 健康检查

**GET** `/health`

检查服务运行状态。

**成功响应** (200):
```json
{
    "status": "healthy",
    "version": "1.0.0",
    "timestamp": "2024-10-19T12:00:00Z",
    "uptime": 3600,
    "database": "connected",
    "redis": "connected"
}
```

### 6.2 服务信息

**GET** `/api/v1/info`

获取服务基本信息。

**成功响应** (200):
```json
{
    "code": 200,
    "data": {
        "service": "QTFund Auth Service",
        "version": "1.0.0",
        "description": "统一认证服务",
        "features": [
            "JWT认证",
            "用户管理",
            "权限控制",
            "Nginx集成"
        ],
        "endpoints": {
            "auth": "/api/v1/auth/*",
            "user": "/api/v1/user/*",
            "admin": "/api/v1/admin/*"
        }
    }
}
```

---

## 错误代码参考

### 认证相关
- `INVALID_CREDENTIALS`: 用户名或密码错误
- `TOKEN_EXPIRED`: Token已过期
- `TOKEN_INVALID`: Token格式无效
- `USER_DISABLED`: 用户账号已被禁用
- `LOGIN_LOCKED`: 登录失败次数过多，账号被锁定

### 用户管理
- `USERNAME_EXISTS`: 用户名已存在
- `EMAIL_EXISTS`: 邮箱已存在
- `USER_NOT_FOUND`: 用户不存在
- `WEAK_PASSWORD`: 密码强度不足
- `OLD_PASSWORD_INCORRECT`: 原密码错误

### 权限相关
- `INSUFFICIENT_PERMISSIONS`: 权限不足
- `ROLE_NOT_ALLOWED`: 角色不允许此操作
- `ADMIN_REQUIRED`: 需要管理员权限

### 系统相关
- `RATE_LIMIT_EXCEEDED`: 请求频率超限
- `VALIDATION_ERROR`: 输入验证失败
- `INTERNAL_ERROR`: 服务器内部错误
- `DATABASE_ERROR`: 数据库操作失败

---

## 使用示例

### JavaScript/Browser
```javascript
// 登录
const response = await fetch('/api/v1/auth/login', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json'
    },
    body: JSON.stringify({
        username: 'testuser',
        password: 'password123'
    })
});

const data = await response.json();
if (data.code === 200) {
    // 存储token
    localStorage.setItem('access_token', data.data.access_token);
}

// 后续API调用
const userResponse = await fetch('/api/v1/user/profile', {
    headers: {
        'Authorization': `Bearer ${localStorage.getItem('access_token')}`
    }
});
```

### Python/Requests
```python
import requests

# 登录
response = requests.post('http://localhost:9000/api/v1/auth/login', json={
    'username': 'testuser',
    'password': 'password123'
})

data = response.json()
if data['code'] == 200:
    token = data['data']['access_token']

    # 使用token调用API
    headers = {'Authorization': f'Bearer {token}'}
    user_info = requests.get('http://localhost:9000/api/v1/user/profile',
                           headers=headers).json()
```

### cURL
```bash
# 登录
curl -X POST http://localhost:9000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","password":"password123"}'

# 使用token
curl -X GET http://localhost:9000/api/v1/user/profile \
  -H "Authorization: Bearer <your_token>"
```

---

*API文档版本: v1.0*
*最后更新: 2024-10-19*