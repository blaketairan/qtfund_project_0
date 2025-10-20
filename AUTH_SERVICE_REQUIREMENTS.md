# QTFund 认证服务 (auth_request) 需求文档

## 项目概述

### 项目背景
为 QTFund 系统提供统一的认证服务，配合 Nginx auth_request 模块实现对前端项目 (qtfund_project_1) 和后端 API (qtfund_project_2) 的统一鉴权管理。

### 项目目标
- 实现统一的用户认证和授权
- 支持 JWT Token 验证
- 提供细粒度的权限控制
- 与 Nginx auth_request 模块无缝集成
- 支持用户登录、注册、密码管理
- 提供高性能的认证验证服务

### 技术架构
- **开发语言**: Python 3.8+
- **Web框架**: Flask
- **数据库**: SQLite (开发) / PostgreSQL (生产)
- **认证方案**: JWT (JSON Web Tokens)
- **缓存**: Redis (可选)
- **部署端口**: 9000

---

## 功能需求

### 1. 用户管理模块

#### 1.1 用户注册
**功能描述**: 新用户账号注册

**输入参数**:
- username: 用户名 (3-20字符，字母数字下划线)
- password: 密码 (8-50字符，至少包含字母和数字)
- email: 邮箱地址 (可选)
- real_name: 真实姓名 (可选)

**业务规则**:
- 用户名全局唯一
- 密码需要加密存储 (bcrypt)
- 支持邮箱验证 (可选功能)
- 新用户默认角色为 'user'

**响应结果**:
- 成功: 返回用户基本信息
- 失败: 返回具体错误信息

#### 1.2 用户登录
**功能描述**: 用户身份验证并获取访问令牌

**输入参数**:
- username: 用户名
- password: 密码

**业务规则**:
- 验证用户名密码正确性
- 生成 JWT Token (有效期24小时)
- 记录登录日志
- 支持登录失败次数限制 (可选)

**响应结果**:
- 成功: 返回 JWT Token 和用户信息
- 失败: 返回认证失败信息

#### 1.3 用户信息管理
**功能描述**: 查询和更新用户信息

**支持操作**:
- 查询用户详细信息
- 修改用户基本信息
- 修改用户密码
- 用户角色管理 (管理员功能)

### 2. 认证验证模块

#### 2.1 Token 验证 (核心功能)
**功能描述**: 为 Nginx auth_request 提供 Token 验证服务

**输入来源**:
- HTTP Header: Authorization: Bearer <token>
- HTTP Cookie: auth_token=<token>
- Nginx 传递的原始请求信息

**验证流程**:
1. 提取并解析 JWT Token
2. 验证 Token 签名和有效期
3. 检查用户状态 (是否被禁用)
4. 验证请求权限
5. 返回用户信息给 Nginx

**响应格式**:
- 认证成功: HTTP 200 + 用户信息头部
- 认证失败: HTTP 401
- 权限不足: HTTP 403
- 服务错误: HTTP 500

#### 2.2 权限控制
**功能描述**: 基于用户角色和资源路径的访问控制

**角色定义**:
- `admin`: 管理员 - 完全访问权限
- `user`: 普通用户 - 基础功能访问权限
- `readonly`: 只读用户 - 仅查询权限

**权限规则**:
- `/api/admin/*`: 仅 admin 角色
- `/api/user/*`: user 和 admin 角色
- `/api/public/*`: 所有认证用户
- 其他路径: 根据配置决定

#### 2.3 Token 刷新
**功能描述**: 延长 Token 有效期

**业务规则**:
- Token 过期前 2 小时内可刷新
- 刷新后生成新的 Token
- 旧 Token 立即失效

### 3. 安全功能模块

#### 3.1 密码安全
- 使用 bcrypt 加密存储密码
- 支持密码强度检查
- 提供密码重置功能
- 记录密码修改历史

#### 3.2 访问控制
- IP 白名单/黑名单 (可选)
- 登录失败锁定机制
- 异常登录检测
- 会话管理

#### 3.3 日志审计
- 登录/登出日志
- 权限验证日志
- 异常访问日志
- 管理操作日志

---

## API 接口规范

### 1. 认证相关接口

#### POST /login
```json
请求:
{
    "username": "string",
    "password": "string"
}

响应 (成功):
{
    "code": 200,
    "message": "登录成功",
    "data": {
        "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
        "user": {
            "id": 1,
            "username": "testuser",
            "role": "user",
            "real_name": "测试用户"
        },
        "expires_in": 86400
    }
}

响应 (失败):
{
    "code": 401,
    "message": "用户名或密码错误",
    "error": "INVALID_CREDENTIALS"
}
```

#### POST /register
```json
请求:
{
    "username": "string",
    "password": "string",
    "email": "string (可选)",
    "real_name": "string (可选)"
}

响应:
{
    "code": 201,
    "message": "注册成功",
    "data": {
        "user_id": 123,
        "username": "newuser"
    }
}
```

#### POST /logout
```json
请求头: Authorization: Bearer <token>

响应:
{
    "code": 200,
    "message": "退出成功"
}
```

#### POST /refresh
```json
请求头: Authorization: Bearer <token>

响应:
{
    "code": 200,
    "message": "Token刷新成功",
    "data": {
        "token": "new_jwt_token",
        "expires_in": 86400
    }
}
```

### 2. 验证接口 (Nginx auth_request)

#### GET/POST/PUT/DELETE /validate
```
请求头 (Nginx 传递):
- X-Original-URI: 原始请求路径
- X-Original-Method: 原始请求方法
- Authorization: Bearer token 或 Cookie
- X-Real-IP: 客户端IP
- X-Forwarded-For: 代理IP链

响应头 (认证成功):
- X-User-ID: 用户ID
- X-User-Role: 用户角色
- X-User-Name: 用户名
- X-Permissions: 用户权限列表

响应状态码:
- 200: 认证成功
- 401: 未认证或Token无效
- 403: 权限不足
- 500: 服务器错误
```

### 3. 用户管理接口

#### GET /user/profile
```json
请求头: Authorization: Bearer <token>

响应:
{
    "code": 200,
    "data": {
        "id": 1,
        "username": "testuser",
        "email": "test@example.com",
        "real_name": "测试用户",
        "role": "user",
        "created_at": "2024-01-01T00:00:00Z",
        "last_login": "2024-01-02T12:00:00Z"
    }
}
```

#### PUT /user/profile
```json
请求:
{
    "email": "new@example.com",
    "real_name": "新名称"
}

响应:
{
    "code": 200,
    "message": "更新成功"
}
```

#### PUT /user/password
```json
请求:
{
    "old_password": "string",
    "new_password": "string"
}

响应:
{
    "code": 200,
    "message": "密码修改成功"
}
```

### 4. 管理员接口

#### GET /admin/users
```json
请求参数:
- page: 页码 (默认1)
- size: 每页数量 (默认10)
- role: 角色筛选 (可选)

响应:
{
    "code": 200,
    "data": {
        "users": [...],
        "total": 100,
        "page": 1,
        "size": 10
    }
}
```

#### PUT /admin/users/{user_id}/role
```json
请求:
{
    "role": "admin" | "user" | "readonly"
}

响应:
{
    "code": 200,
    "message": "角色更新成功"
}
```

#### PUT /admin/users/{user_id}/status
```json
请求:
{
    "status": "active" | "disabled"
}

响应:
{
    "code": 200,
    "message": "状态更新成功"
}
```

---

## 数据库设计

### 用户表 (users)
```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username VARCHAR(50) UNIQUE NOT NULL,
    password_hash VARCHAR(128) NOT NULL,
    email VARCHAR(100),
    real_name VARCHAR(50),
    role VARCHAR(20) DEFAULT 'user',
    status VARCHAR(20) DEFAULT 'active',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP
);
```

### 登录日志表 (login_logs)
```sql
CREATE TABLE login_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    ip_address VARCHAR(45),
    user_agent TEXT,
    login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    success BOOLEAN,
    error_message TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
```

### Token黑名单表 (token_blacklist)
```sql
CREATE TABLE token_blacklist (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token_jti VARCHAR(50) UNIQUE,
    user_id INTEGER,
    revoked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
```

### 权限配置表 (permissions)
```sql
CREATE TABLE permissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    path_pattern VARCHAR(200),
    method VARCHAR(10),
    required_role VARCHAR(20),
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

---

## 技术实现要求

### 1. 开发环境
- Python 3.8+
- Flask 2.0+
- SQLAlchemy 1.4+
- PyJWT 2.4+
- bcrypt 3.2+
- Flask-CORS
- python-dotenv

### 2. 配置管理
```python
# config/settings.py
class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key')
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', 'jwt-secret-key')
    JWT_EXPIRATION_HOURS = int(os.getenv('JWT_EXPIRATION_HOURS', '24'))
    DATABASE_URL = os.getenv('DATABASE_URL', 'sqlite:///auth.db')
    REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
    CORS_ORIGINS = os.getenv('CORS_ORIGINS', '*').split(',')
```

### 3. 项目结构
```
qtfund_project_0/
├── app/
│   ├── __init__.py
│   ├── models/
│   │   ├── user.py
│   │   ├── login_log.py
│   │   └── permission.py
│   ├── auth/
│   │   ├── __init__.py
│   │   ├── routes.py
│   │   ├── validators.py
│   │   └── jwt_utils.py
│   ├── admin/
│   │   ├── __init__.py
│   │   └── routes.py
│   └── utils/
│       ├── database.py
│       ├── responses.py
│       └── logging.py
├── config/
│   ├── __init__.py
│   └── settings.py
├── migrations/
├── tests/
├── requirements.txt
├── run.py
├── .env.example
└── README.md
```

### 4. 错误处理
- 统一的错误响应格式
- 详细的错误日志记录
- 异常情况的优雅处理
- 用户友好的错误信息

### 5. 性能要求
- Token 验证响应时间 < 50ms
- 支持并发用户数 > 1000
- 数据库查询优化
- 可选的 Redis 缓存支持

### 6. 安全要求
- 所有密码使用 bcrypt 加密
- JWT Token 使用 HS256 签名
- 防止 SQL 注入
- 输入参数验证
- 敏感信息不记录到日志

---

## 部署要求

### 1. 服务配置
- 监听端口: 9000
- 进程数: 根据CPU核心数配置
- 工作模式: WSGI (Gunicorn)

### 2. 监控指标
- 请求响应时间
- 错误率统计
- 认证成功率
- 系统资源使用情况

### 3. 日志配置
- 按日期轮转的日志文件
- 结构化日志格式 (JSON)
- 不同级别的日志分离
- 敏感信息脱敏

### 4. 备份策略
- 数据库定期备份
- 配置文件版本控制
- 日志文件归档

---

## 测试要求

### 1. 单元测试
- 所有核心功能的单元测试
- 测试覆盖率 > 80%
- 异常情况测试

### 2. 集成测试
- API 接口测试
- 数据库操作测试
- Nginx 集成测试

### 3. 性能测试
- 并发用户测试
- 压力测试
- 响应时间测试

### 4. 安全测试
- 认证绕过测试
- SQL 注入测试
- XSS 防护测试

---

## 开发计划

### 第一阶段: 核心功能 (1-2周)
- [ ] 基础项目结构搭建
- [ ] 用户模型和数据库设计
- [ ] JWT 认证机制实现
- [ ] 基础API接口开发
- [ ] Nginx auth_request 集成

### 第二阶段: 完善功能 (1周)
- [ ] 用户管理界面
- [ ] 权限控制系统
- [ ] 日志审计功能
- [ ] 错误处理优化

### 第三阶段: 优化部署 (1周)
- [ ] 性能优化
- [ ] 安全加固
- [ ] 监控和日志
- [ ] 文档完善

### 第四阶段: 测试验证 (1周)
- [ ] 完整测试套件
- [ ] 部署验证
- [ ] 与现有系统集成测试
- [ ] 上线准备

---

## 风险评估

### 技术风险
- JWT Token 安全性风险
- 数据库性能瓶颈
- Nginx 集成兼容性

### 业务风险
- 认证服务单点故障
- 用户体验影响
- 数据迁移风险

### 缓解措施
- 完善的错误处理和降级方案
- 充分的测试验证
- 灰度部署策略
- 快速回滚机制

---

*文档版本: v1.0*
*创建日期: 2024-10-19*
*最后更新: 2024-10-19*