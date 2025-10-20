# QTFund 认证服务项目结构 (简化版)

```
qtfund_project_0/
├── app/
│   ├── __init__.py                 # Flask应用工厂
│   ├── models/
│   │   ├── __init__.py
│   │   ├── user.py                 # 用户模型 (Pydantic/dataclass)
│   │   ├── login_log.py            # 登录日志模型
│   │   └── permission.py           # 权限模型
│   ├── storage/
│   │   ├── __init__.py
│   │   ├── base.py                 # 文件存储基类
│   │   ├── user_storage.py         # 用户数据存储
│   │   ├── log_storage.py          # 日志存储
│   │   ├── permission_storage.py   # 权限存储
│   │   └── manager.py              # 存储管理器
│   ├── auth/
│   │   ├── __init__.py
│   │   ├── routes.py               # 认证相关路由
│   │   ├── validators.py           # 输入验证器
│   │   ├── jwt_utils.py            # JWT工具函数
│   │   └── permissions.py          # 权限检查逻辑
│   ├── admin/
│   │   ├── __init__.py
│   │   ├── routes.py               # 管理员功能路由
│   │   └── decorators.py           # 管理员权限装饰器
│   ├── user/
│   │   ├── __init__.py
│   │   ├── routes.py               # 用户管理路由
│   │   └── schemas.py              # 用户数据序列化
│   └── utils/
│       ├── __init__.py
│       ├── responses.py            # 统一响应格式
│       ├── logging.py              # 日志配置
│       └── decorators.py           # 通用装饰器
├── config/
│   ├── __init__.py
│   └── settings.py                 # 配置管理
├── data/                           # 数据文件目录
│   ├── users.json                  # 用户数据
│   ├── login_logs.json             # 登录日志
│   ├── permissions.json            # 权限配置
│   └── token_blacklist.json        # Token黑名单
├── backups/                        # 备份目录
├── tests/
│   ├── __init__.py
│   ├── conftest.py                 # 测试配置
│   ├── test_auth.py                # 认证功能测试
│   ├── test_user.py                # 用户管理测试
│   ├── test_admin.py               # 管理功能测试
│   ├── test_storage.py             # 存储层测试
│   └── test_permissions.py         # 权限控制测试
├── logs/                           # 日志目录
├── docs/                           # 文档目录
│   ├── API.md                      # API接口文档
│   ├── DEPLOYMENT.md               # 部署文档
│   └── DEVELOPMENT.md              # 开发文档
├── scripts/
│   ├── init_data.py                # 数据初始化脚本
│   ├── create_admin.py             # 创建管理员脚本
│   ├── backup_data.py              # 数据备份脚本
│   └── migrate_to_db.py            # 升级到数据库的迁移脚本
├── AUTH_SERVICE_REQUIREMENTS.md    # 需求文档
├── FILE_STORAGE_DESIGN.md          # 文件存储设计
├── requirements.txt                # Python依赖 (简化版)
├── .env.example                    # 环境变量示例
├── .env                           # 环境变量 (git ignore)
├── .gitignore                     # Git忽略文件
├── run.py                         # 应用启动文件
├── wsgi.py                        # WSGI入口
└── README.md                      # 项目说明
```

## 核心文件说明 (简化版)

### 1. 应用入口
- `run.py`: 开发环境启动文件
- `wsgi.py`: 生产环境WSGI入口
- `app/__init__.py`: Flask应用工厂函数

### 2. 数据模型 (轻量级)
- `models/user.py`: 用户信息数据类 (使用 dataclass 或 Pydantic)
- `models/login_log.py`: 登录历史数据类
- `models/permission.py`: 权限规则数据类

### 3. 存储层 (文件存储)
- `storage/base.py`: 文件存储基类，处理文件锁、原子写入
- `storage/user_storage.py`: 用户数据的CRUD操作
- `storage/log_storage.py`: 日志数据管理
- `storage/manager.py`: 存储管理器，统一存储接口

### 4. 业务逻辑
- `auth/routes.py`: 登录、注册、Token验证
- `user/routes.py`: 用户信息管理、密码修改
- `admin/routes.py`: 用户管理、权限分配

### 5. 数据文件 (JSON格式)
- `data/users.json`: 用户信息存储
- `data/login_logs.json`: 登录历史记录
- `data/permissions.json`: 权限规则配置
- `data/token_blacklist.json`: 撤销的Token列表

### 6. 工具脚本
- `scripts/init_data.py`: 初始化数据文件和默认管理员
- `scripts/backup_data.py`: 定期备份数据文件
- `scripts/migrate_to_db.py`: 未来升级到数据库时的迁移工具

## 简化后的优势

### 1. 极简部署
- 无需安装数据库服务
- 无需Redis缓存
- 只需Python环境即可运行
- 单文件夹即可完整备份

### 2. 开发友好
- JSON文件可直接查看和编辑
- 便于调试和问题排查
- 快速原型开发
- 零配置启动

### 3. 运维简单
- 文件锁机制保证数据安全
- 自动备份和日志轮转
- 便于监控和维护
- 支持手动数据修复

### 4. 扩展性
- 保持相同的API接口
- 可无缝升级到数据库
- 数据迁移脚本已准备
- 架构设计支持扩展

## 开发流程 (简化版)

### 1. 环境准备
```bash
cd qtfund_project_0
python -m venv venv
source venv/bin/activate  # Linux/Mac
pip install -r requirements.txt
cp .env.example .env  # 编辑基本配置
```

### 2. 数据初始化
```bash
python scripts/init_data.py  # 创建数据目录和文件
python scripts/create_admin.py  # 创建默认管理员
```

### 3. 开发启动
```bash
python run.py  # 开发模式，单进程足够
```

### 4. 测试验证
```bash
pytest tests/  # 运行测试
curl http://localhost:9000/health  # 健康检查
```

## 部署说明 (简化版)

### 1. 生产部署
```bash
# 只需要单个Gunicorn进程
gunicorn -w 1 -b 0.0.0.0:9000 wsgi:app

# 或使用systemd服务
sudo systemctl start qtfund-auth
```

### 2. Nginx配置 (无变化)
```nginx
# auth_request配置保持不变
location = /auth {
    internal;
    proxy_pass http://127.0.0.1:9000/api/v1/auth/validate;
    # ... 其他配置
}
```

### 3. 备份策略
```bash
# 简单的文件备份
tar -czf backup_$(date +%Y%m%d).tar.gz data/ logs/

# 定时备份
0 2 * * * cd /opt/qtfund/auth && python scripts/backup_data.py
```

## 性能特点

### 1. 资源需求
- **内存**: 50-100MB (vs 数据库版本的200-500MB)
- **CPU**: 低负载下几乎不占用
- **存储**: 几KB到几MB的数据文件
- **网络**: 只有应用端口9000

### 2. 并发能力
- 支持10-50个并发用户 (个位数用户完全够用)
- 文件锁保证数据一致性
- 读多写少的场景性能优秀

### 3. 响应时间
- 认证验证: <10ms
- 用户管理: <20ms
- 文件读写: <5ms

## 安全考虑

### 1. 文件安全
- 数据文件权限设置为600 (仅owner可读写)
- 使用文件锁防止并发写入冲突
- 原子写入防止数据损坏

### 2. 备份安全
- 自动备份机制
- 备份文件加密存储 (可选)
- 多版本备份保留

### 3. 升级路径
- 保留数据库迁移脚本
- API接口兼容性
- 平滑升级方案

这个简化版本特别适合你的小规模部署需求，将复杂度降到最低的同时保持了完整的功能性。