# 文件存储数据结构设计

## 数据文件设计

### 1. 用户数据文件 (users.json)
```json
{
    "users": {
        "1": {
            "id": 1,
            "username": "admin",
            "password_hash": "$2b$12$...",
            "email": "admin@qtfund.local",
            "real_name": "系统管理员",
            "role": "admin",
            "status": "active",
            "created_at": "2024-10-19T12:00:00Z",
            "updated_at": "2024-10-19T12:00:00Z",
            "last_login": "2024-10-19T11:30:00Z",
            "login_count": 156
        }
    },
    "next_id": 2,
    "version": "1.0",
    "last_updated": "2024-10-19T12:00:00Z"
}
```

### 2. 登录日志文件 (login_logs.json)
```json
{
    "logs": [
        {
            "id": 1,
            "user_id": 1,
            "ip_address": "192.168.1.100",
            "user_agent": "Mozilla/5.0...",
            "login_time": "2024-10-19T12:00:00Z",
            "success": true,
            "error_message": null
        }
    ],
    "next_id": 2,
    "max_logs": 1000,
    "auto_cleanup": true
}
```

### 3. 权限配置文件 (permissions.json)
```json
{
    "rules": [
        {
            "id": 1,
            "path_pattern": "/api/admin/*",
            "method": "*",
            "required_role": "admin",
            "description": "管理员API",
            "enabled": true
        },
        {
            "id": 2,
            "path_pattern": "/api/user/*",
            "method": "*",
            "required_role": "user",
            "description": "用户API",
            "enabled": true
        }
    ],
    "next_id": 3,
    "default_rules": true
}
```

### 4. Token黑名单文件 (token_blacklist.json)
```json
{
    "blacklist": [
        {
            "jti": "token-unique-id-123",
            "user_id": 1,
            "revoked_at": "2024-10-19T12:00:00Z",
            "expires_at": "2024-10-20T12:00:00Z"
        }
    ],
    "auto_cleanup": true,
    "cleanup_interval": 3600
}
```

## 文件操作工具类

### FileStorage 基类设计
```python
import json
import os
from datetime import datetime
from filelock import FileLock
from typing import Dict, Any, List, Optional

class FileStorage:
    """文件存储基类"""

    def __init__(self, data_dir: str, filename: str):
        self.data_dir = data_dir
        self.filename = filename
        self.file_path = os.path.join(data_dir, filename)
        self.lock_path = f"{self.file_path}.lock"
        self._ensure_data_dir()
        self._ensure_file_exists()

    def _ensure_data_dir(self):
        """确保数据目录存在"""
        os.makedirs(self.data_dir, exist_ok=True)

    def _ensure_file_exists(self):
        """确保数据文件存在"""
        if not os.path.exists(self.file_path):
            self._write_data(self._get_default_data())

    def _get_default_data(self) -> Dict[str, Any]:
        """获取默认数据结构"""
        return {}

    def _read_data(self) -> Dict[str, Any]:
        """读取数据文件"""
        try:
            with open(self.file_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return self._get_default_data()

    def _write_data(self, data: Dict[str, Any]):
        """写入数据文件"""
        # 添加元数据
        data['last_updated'] = datetime.utcnow().isoformat() + 'Z'

        # 原子写入：先写临时文件，再重命名
        temp_path = f"{self.file_path}.tmp"
        with open(temp_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        # 原子操作
        os.replace(temp_path, self.file_path)

    def read_with_lock(self) -> Dict[str, Any]:
        """加锁读取数据"""
        with FileLock(self.lock_path):
            return self._read_data()

    def write_with_lock(self, data: Dict[str, Any]):
        """加锁写入数据"""
        with FileLock(self.lock_path):
            self._write_data(data)

    def update_with_lock(self, update_func):
        """加锁更新数据"""
        with FileLock(self.lock_path):
            data = self._read_data()
            updated_data = update_func(data)
            self._write_data(updated_data)
            return updated_data
```

### 具体存储类设计
```python
class UserStorage(FileStorage):
    """用户数据存储"""

    def _get_default_data(self) -> Dict[str, Any]:
        return {
            "users": {},
            "next_id": 1,
            "version": "1.0"
        }

    def create_user(self, user_data: Dict[str, Any]) -> int:
        """创建用户"""
        def update_func(data):
            user_id = data["next_id"]
            user_data["id"] = user_id
            user_data["created_at"] = datetime.utcnow().isoformat() + 'Z'
            user_data["updated_at"] = user_data["created_at"]

            data["users"][str(user_id)] = user_data
            data["next_id"] += 1
            return data

        result = self.update_with_lock(update_func)
        return result["next_id"] - 1

    def get_user_by_username(self, username: str) -> Optional[Dict[str, Any]]:
        """根据用户名获取用户"""
        data = self.read_with_lock()
        for user in data["users"].values():
            if user["username"] == username:
                return user
        return None

    def get_user_by_id(self, user_id: int) -> Optional[Dict[str, Any]]:
        """根据ID获取用户"""
        data = self.read_with_lock()
        return data["users"].get(str(user_id))

    def update_user(self, user_id: int, updates: Dict[str, Any]) -> bool:
        """更新用户信息"""
        def update_func(data):
            user_key = str(user_id)
            if user_key in data["users"]:
                data["users"][user_key].update(updates)
                data["users"][user_key]["updated_at"] = datetime.utcnow().isoformat() + 'Z'
            return data

        result = self.update_with_lock(update_func)
        return str(user_id) in result["users"]

    def list_users(self, limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
        """获取用户列表"""
        data = self.read_with_lock()
        users = list(data["users"].values())
        return users[offset:offset + limit]

class LoginLogStorage(FileStorage):
    """登录日志存储"""

    def _get_default_data(self) -> Dict[str, Any]:
        return {
            "logs": [],
            "next_id": 1,
            "max_logs": 1000,
            "auto_cleanup": True
        }

    def add_log(self, log_data: Dict[str, Any]):
        """添加登录日志"""
        def update_func(data):
            log_data["id"] = data["next_id"]
            data["logs"].append(log_data)
            data["next_id"] += 1

            # 自动清理老日志
            if data["auto_cleanup"] and len(data["logs"]) > data["max_logs"]:
                data["logs"] = data["logs"][-data["max_logs"]:]

            return data

        self.update_with_lock(update_func)

    def get_user_logs(self, user_id: int, limit: int = 10) -> List[Dict[str, Any]]:
        """获取用户登录日志"""
        data = self.read_with_lock()
        user_logs = [log for log in data["logs"] if log["user_id"] == user_id]
        return user_logs[-limit:]  # 返回最新的几条

class PermissionStorage(FileStorage):
    """权限配置存储"""

    def _get_default_data(self) -> Dict[str, Any]:
        return {
            "rules": [
                {
                    "id": 1,
                    "path_pattern": "/api/admin/*",
                    "method": "*",
                    "required_role": "admin",
                    "description": "管理员API",
                    "enabled": True
                },
                {
                    "id": 2,
                    "path_pattern": "/api/user/*",
                    "method": "*",
                    "required_role": "user",
                    "description": "用户API",
                    "enabled": True
                }
            ],
            "next_id": 3,
            "default_rules": True
        }

    def get_rules(self) -> List[Dict[str, Any]]:
        """获取所有权限规则"""
        data = self.read_with_lock()
        return [rule for rule in data["rules"] if rule["enabled"]]

class TokenBlacklistStorage(FileStorage):
    """Token黑名单存储"""

    def _get_default_data(self) -> Dict[str, Any]:
        return {
            "blacklist": [],
            "auto_cleanup": True,
            "cleanup_interval": 3600
        }

    def add_token(self, jti: str, user_id: int, expires_at: str):
        """添加黑名单Token"""
        def update_func(data):
            data["blacklist"].append({
                "jti": jti,
                "user_id": user_id,
                "revoked_at": datetime.utcnow().isoformat() + 'Z',
                "expires_at": expires_at
            })

            # 清理过期的token
            if data["auto_cleanup"]:
                now = datetime.utcnow().isoformat() + 'Z'
                data["blacklist"] = [
                    token for token in data["blacklist"]
                    if token["expires_at"] > now
                ]

            return data

        self.update_with_lock(update_func)

    def is_blacklisted(self, jti: str) -> bool:
        """检查Token是否在黑名单中"""
        data = self.read_with_lock()
        return any(token["jti"] == jti for token in data["blacklist"])
```

## 存储管理器
```python
class StorageManager:
    """存储管理器 - 统一管理所有存储"""

    def __init__(self, data_dir: str):
        self.data_dir = data_dir
        self.users = UserStorage(data_dir, "users.json")
        self.login_logs = LoginLogStorage(data_dir, "login_logs.json")
        self.permissions = PermissionStorage(data_dir, "permissions.json")
        self.token_blacklist = TokenBlacklistStorage(data_dir, "token_blacklist.json")

    def backup_all(self, backup_dir: str):
        """备份所有数据文件"""
        import shutil
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = os.path.join(backup_dir, f"backup_{timestamp}")
        os.makedirs(backup_path, exist_ok=True)

        # 复制所有数据文件
        for filename in ["users.json", "login_logs.json", "permissions.json", "token_blacklist.json"]:
            src = os.path.join(self.data_dir, filename)
            if os.path.exists(src):
                shutil.copy2(src, backup_path)

        return backup_path

    def restore_from_backup(self, backup_path: str):
        """从备份恢复数据"""
        import shutil
        for filename in ["users.json", "login_logs.json", "permissions.json", "token_blacklist.json"]:
            src = os.path.join(backup_path, filename)
            dst = os.path.join(self.data_dir, filename)
            if os.path.exists(src):
                shutil.copy2(src, dst)
```

## 优势

### 简单部署
- 无需外部数据库
- 无需Redis缓存
- 单进程即可运行
- 便于备份和迁移

### 高可靠性
- 文件锁保证并发安全
- 原子写入防止数据损坏
- 自动备份机制
- JSON格式便于手动维护

### 易于升级
- 保持相同的API接口
- 可无缝升级到数据库存储
- 数据迁移脚本简单

这种方案特别适合你的小规模部署需求，同时保持了后续扩展的可能性。