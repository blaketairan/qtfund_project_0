"""
用户数据模型
使用dataclass定义用户相关的数据结构
"""
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Optional, Dict, Any
import bcrypt


@dataclass
class User:
    """用户数据模型"""
    id: int
    username: str
    password_hash: str
    email: Optional[str] = None
    real_name: Optional[str] = None
    role: str = 'user'
    status: str = 'active'
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat() + 'Z')
    updated_at: str = field(default_factory=lambda: datetime.utcnow().isoformat() + 'Z')
    last_login: Optional[str] = None
    login_count: int = 0

    @classmethod
    def create(
        cls,
        user_id: int,
        username: str,
        password: str,
        email: Optional[str] = None,
        real_name: Optional[str] = None,
        role: str = 'user'
    ) -> 'User':
        """
        创建新用户

        Args:
            user_id: 用户ID
            username: 用户名
            password: 明文密码
            email: 邮箱
            real_name: 真实姓名
            role: 用户角色

        Returns:
            User: 用户对象
        """
        password_hash = cls.hash_password(password)
        return cls(
            id=user_id,
            username=username,
            password_hash=password_hash,
            email=email,
            real_name=real_name,
            role=role
        )

    @staticmethod
    def hash_password(password: str) -> str:
        """密码哈希"""
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    def verify_password(self, password: str) -> bool:
        """验证密码"""
        return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))

    def update_password(self, new_password: str):
        """更新密码"""
        self.password_hash = self.hash_password(new_password)
        self.updated_at = datetime.utcnow().isoformat() + 'Z'

    def update_last_login(self):
        """更新最后登录时间"""
        self.last_login = datetime.utcnow().isoformat() + 'Z'
        self.login_count += 1
        self.updated_at = self.last_login

    def update_info(self, **kwargs):
        """更新用户信息"""
        allowed_fields = {'email', 'real_name', 'role', 'status'}
        for field_name, value in kwargs.items():
            if field_name in allowed_fields and hasattr(self, field_name):
                setattr(self, field_name, value)
        self.updated_at = datetime.utcnow().isoformat() + 'Z'

    def to_dict(self, include_sensitive: bool = False) -> Dict[str, Any]:
        """
        转换为字典

        Args:
            include_sensitive: 是否包含敏感信息（密码哈希）

        Returns:
            Dict: 用户信息字典
        """
        data = asdict(self)
        if not include_sensitive:
            data.pop('password_hash', None)
        return data

    def to_public_dict(self) -> Dict[str, Any]:
        """转换为公开信息字典（用于API响应）"""
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'real_name': self.real_name,
            'role': self.role,
            'status': self.status,
            'created_at': self.created_at,
            'last_login': self.last_login,
            'login_count': self.login_count
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'User':
        """从字典创建用户对象"""
        # 确保必需字段存在
        required_fields = {'id', 'username', 'password_hash'}
        if not all(field in data for field in required_fields):
            raise ValueError(f"缺少必需字段: {required_fields - set(data.keys())}")

        return cls(**data)

    def is_admin(self) -> bool:
        """检查是否为管理员"""
        return self.role == 'admin'

    def is_active(self) -> bool:
        """检查用户是否激活"""
        return self.status == 'active'

    def can_access_resource(self, resource_path: str, method: str = 'GET') -> bool:
        """
        检查用户是否可以访问指定资源

        Args:
            resource_path: 资源路径
            method: HTTP方法

        Returns:
            bool: 是否有权限访问
        """
        if not self.is_active():
            return False

        # 管理员拥有所有权限
        if self.is_admin():
            return True

        # 只读用户只能访问GET请求
        if self.role == 'readonly' and method.upper() != 'GET':
            return False

        # 基于路径的权限检查
        if resource_path.startswith('/api/admin'):
            return self.is_admin()
        elif resource_path.startswith('/api/user'):
            return self.role in ['admin', 'user']
        elif resource_path.startswith('/api/public'):
            return True

        # 默认允许普通用户访问
        return self.role in ['admin', 'user']

    def __str__(self) -> str:
        return f"User(id={self.id}, username='{self.username}', role='{self.role}')"

    def __repr__(self) -> str:
        return self.__str__()