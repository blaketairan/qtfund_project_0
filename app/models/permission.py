"""
权限配置数据模型
定义系统权限规则和角色权限管理
"""
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Optional, Dict, Any, List
import re


@dataclass
class Permission:
    """权限规则数据模型"""
    id: int
    path_pattern: str
    method: str
    required_role: str
    description: str = ''
    enabled: bool = True
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat() + 'Z')
    updated_at: str = field(default_factory=lambda: datetime.utcnow().isoformat() + 'Z')

    @classmethod
    def create(
        cls,
        permission_id: int,
        path_pattern: str,
        method: str,
        required_role: str,
        description: str = ''
    ) -> 'Permission':
        """
        创建权限规则

        Args:
            permission_id: 权限ID
            path_pattern: 路径模式（支持通配符）
            method: HTTP方法（GET, POST, PUT, DELETE, ANY）
            required_role: 所需角色
            description: 描述

        Returns:
            Permission: 权限对象
        """
        return cls(
            id=permission_id,
            path_pattern=path_pattern,
            method=method.upper(),
            required_role=required_role,
            description=description
        )

    def matches_request(self, path: str, method: str) -> bool:
        """
        检查请求是否匹配此权限规则

        Args:
            path: 请求路径
            method: 请求方法

        Returns:
            bool: 是否匹配
        """
        if not self.enabled:
            return False

        # 检查方法匹配
        if self.method != 'ANY' and self.method != method.upper():
            return False

        # 检查路径匹配（支持通配符）
        return self._match_path_pattern(path)

    def _match_path_pattern(self, path: str) -> bool:
        """
        匹配路径模式

        Args:
            path: 请求路径

        Returns:
            bool: 是否匹配
        """
        # 将通配符模式转换为正则表达式
        pattern = self.path_pattern
        pattern = pattern.replace('*', '.*')  # * 匹配任意字符
        pattern = pattern.replace('?', '.')   # ? 匹配单个字符
        pattern = f'^{pattern}$'

        try:
            return bool(re.match(pattern, path))
        except re.error:
            # 如果正则表达式无效，使用简单的字符串匹配
            return path.startswith(self.path_pattern.rstrip('*'))

    def allows_role(self, user_role: str) -> bool:
        """
        检查角色是否满足权限要求

        Args:
            user_role: 用户角色

        Returns:
            bool: 是否允许
        """
        # 管理员拥有所有权限
        if user_role == 'admin':
            return True

        # 检查角色匹配
        if self.required_role == 'any':
            return True

        # 角色层级检查
        role_hierarchy = {
            'readonly': 1,
            'user': 2,
            'admin': 3
        }

        user_level = role_hierarchy.get(user_role, 0)
        required_level = role_hierarchy.get(self.required_role, 3)

        return user_level >= required_level

    def update(self, **kwargs):
        """更新权限规则"""
        allowed_fields = {
            'path_pattern', 'method', 'required_role',
            'description', 'enabled'
        }

        for field_name, value in kwargs.items():
            if field_name in allowed_fields and hasattr(self, field_name):
                if field_name == 'method':
                    value = value.upper()
                setattr(self, field_name, value)

        self.updated_at = datetime.utcnow().isoformat() + 'Z'

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Permission':
        """从字典创建权限对象"""
        required_fields = {'id', 'path_pattern', 'method', 'required_role'}
        if not all(field in data for field in required_fields):
            raise ValueError(f"缺少必需字段: {required_fields - set(data.keys())}")

        return cls(**data)

    def __str__(self) -> str:
        return f"Permission(id={self.id}, {self.method} {self.path_pattern} -> {self.required_role})"

    def __repr__(self) -> str:
        return self.__str__()


@dataclass
class TokenBlacklistItem:
    """Token黑名单项"""
    id: int
    token_jti: str  # JWT ID
    user_id: int
    revoked_at: str = field(default_factory=lambda: datetime.utcnow().isoformat() + 'Z')
    expires_at: str = ''
    reason: str = 'logout'

    @classmethod
    def create(
        cls,
        item_id: int,
        token_jti: str,
        user_id: int,
        expires_at: str,
        reason: str = 'logout'
    ) -> 'TokenBlacklistItem':
        """
        创建Token黑名单项

        Args:
            item_id: 项目ID
            token_jti: Token的JTI
            user_id: 用户ID
            expires_at: Token过期时间
            reason: 撤销原因

        Returns:
            TokenBlacklistItem: 黑名单项对象
        """
        return cls(
            id=item_id,
            token_jti=token_jti,
            user_id=user_id,
            expires_at=expires_at,
            reason=reason
        )

    def is_expired(self) -> bool:
        """检查Token是否已过期"""
        try:
            expires_dt = datetime.fromisoformat(self.expires_at.replace('Z', '+00:00'))
            return datetime.utcnow().replace(tzinfo=None) > expires_dt.replace(tzinfo=None)
        except (ValueError, AttributeError):
            return True

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'TokenBlacklistItem':
        """从字典创建黑名单项对象"""
        required_fields = {'id', 'token_jti', 'user_id'}
        if not all(field in data for field in required_fields):
            raise ValueError(f"缺少必需字段: {required_fields - set(data.keys())}")

        return cls(**data)

    def __str__(self) -> str:
        return f"TokenBlacklistItem(id={self.id}, jti='{self.token_jti}', user_id={self.user_id})"

    def __repr__(self) -> str:
        return self.__str__()


# 默认权限规则
DEFAULT_PERMISSIONS = [
    {
        'id': 1,
        'path_pattern': '/api/v1/admin/*',
        'method': 'ANY',
        'required_role': 'admin',
        'description': '管理员接口，仅管理员可访问'
    },
    {
        'id': 2,
        'path_pattern': '/api/v1/user/*',
        'method': 'ANY',
        'required_role': 'user',
        'description': '用户接口，普通用户及以上可访问'
    },
    {
        'id': 3,
        'path_pattern': '/api/v1/auth/login',
        'method': 'POST',
        'required_role': 'any',
        'description': '登录接口，公开访问'
    },
    {
        'id': 4,
        'path_pattern': '/api/v1/auth/register',
        'method': 'POST',
        'required_role': 'any',
        'description': '注册接口，公开访问'
    },
    {
        'id': 5,
        'path_pattern': '/api/v1/auth/validate',
        'method': 'ANY',
        'required_role': 'readonly',
        'description': 'Nginx认证验证接口'
    },
    {
        'id': 6,
        'path_pattern': '/health',
        'method': 'GET',
        'required_role': 'any',
        'description': '健康检查接口，公开访问'
    }
]