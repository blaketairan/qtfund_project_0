"""
权限配置存储
基于JSON文件的权限规则和Token黑名单管理
"""
from typing import Optional, List, Dict, Any
from datetime import datetime
import logging

from .base import BaseFileStorage
from ..models.permission import Permission, TokenBlacklistItem, DEFAULT_PERMISSIONS

logger = logging.getLogger(__name__)


class PermissionStorage(BaseFileStorage[Permission]):
    """权限配置存储"""

    def __init__(self, file_path: str):
        super().__init__(file_path)

    def _get_empty_structure(self) -> Dict[str, Any]:
        """获取空的权限数据结构"""
        return {
            'permissions': [],  # 权限规则列表
            'next_id': 1,  # 下一个权限ID
            'metadata': {
                'version': '1.0',
                'created_at': datetime.utcnow().isoformat() + 'Z',
                'last_updated': datetime.utcnow().isoformat() + 'Z',
                'permission_count': 0
            }
        }

    def _validate_data_structure(self, data: Dict[str, Any]) -> bool:
        """验证权限数据结构"""
        if not isinstance(data, dict):
            return False

        required_fields = {'permissions', 'next_id', 'metadata'}
        if not all(field in data for field in required_fields):
            return False

        if not isinstance(data.get('permissions'), list):
            return False

        if not isinstance(data.get('next_id'), int):
            return False

        return True

    def initialize_default_permissions(self):
        """初始化默认权限规则"""
        data = self.read_data()

        # 如果已有权限配置，不重复初始化
        if data['permissions']:
            return

        def _init_permissions(data):
            for perm_data in DEFAULT_PERMISSIONS:
                permission = Permission.create(**perm_data)
                data['permissions'].append(permission.to_dict())

            data['next_id'] = len(DEFAULT_PERMISSIONS) + 1
            data['metadata']['permission_count'] = len(data['permissions'])
            data['metadata']['last_updated'] = datetime.utcnow().isoformat() + 'Z'

            logger.info(f"已初始化 {len(DEFAULT_PERMISSIONS)} 条默认权限规则")
            return data

        self.update_data(_init_permissions)

    def add_permission(self, path_pattern: str, method: str,
                      required_role: str, description: str = '') -> Permission:
        """
        添加权限规则

        Args:
            path_pattern: 路径模式
            method: HTTP方法
            required_role: 所需角色
            description: 描述

        Returns:
            Permission: 权限对象
        """
        def _add_permission(data):
            permission_id = data['next_id']
            permission = Permission.create(
                permission_id=permission_id,
                path_pattern=path_pattern,
                method=method,
                required_role=required_role,
                description=description
            )

            data['permissions'].append(permission.to_dict())
            data['next_id'] = permission_id + 1
            data['metadata']['permission_count'] = len(data['permissions'])
            data['metadata']['last_updated'] = datetime.utcnow().isoformat() + 'Z'

            logger.info(f"权限规则已添加: {method} {path_pattern} -> {required_role}")
            return data

        self.update_data(_add_permission)

        # 返回创建的权限
        data = self.read_data()
        return Permission.from_dict(data['permissions'][-1])

    def get_permission_by_id(self, permission_id: int) -> Optional[Permission]:
        """
        根据ID获取权限规则

        Args:
            permission_id: 权限ID

        Returns:
            Optional[Permission]: 权限对象
        """
        data = self.read_data()

        for perm_data in data['permissions']:
            if perm_data.get('id') == permission_id:
                return Permission.from_dict(perm_data)
        return None

    def get_all_permissions(self) -> List[Permission]:
        """
        获取所有权限规则

        Returns:
            List[Permission]: 权限列表
        """
        data = self.read_data()
        permissions = []

        for perm_data in data['permissions']:
            try:
                permissions.append(Permission.from_dict(perm_data))
            except Exception as e:
                logger.warning(f"解析权限规则失败: {e}")

        return permissions

    def get_enabled_permissions(self) -> List[Permission]:
        """
        获取启用的权限规则

        Returns:
            List[Permission]: 启用的权限列表
        """
        permissions = self.get_all_permissions()
        return [perm for perm in permissions if perm.enabled]

    def update_permission(self, permission: Permission) -> bool:
        """
        更新权限规则

        Args:
            permission: 权限对象

        Returns:
            bool: 是否更新成功
        """
        def _update_permission(data):
            for i, perm_data in enumerate(data['permissions']):
                if perm_data.get('id') == permission.id:
                    permission.updated_at = datetime.utcnow().isoformat() + 'Z'
                    data['permissions'][i] = permission.to_dict()
                    data['metadata']['last_updated'] = datetime.utcnow().isoformat() + 'Z'
                    logger.info(f"权限规则已更新: ID {permission.id}")
                    return data
            return None  # 权限不存在

        try:
            self.update_data(_update_permission)
            return True
        except Exception as e:
            logger.error(f"更新权限规则失败: {e}")
            return False

    def delete_permission(self, permission_id: int) -> bool:
        """
        删除权限规则

        Args:
            permission_id: 权限ID

        Returns:
            bool: 是否删除成功
        """
        def _delete_permission(data):
            for i, perm_data in enumerate(data['permissions']):
                if perm_data.get('id') == permission_id:
                    deleted_perm = data['permissions'].pop(i)
                    data['metadata']['permission_count'] = len(data['permissions'])
                    data['metadata']['last_updated'] = datetime.utcnow().isoformat() + 'Z'
                    logger.info(f"权限规则已删除: {deleted_perm.get('path_pattern')}")
                    return data
            return None  # 权限不存在

        try:
            self.update_data(_delete_permission)
            return True
        except Exception as e:
            logger.error(f"删除权限规则失败: {e}")
            return False

    def check_permission(self, path: str, method: str, user_role: str) -> bool:
        """
        检查用户是否有权限访问指定资源

        Args:
            path: 请求路径
            method: 请求方法
            user_role: 用户角色

        Returns:
            bool: 是否有权限
        """
        permissions = self.get_enabled_permissions()

        # 遍历权限规则，找到匹配的规则
        for permission in permissions:
            if permission.matches_request(path, method):
                return permission.allows_role(user_role)

        # 如果没有匹配的规则，默认拒绝访问
        logger.warning(f"没有匹配的权限规则: {method} {path}")
        return False

    def get_matching_permissions(self, path: str, method: str) -> List[Permission]:
        """
        获取匹配指定请求的权限规则

        Args:
            path: 请求路径
            method: 请求方法

        Returns:
            List[Permission]: 匹配的权限规则列表
        """
        permissions = self.get_enabled_permissions()
        matching = []

        for permission in permissions:
            if permission.matches_request(path, method):
                matching.append(permission)

        return matching


class TokenBlacklistStorage(BaseFileStorage[TokenBlacklistItem]):
    """Token黑名单存储"""

    def __init__(self, file_path: str):
        super().__init__(file_path)

    def _get_empty_structure(self) -> Dict[str, Any]:
        """获取空的黑名单数据结构"""
        return {
            'blacklist': [],  # 黑名单列表
            'next_id': 1,  # 下一个黑名单项ID
            'metadata': {
                'version': '1.0',
                'created_at': datetime.utcnow().isoformat() + 'Z',
                'last_updated': datetime.utcnow().isoformat() + 'Z',
                'item_count': 0
            }
        }

    def _validate_data_structure(self, data: Dict[str, Any]) -> bool:
        """验证黑名单数据结构"""
        if not isinstance(data, dict):
            return False

        required_fields = {'blacklist', 'next_id', 'metadata'}
        if not all(field in data for field in required_fields):
            return False

        if not isinstance(data.get('blacklist'), list):
            return False

        if not isinstance(data.get('next_id'), int):
            return False

        return True

    def add_token(self, token_jti: str, user_id: int, expires_at: str,
                 reason: str = 'logout') -> TokenBlacklistItem:
        """
        添加Token到黑名单

        Args:
            token_jti: Token的JTI
            user_id: 用户ID
            expires_at: Token过期时间
            reason: 撤销原因

        Returns:
            TokenBlacklistItem: 黑名单项对象
        """
        def _add_token(data):
            item_id = data['next_id']
            item = TokenBlacklistItem.create(
                item_id=item_id,
                token_jti=token_jti,
                user_id=user_id,
                expires_at=expires_at,
                reason=reason
            )

            data['blacklist'].append(item.to_dict())
            data['next_id'] = item_id + 1
            data['metadata']['item_count'] = len(data['blacklist'])
            data['metadata']['last_updated'] = datetime.utcnow().isoformat() + 'Z'

            logger.debug(f"Token已加入黑名单: {token_jti} (用户: {user_id})")
            return data

        self.update_data(_add_token)

        # 返回创建的黑名单项
        data = self.read_data()
        return TokenBlacklistItem.from_dict(data['blacklist'][-1])

    def is_token_blacklisted(self, token_jti: str) -> bool:
        """
        检查Token是否在黑名单中

        Args:
            token_jti: Token的JTI

        Returns:
            bool: 是否在黑名单中
        """
        data = self.read_data()

        for item_data in data['blacklist']:
            if item_data.get('token_jti') == token_jti:
                try:
                    item = TokenBlacklistItem.from_dict(item_data)
                    # 检查Token是否已过期（过期的Token无需检查黑名单）
                    if not item.is_expired():
                        return True
                except Exception as e:
                    logger.warning(f"解析黑名单项失败: {e}")

        return False

    def get_user_blacklisted_tokens(self, user_id: int) -> List[TokenBlacklistItem]:
        """
        获取用户的黑名单Token

        Args:
            user_id: 用户ID

        Returns:
            List[TokenBlacklistItem]: 黑名单项列表
        """
        data = self.read_data()
        items = []

        for item_data in data['blacklist']:
            if item_data.get('user_id') == user_id:
                try:
                    item = TokenBlacklistItem.from_dict(item_data)
                    if not item.is_expired():  # 只返回未过期的
                        items.append(item)
                except Exception as e:
                    logger.warning(f"解析黑名单项失败: {e}")

        return items

    def cleanup_expired_tokens(self) -> int:
        """
        清理已过期的黑名单Token

        Returns:
            int: 清理的数量
        """
        cleaned_count = 0

        def _cleanup_tokens(data):
            nonlocal cleaned_count
            new_blacklist = []

            for item_data in data['blacklist']:
                try:
                    item = TokenBlacklistItem.from_dict(item_data)
                    if not item.is_expired():
                        new_blacklist.append(item_data)
                    else:
                        cleaned_count += 1
                except Exception as e:
                    # 保留无法解析的项
                    new_blacklist.append(item_data)
                    logger.warning(f"解析黑名单项失败: {e}")

            data['blacklist'] = new_blacklist
            data['metadata']['item_count'] = len(new_blacklist)
            data['metadata']['last_updated'] = datetime.utcnow().isoformat() + 'Z'

            if cleaned_count > 0:
                logger.info(f"已清理 {cleaned_count} 个过期的黑名单Token")
            return data

        self.update_data(_cleanup_tokens)
        return cleaned_count

    def revoke_all_user_tokens(self, user_id: int, reason: str = 'admin_revoke'):
        """
        撤销用户的所有Token（通过添加特殊标记）

        Args:
            user_id: 用户ID
            reason: 撤销原因
        """
        def _revoke_all_tokens(data):
            # 添加一个特殊的黑名单项，用于标记该用户的所有Token都被撤销
            item_id = data['next_id']
            revoke_time = datetime.utcnow().isoformat() + 'Z'

            item = {
                'id': item_id,
                'token_jti': f'USER_REVOKE_{user_id}_{revoke_time}',
                'user_id': user_id,
                'revoked_at': revoke_time,
                'expires_at': '',  # 永不过期
                'reason': reason
            }

            data['blacklist'].append(item)
            data['next_id'] = item_id + 1
            data['metadata']['item_count'] = len(data['blacklist'])
            data['metadata']['last_updated'] = datetime.utcnow().isoformat() + 'Z'

            logger.info(f"用户 {user_id} 的所有Token已被撤销: {reason}")
            return data

        self.update_data(_revoke_all_tokens)