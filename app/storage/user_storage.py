"""
用户数据存储
基于JSON文件的用户数据CRUD操作
"""
from typing import Optional, List, Dict, Any
from datetime import datetime
import logging

from .base import BaseFileStorage
from ..models.user import User

logger = logging.getLogger(__name__)


class UserStorage(BaseFileStorage[User]):
    """用户数据存储"""

    def __init__(self, file_path: str):
        super().__init__(file_path)

    def _get_empty_structure(self) -> Dict[str, Any]:
        """获取空的用户数据结构"""
        return {
            'users': {},  # 用户数据，以用户ID为键
            'next_id': 1,  # 下一个用户ID
            'metadata': {
                'version': '1.0',
                'created_at': datetime.utcnow().isoformat() + 'Z',
                'last_updated': datetime.utcnow().isoformat() + 'Z',
                'user_count': 0
            }
        }

    def _validate_data_structure(self, data: Dict[str, Any]) -> bool:
        """验证用户数据结构"""
        if not isinstance(data, dict):
            return False

        required_fields = {'users', 'next_id', 'metadata'}
        if not all(field in data for field in required_fields):
            return False

        if not isinstance(data.get('users'), dict):
            return False

        if not isinstance(data.get('next_id'), int):
            return False

        return True

    def create_user(self, username: str, password: str, **kwargs) -> User:
        """
        创建新用户

        Args:
            username: 用户名
            password: 密码
            **kwargs: 其他用户属性

        Returns:
            User: 创建的用户对象

        Raises:
            ValueError: 用户名已存在
        """
        def _create_user(data):
            # 检查用户名是否已存在
            for user_data in data['users'].values():
                if user_data['username'] == username:
                    raise ValueError(f"用户名已存在: {username}")

            # 创建新用户
            user_id = data['next_id']
            user = User.create(
                user_id=user_id,
                username=username,
                password=password,
                **kwargs
            )

            # 保存到数据结构
            data['users'][str(user_id)] = user.to_dict(include_sensitive=True)
            data['next_id'] = user_id + 1
            data['metadata']['user_count'] = len(data['users'])
            data['metadata']['last_updated'] = datetime.utcnow().isoformat() + 'Z'

            logger.info(f"用户已创建: {username} (ID: {user_id})")
            return data

        self.update_data(_create_user)

        # 返回创建的用户（重新从存储中读取以确保一致性）
        return self.get_user_by_id(data['next_id'] - 1)

    def get_user_by_id(self, user_id: int) -> Optional[User]:
        """
        根据ID获取用户

        Args:
            user_id: 用户ID

        Returns:
            Optional[User]: 用户对象，不存在时返回None
        """
        data = self.read_data()
        user_data = data['users'].get(str(user_id))

        if user_data:
            return User.from_dict(user_data)
        return None

    def get_user_by_username(self, username: str) -> Optional[User]:
        """
        根据用户名获取用户

        Args:
            username: 用户名

        Returns:
            Optional[User]: 用户对象，不存在时返回None
        """
        data = self.read_data()

        for user_data in data['users'].values():
            if user_data['username'] == username:
                return User.from_dict(user_data)
        return None

    def update_user(self, user: User) -> bool:
        """
        更新用户信息

        Args:
            user: 用户对象

        Returns:
            bool: 是否更新成功
        """
        def _update_user(data):
            user_id_str = str(user.id)
            if user_id_str not in data['users']:
                return None  # 用户不存在，不更新数据

            # 更新用户数据
            user.updated_at = datetime.utcnow().isoformat() + 'Z'
            data['users'][user_id_str] = user.to_dict(include_sensitive=True)
            data['metadata']['last_updated'] = datetime.utcnow().isoformat() + 'Z'

            logger.info(f"用户已更新: {user.username} (ID: {user.id})")
            return data

        try:
            self.update_data(_update_user)
            return True
        except Exception as e:
            logger.error(f"更新用户失败: {e}")
            return False

    def delete_user(self, user_id: int) -> bool:
        """
        删除用户

        Args:
            user_id: 用户ID

        Returns:
            bool: 是否删除成功
        """
        def _delete_user(data):
            user_id_str = str(user_id)
            if user_id_str not in data['users']:
                return None  # 用户不存在

            # 删除用户
            user_data = data['users'].pop(user_id_str)
            data['metadata']['user_count'] = len(data['users'])
            data['metadata']['last_updated'] = datetime.utcnow().isoformat() + 'Z'

            logger.info(f"用户已删除: {user_data['username']} (ID: {user_id})")
            return data

        try:
            self.update_data(_delete_user)
            return True
        except Exception as e:
            logger.error(f"删除用户失败: {e}")
            return False

    def get_all_users(self, limit: Optional[int] = None, offset: int = 0) -> List[User]:
        """
        获取所有用户

        Args:
            limit: 限制返回数量
            offset: 偏移量

        Returns:
            List[User]: 用户列表
        """
        data = self.read_data()
        users = []

        # 按ID排序
        user_items = sorted(data['users'].items(), key=lambda x: int(x[0]))

        # 应用分页
        if offset > 0:
            user_items = user_items[offset:]
        if limit is not None:
            user_items = user_items[:limit]

        for user_id_str, user_data in user_items:
            try:
                users.append(User.from_dict(user_data))
            except Exception as e:
                logger.warning(f"解析用户数据失败 (ID: {user_id_str}): {e}")

        return users

    def get_users_by_role(self, role: str) -> List[User]:
        """
        根据角色获取用户列表

        Args:
            role: 用户角色

        Returns:
            List[User]: 用户列表
        """
        data = self.read_data()
        users = []

        for user_data in data['users'].values():
            if user_data.get('role') == role:
                try:
                    users.append(User.from_dict(user_data))
                except Exception as e:
                    logger.warning(f"解析用户数据失败: {e}")

        return users

    def get_users_by_status(self, status: str) -> List[User]:
        """
        根据状态获取用户列表

        Args:
            status: 用户状态

        Returns:
            List[User]: 用户列表
        """
        data = self.read_data()
        users = []

        for user_data in data['users'].values():
            if user_data.get('status') == status:
                try:
                    users.append(User.from_dict(user_data))
                except Exception as e:
                    logger.warning(f"解析用户数据失败: {e}")

        return users

    def search_users(self, keyword: str, fields: List[str] = None) -> List[User]:
        """
        搜索用户

        Args:
            keyword: 搜索关键词
            fields: 搜索字段列表，默认为['username', 'email', 'real_name']

        Returns:
            List[User]: 匹配的用户列表
        """
        if fields is None:
            fields = ['username', 'email', 'real_name']

        data = self.read_data()
        users = []
        keyword_lower = keyword.lower()

        for user_data in data['users'].values():
            # 检查是否有字段匹配关键词
            for field in fields:
                field_value = user_data.get(field)
                if field_value and keyword_lower in str(field_value).lower():
                    try:
                        users.append(User.from_dict(user_data))
                        break  # 找到匹配就退出字段循环
                    except Exception as e:
                        logger.warning(f"解析用户数据失败: {e}")

        return users

    def get_user_count(self) -> int:
        """
        获取用户总数

        Returns:
            int: 用户总数
        """
        data = self.read_data()
        return len(data['users'])

    def get_statistics(self) -> Dict[str, Any]:
        """
        获取用户统计信息

        Returns:
            Dict: 统计信息
        """
        data = self.read_data()
        stats = {
            'total_users': len(data['users']),
            'roles': {},
            'status': {},
            'recent_registrations': 0  # 最近7天注册数
        }

        # 统计角色和状态分布
        now = datetime.utcnow()
        week_ago = now.timestamp() - (7 * 24 * 3600)

        for user_data in data['users'].values():
            # 角色统计
            role = user_data.get('role', 'unknown')
            stats['roles'][role] = stats['roles'].get(role, 0) + 1

            # 状态统计
            status = user_data.get('status', 'unknown')
            stats['status'][status] = stats['status'].get(status, 0) + 1

            # 最近注册统计
            try:
                created_at = user_data.get('created_at', '')
                if created_at:
                    created_dt = datetime.fromisoformat(created_at.replace('Z', '+00:00'))
                    if created_dt.timestamp() > week_ago:
                        stats['recent_registrations'] += 1
            except (ValueError, AttributeError):
                pass

        return stats

    def username_exists(self, username: str) -> bool:
        """
        检查用户名是否存在

        Args:
            username: 用户名

        Returns:
            bool: 是否存在
        """
        return self.get_user_by_username(username) is not None

    def email_exists(self, email: str) -> bool:
        """
        检查邮箱是否存在

        Args:
            email: 邮箱地址

        Returns:
            bool: 是否存在
        """
        if not email:
            return False

        data = self.read_data()
        for user_data in data['users'].values():
            if user_data.get('email', '').lower() == email.lower():
                return True
        return False