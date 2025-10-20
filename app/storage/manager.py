"""
存储管理器
统一管理所有存储实例，提供单一访问点
"""
import os
from typing import Optional
from flask import current_app

from .user_storage import UserStorage
from .log_storage import LoginLogStorage
from .permission_storage import PermissionStorage, TokenBlacklistStorage


class StorageManager:
    """存储管理器"""

    def __init__(self, config=None):
        """
        初始化存储管理器

        Args:
            config: 配置对象，如果为None则从Flask应用上下文获取
        """
        self._config = config or current_app.config
        self._user_storage = None
        self._log_storage = None
        self._permission_storage = None
        self._token_blacklist_storage = None

    @property
    def user_storage(self) -> UserStorage:
        """用户存储实例"""
        if self._user_storage is None:
            file_path = os.path.join(
                self._config['DATA_DIR'],
                self._config['USERS_FILE']
            )
            self._user_storage = UserStorage(file_path)
        return self._user_storage

    @property
    def log_storage(self) -> LoginLogStorage:
        """登录日志存储实例"""
        if self._log_storage is None:
            file_path = os.path.join(
                self._config['DATA_DIR'],
                self._config['LOGIN_LOGS_FILE']
            )
            self._log_storage = LoginLogStorage(file_path)
        return self._log_storage

    @property
    def permission_storage(self) -> PermissionStorage:
        """权限配置存储实例"""
        if self._permission_storage is None:
            file_path = os.path.join(
                self._config['DATA_DIR'],
                self._config['PERMISSIONS_FILE']
            )
            self._permission_storage = PermissionStorage(file_path)
        return self._permission_storage

    @property
    def token_blacklist_storage(self) -> TokenBlacklistStorage:
        """Token黑名单存储实例"""
        if self._token_blacklist_storage is None:
            file_path = os.path.join(
                self._config['DATA_DIR'],
                self._config['TOKEN_BLACKLIST_FILE']
            )
            self._token_blacklist_storage = TokenBlacklistStorage(file_path)
        return self._token_blacklist_storage

    def initialize_data(self):
        """初始化所有数据文件和默认数据"""
        # 确保所有存储实例被创建（这会创建文件）
        _ = self.user_storage
        _ = self.log_storage
        _ = self.permission_storage
        _ = self.token_blacklist_storage

        # 初始化默认权限规则
        self.permission_storage.initialize_default_permissions()

    def get_system_statistics(self) -> dict:
        """
        获取系统统计信息

        Returns:
            dict: 系统统计信息
        """
        stats = {
            'users': self.user_storage.get_statistics(),
            'login_logs': self.log_storage.get_login_statistics(),
            'permissions': {
                'total_rules': len(self.permission_storage.get_all_permissions()),
                'enabled_rules': len(self.permission_storage.get_enabled_permissions())
            },
            'token_blacklist': {
                'total_items': len(self.token_blacklist_storage.read_data().get('blacklist', []))
            }
        }
        return stats

    def backup_all_data(self, backup_dir: str = None) -> dict:
        """
        备份所有数据文件

        Args:
            backup_dir: 备份目录，如果为None则使用默认备份目录

        Returns:
            dict: 备份结果信息
        """
        if backup_dir is None:
            backup_dir = self._config.get('BACKUP_DIR', './backups')

        os.makedirs(backup_dir, exist_ok=True)

        results = {}
        storage_instances = [
            ('users', self.user_storage),
            ('login_logs', self.log_storage),
            ('permissions', self.permission_storage),
            ('token_blacklist', self.token_blacklist_storage)
        ]

        for name, storage in storage_instances:
            try:
                backup_path = os.path.join(backup_dir, f"{name}_backup.json")
                actual_path = storage.backup_data(backup_path)
                results[name] = {
                    'success': True,
                    'backup_path': actual_path
                }
            except Exception as e:
                results[name] = {
                    'success': False,
                    'error': str(e)
                }

        return results

    def cleanup_old_data(self, days_to_keep: int = 30) -> dict:
        """
        清理旧数据

        Args:
            days_to_keep: 保留最近几天的数据

        Returns:
            dict: 清理结果
        """
        results = {}

        # 清理登录日志
        try:
            deleted_logs = self.log_storage.cleanup_old_logs(days_to_keep)
            results['login_logs'] = {
                'success': True,
                'deleted_count': deleted_logs
            }
        except Exception as e:
            results['login_logs'] = {
                'success': False,
                'error': str(e)
            }

        # 清理过期的Token黑名单
        try:
            deleted_tokens = self.token_blacklist_storage.cleanup_expired_tokens()
            results['token_blacklist'] = {
                'success': True,
                'deleted_count': deleted_tokens
            }
        except Exception as e:
            results['token_blacklist'] = {
                'success': False,
                'error': str(e)
            }

        return results

    def check_data_integrity(self) -> dict:
        """
        检查数据完整性

        Returns:
            dict: 检查结果
        """
        results = {}

        storage_instances = [
            ('users', self.user_storage),
            ('login_logs', self.log_storage),
            ('permissions', self.permission_storage),
            ('token_blacklist', self.token_blacklist_storage)
        ]

        for name, storage in storage_instances:
            try:
                data = storage.read_data()
                file_info = storage.get_file_info()
                results[name] = {
                    'valid': storage._validate_data_structure(data),
                    'file_exists': file_info.get('exists', False),
                    'file_size': file_info.get('size', 0),
                    'last_modified': file_info.get('modified_at', '')
                }
            except Exception as e:
                results[name] = {
                    'valid': False,
                    'error': str(e)
                }

        return results


# 全局存储管理器实例
_storage_manager: Optional[StorageManager] = None


def get_storage_manager() -> StorageManager:
    """
    获取存储管理器实例（单例模式）

    Returns:
        StorageManager: 存储管理器实例
    """
    global _storage_manager
    if _storage_manager is None:
        _storage_manager = StorageManager()
    return _storage_manager


def init_storage_manager(config=None):
    """
    初始化存储管理器

    Args:
        config: 配置对象
    """
    global _storage_manager
    _storage_manager = StorageManager(config)
    _storage_manager.initialize_data()


# 便捷函数
def get_user_storage() -> UserStorage:
    """获取用户存储实例"""
    return get_storage_manager().user_storage


def get_log_storage() -> LoginLogStorage:
    """获取登录日志存储实例"""
    return get_storage_manager().log_storage


def get_permission_storage() -> PermissionStorage:
    """获取权限配置存储实例"""
    return get_storage_manager().permission_storage


def get_token_blacklist_storage() -> TokenBlacklistStorage:
    """获取Token黑名单存储实例"""
    return get_storage_manager().token_blacklist_storage