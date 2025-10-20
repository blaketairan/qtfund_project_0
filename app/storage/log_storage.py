"""
登录日志存储
基于JSON文件的登录日志管理
"""
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta
import logging

from .base import BaseFileStorage
from ..models.login_log import LoginLog

logger = logging.getLogger(__name__)


class LoginLogStorage(BaseFileStorage[LoginLog]):
    """登录日志存储"""

    def __init__(self, file_path: str):
        super().__init__(file_path)

    def _get_empty_structure(self) -> Dict[str, Any]:
        """获取空的日志数据结构"""
        return {
            'logs': [],  # 日志列表
            'next_id': 1,  # 下一个日志ID
            'metadata': {
                'version': '1.0',
                'created_at': datetime.utcnow().isoformat() + 'Z',
                'last_updated': datetime.utcnow().isoformat() + 'Z',
                'log_count': 0
            }
        }

    def _validate_data_structure(self, data: Dict[str, Any]) -> bool:
        """验证日志数据结构"""
        if not isinstance(data, dict):
            return False

        required_fields = {'logs', 'next_id', 'metadata'}
        if not all(field in data for field in required_fields):
            return False

        if not isinstance(data.get('logs'), list):
            return False

        if not isinstance(data.get('next_id'), int):
            return False

        return True

    def add_log(self, user_id: int, username: str, ip_address: str,
                user_agent: str, success: bool, error_message: str = None) -> LoginLog:
        """
        添加登录日志

        Args:
            user_id: 用户ID
            username: 用户名
            ip_address: IP地址
            user_agent: 用户代理
            success: 是否成功
            error_message: 错误信息（失败时）

        Returns:
            LoginLog: 日志对象
        """
        def _add_log(data):
            log_id = data['next_id']

            if success:
                log = LoginLog.create_success_log(
                    log_id=log_id,
                    user_id=user_id,
                    username=username,
                    ip_address=ip_address,
                    user_agent=user_agent
                )
            else:
                log = LoginLog.create_failure_log(
                    log_id=log_id,
                    username=username,
                    ip_address=ip_address,
                    user_agent=user_agent,
                    error_message=error_message or '',
                    user_id=user_id if user_id > 0 else None
                )

            # 添加到日志列表
            data['logs'].append(log.to_dict())
            data['next_id'] = log_id + 1
            data['metadata']['log_count'] = len(data['logs'])
            data['metadata']['last_updated'] = datetime.utcnow().isoformat() + 'Z'

            logger.debug(f"登录日志已添加: {username} ({'成功' if success else '失败'})")
            return data

        self.update_data(_add_log)

        # 返回创建的日志
        data = self.read_data()
        return LoginLog.from_dict(data['logs'][-1])

    def get_logs_by_user(self, user_id: int, limit: int = 100) -> List[LoginLog]:
        """
        获取用户的登录日志

        Args:
            user_id: 用户ID
            limit: 限制返回数量

        Returns:
            List[LoginLog]: 日志列表
        """
        data = self.read_data()
        logs = []

        # 倒序遍历（最新的在前）
        for log_data in reversed(data['logs']):
            if log_data.get('user_id') == user_id:
                try:
                    logs.append(LoginLog.from_dict(log_data))
                    if len(logs) >= limit:
                        break
                except Exception as e:
                    logger.warning(f"解析登录日志失败: {e}")

        return logs

    def get_logs_by_ip(self, ip_address: str, limit: int = 100) -> List[LoginLog]:
        """
        获取指定IP的登录日志

        Args:
            ip_address: IP地址
            limit: 限制返回数量

        Returns:
            List[LoginLog]: 日志列表
        """
        data = self.read_data()
        logs = []

        for log_data in reversed(data['logs']):
            if log_data.get('ip_address') == ip_address:
                try:
                    logs.append(LoginLog.from_dict(log_data))
                    if len(logs) >= limit:
                        break
                except Exception as e:
                    logger.warning(f"解析登录日志失败: {e}")

        return logs

    def get_recent_logs(self, hours: int = 24, limit: int = 1000) -> List[LoginLog]:
        """
        获取最近的登录日志

        Args:
            hours: 最近几小时
            limit: 限制返回数量

        Returns:
            List[LoginLog]: 日志列表
        """
        data = self.read_data()
        logs = []
        cutoff_time = datetime.utcnow() - timedelta(hours=hours)

        for log_data in reversed(data['logs']):
            try:
                log_time = datetime.fromisoformat(
                    log_data.get('login_time', '').replace('Z', '+00:00')
                )
                if log_time.replace(tzinfo=None) >= cutoff_time:
                    logs.append(LoginLog.from_dict(log_data))
                    if len(logs) >= limit:
                        break
                else:
                    # 由于是倒序遍历，如果当前日志太旧，后面的都更旧
                    break
            except (ValueError, AttributeError) as e:
                logger.warning(f"解析登录时间失败: {e}")

        return logs

    def get_failed_login_attempts(self, username: str = None, ip_address: str = None,
                                 hours: int = 1) -> List[LoginLog]:
        """
        获取失败的登录尝试

        Args:
            username: 用户名（可选）
            ip_address: IP地址（可选）
            hours: 最近几小时

        Returns:
            List[LoginLog]: 失败日志列表
        """
        recent_logs = self.get_recent_logs(hours=hours)
        failed_logs = []

        for log in recent_logs:
            if not log.success:
                if username and log.username != username:
                    continue
                if ip_address and log.ip_address != ip_address:
                    continue
                failed_logs.append(log)

        return failed_logs

    def get_login_statistics(self, days: int = 7) -> Dict[str, Any]:
        """
        获取登录统计信息

        Args:
            days: 统计最近几天

        Returns:
            Dict: 统计信息
        """
        data = self.read_data()
        cutoff_time = datetime.utcnow() - timedelta(days=days)

        stats = {
            'total_attempts': 0,
            'successful_logins': 0,
            'failed_attempts': 0,
            'unique_users': set(),
            'unique_ips': set(),
            'daily_stats': {},
            'failure_reasons': {}
        }

        for log_data in data['logs']:
            try:
                log_time = datetime.fromisoformat(
                    log_data.get('login_time', '').replace('Z', '+00:00')
                )
                if log_time.replace(tzinfo=None) < cutoff_time:
                    continue

                stats['total_attempts'] += 1

                # 按日期统计
                date_str = log_time.strftime('%Y-%m-%d')
                if date_str not in stats['daily_stats']:
                    stats['daily_stats'][date_str] = {
                        'total': 0, 'success': 0, 'failed': 0
                    }
                stats['daily_stats'][date_str]['total'] += 1

                if log_data.get('success', False):
                    stats['successful_logins'] += 1
                    stats['daily_stats'][date_str]['success'] += 1
                    if log_data.get('user_id'):
                        stats['unique_users'].add(log_data['user_id'])
                else:
                    stats['failed_attempts'] += 1
                    stats['daily_stats'][date_str]['failed'] += 1

                    # 失败原因统计
                    error_msg = log_data.get('error_message', '未知错误')
                    stats['failure_reasons'][error_msg] = stats['failure_reasons'].get(error_msg, 0) + 1

                # IP统计
                if log_data.get('ip_address'):
                    stats['unique_ips'].add(log_data['ip_address'])

            except (ValueError, AttributeError) as e:
                logger.warning(f"解析登录日志统计失败: {e}")

        # 转换set为数量
        stats['unique_users'] = len(stats['unique_users'])
        stats['unique_ips'] = len(stats['unique_ips'])

        # 计算成功率
        if stats['total_attempts'] > 0:
            stats['success_rate'] = round(
                (stats['successful_logins'] / stats['total_attempts']) * 100, 2
            )
        else:
            stats['success_rate'] = 0

        return stats

    def cleanup_old_logs(self, days_to_keep: int = 30) -> int:
        """
        清理旧日志

        Args:
            days_to_keep: 保留最近几天的日志

        Returns:
            int: 删除的日志数量
        """
        cutoff_time = datetime.utcnow() - timedelta(days=days_to_keep)
        deleted_count = 0

        def _cleanup_logs(data):
            nonlocal deleted_count
            new_logs = []

            for log_data in data['logs']:
                try:
                    log_time = datetime.fromisoformat(
                        log_data.get('login_time', '').replace('Z', '+00:00')
                    )
                    if log_time.replace(tzinfo=None) >= cutoff_time:
                        new_logs.append(log_data)
                    else:
                        deleted_count += 1
                except (ValueError, AttributeError):
                    # 保留无法解析时间的日志
                    new_logs.append(log_data)

            data['logs'] = new_logs
            data['metadata']['log_count'] = len(new_logs)
            data['metadata']['last_updated'] = datetime.utcnow().isoformat() + 'Z'

            logger.info(f"已清理 {deleted_count} 条旧登录日志")
            return data

        self.update_data(_cleanup_logs)
        return deleted_count

    def search_logs(self, keyword: str, limit: int = 100) -> List[LoginLog]:
        """
        搜索登录日志

        Args:
            keyword: 搜索关键词
            limit: 限制返回数量

        Returns:
            List[LoginLog]: 匹配的日志列表
        """
        data = self.read_data()
        logs = []
        keyword_lower = keyword.lower()

        search_fields = ['username', 'ip_address', 'user_agent', 'error_message']

        for log_data in reversed(data['logs']):
            # 检查各字段是否包含关键词
            for field in search_fields:
                field_value = log_data.get(field)
                if field_value and keyword_lower in str(field_value).lower():
                    try:
                        logs.append(LoginLog.from_dict(log_data))
                        break
                    except Exception as e:
                        logger.warning(f"解析登录日志失败: {e}")

            if len(logs) >= limit:
                break

        return logs