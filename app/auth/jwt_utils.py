"""
JWT工具函数
提供JWT Token的生成、验证和管理功能
"""
import jwt
import uuid
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, Tuple
from flask import current_app
import logging

from ..models.user import User
from ..storage.manager import get_token_blacklist_storage

logger = logging.getLogger(__name__)


class JWTManager:
    """JWT管理器"""

    @staticmethod
    def generate_token(user: User) -> Tuple[str, str]:
        """
        生成JWT Token

        Args:
            user: 用户对象

        Returns:
            Tuple[str, str]: (token, expires_at)
        """
        now = datetime.utcnow()
        expires_at = now + timedelta(hours=current_app.config['JWT_EXPIRATION_HOURS'])
        jti = str(uuid.uuid4())  # 唯一标识符

        payload = {
            'user_id': user.id,
            'username': user.username,
            'role': user.role,
            'iat': now,  # 签发时间
            'exp': expires_at,  # 过期时间
            'jti': jti  # JWT ID，用于Token撤销
        }

        token = jwt.encode(
            payload,
            current_app.config['JWT_SECRET_KEY'],
            algorithm=current_app.config.get('JWT_ALGORITHM', 'HS256')
        )

        expires_at_str = expires_at.isoformat() + 'Z'
        logger.debug(f"JWT Token生成成功: 用户 {user.username} (ID: {user.id})")

        return token, expires_at_str

    @staticmethod
    def decode_token(token: str) -> Optional[Dict[str, Any]]:
        """
        解码JWT Token

        Args:
            token: JWT Token字符串

        Returns:
            Optional[Dict]: Token载荷，无效时返回None
        """
        try:
            payload = jwt.decode(
                token,
                current_app.config['JWT_SECRET_KEY'],
                algorithms=[current_app.config.get('JWT_ALGORITHM', 'HS256')]
            )
            return payload
        except jwt.ExpiredSignatureError:
            logger.warning("JWT Token已过期")
            return None
        except jwt.InvalidTokenError as e:
            logger.warning(f"JWT Token无效: {e}")
            return None

    @staticmethod
    def validate_token(token: str, check_blacklist: bool = True) -> Tuple[bool, Optional[Dict[str, Any]], str]:
        """
        验证JWT Token

        Args:
            token: JWT Token字符串
            check_blacklist: 是否检查黑名单

        Returns:
            Tuple[bool, Optional[Dict], str]: (是否有效, 载荷, 错误信息)
        """
        # 解码Token
        payload = JWTManager.decode_token(token)
        if payload is None:
            return False, None, "Token无效或已过期"

        # 检查必需字段
        required_fields = ['user_id', 'username', 'role', 'jti']
        if not all(field in payload for field in required_fields):
            return False, None, "Token载荷缺少必需字段"

        # 检查是否在黑名单中
        if check_blacklist:
            token_jti = payload.get('jti')
            if token_jti and JWTManager.is_token_blacklisted(token_jti):
                return False, None, "Token已被撤销"

        return True, payload, ""

    @staticmethod
    def is_token_blacklisted(token_jti: str) -> bool:
        """
        检查Token是否在黑名单中

        Args:
            token_jti: Token的JTI

        Returns:
            bool: 是否在黑名单中
        """
        try:
            blacklist_storage = get_token_blacklist_storage()
            return blacklist_storage.is_token_blacklisted(token_jti)
        except Exception as e:
            logger.error(f"检查Token黑名单失败: {e}")
            return False

    @staticmethod
    def revoke_token(token: str, reason: str = 'logout') -> bool:
        """
        撤销Token（加入黑名单）

        Args:
            token: JWT Token字符串
            reason: 撤销原因

        Returns:
            bool: 是否成功撤销
        """
        try:
            payload = JWTManager.decode_token(token)
            if not payload:
                return False

            token_jti = payload.get('jti')
            user_id = payload.get('user_id')
            exp = payload.get('exp')

            if not all([token_jti, user_id, exp]):
                return False

            # 转换过期时间格式
            if isinstance(exp, (int, float)):
                expires_at = datetime.fromtimestamp(exp).isoformat() + 'Z'
            else:
                expires_at = str(exp)

            # 添加到黑名单
            blacklist_storage = get_token_blacklist_storage()
            blacklist_storage.add_token(
                token_jti=token_jti,
                user_id=user_id,
                expires_at=expires_at,
                reason=reason
            )

            logger.info(f"Token已撤销: 用户 {user_id}, 原因: {reason}")
            return True

        except Exception as e:
            logger.error(f"撤销Token失败: {e}")
            return False

    @staticmethod
    def refresh_token(old_token: str) -> Optional[Tuple[str, str]]:
        """
        刷新Token

        Args:
            old_token: 旧的JWT Token

        Returns:
            Optional[Tuple[str, str]]: 新Token和过期时间，失败时返回None
        """
        try:
            # 验证旧Token（但允许即将过期的Token）
            payload = JWTManager.decode_token(old_token)
            if not payload:
                return None

            # 检查是否在黑名单中
            token_jti = payload.get('jti')
            if token_jti and JWTManager.is_token_blacklisted(token_jti):
                return None

            # 检查Token是否在可刷新时间内（过期前2小时）
            exp = payload.get('exp')
            if isinstance(exp, (int, float)):
                exp_dt = datetime.fromtimestamp(exp)
                now = datetime.utcnow()
                refresh_cutoff = exp_dt - timedelta(hours=2)

                if now < refresh_cutoff:
                    logger.warning("Token还未到刷新时间")
                    return None

            # 从存储中获取最新的用户信息
            from ..storage.manager import get_user_storage
            user_storage = get_user_storage()
            user = user_storage.get_user_by_id(payload.get('user_id'))

            if not user or not user.is_active():
                return None

            # 撤销旧Token
            JWTManager.revoke_token(old_token, 'refresh')

            # 生成新Token
            new_token, expires_at = JWTManager.generate_token(user)

            logger.info(f"Token已刷新: 用户 {user.username}")
            return new_token, expires_at

        except Exception as e:
            logger.error(f"刷新Token失败: {e}")
            return None

    @staticmethod
    def extract_token_from_header(auth_header: str) -> Optional[str]:
        """
        从Authorization头部提取Token

        Args:
            auth_header: Authorization头部值

        Returns:
            Optional[str]: Token字符串，失败时返回None
        """
        if not auth_header:
            return None

        # 支持 "Bearer <token>" 格式
        if auth_header.startswith('Bearer '):
            return auth_header[7:]  # 去掉 "Bearer " 前缀

        # 支持直接传递Token
        return auth_header

    @staticmethod
    def get_token_info(token: str) -> Dict[str, Any]:
        """
        获取Token信息（不验证签名，仅解析）

        Args:
            token: JWT Token字符串

        Returns:
            Dict: Token信息
        """
        try:
            # 不验证签名，仅解析
            payload = jwt.decode(
                token,
                options={"verify_signature": False}
            )

            # 转换时间戳为可读格式
            info = {
                'user_id': payload.get('user_id'),
                'username': payload.get('username'),
                'role': payload.get('role'),
                'jti': payload.get('jti'),
                'issued_at': None,
                'expires_at': None,
                'is_expired': False
            }

            # 处理签发时间
            iat = payload.get('iat')
            if iat:
                if isinstance(iat, (int, float)):
                    info['issued_at'] = datetime.fromtimestamp(iat).isoformat() + 'Z'
                else:
                    info['issued_at'] = str(iat)

            # 处理过期时间
            exp = payload.get('exp')
            if exp:
                if isinstance(exp, (int, float)):
                    exp_dt = datetime.fromtimestamp(exp)
                    info['expires_at'] = exp_dt.isoformat() + 'Z'
                    info['is_expired'] = datetime.utcnow() > exp_dt
                else:
                    info['expires_at'] = str(exp)

            return info

        except Exception as e:
            logger.error(f"解析Token信息失败: {e}")
            return {}

    @staticmethod
    def revoke_all_user_tokens(user_id: int, reason: str = 'admin_action') -> bool:
        """
        撤销用户的所有Token

        Args:
            user_id: 用户ID
            reason: 撤销原因

        Returns:
            bool: 是否成功
        """
        try:
            blacklist_storage = get_token_blacklist_storage()
            blacklist_storage.revoke_all_user_tokens(user_id, reason)
            logger.info(f"用户 {user_id} 的所有Token已撤销: {reason}")
            return True
        except Exception as e:
            logger.error(f"撤销用户所有Token失败: {e}")
            return False


# 便捷函数
def generate_token(user: User) -> Tuple[str, str]:
    """生成Token的便捷函数"""
    return JWTManager.generate_token(user)


def validate_token(token: str) -> Tuple[bool, Optional[Dict[str, Any]], str]:
    """验证Token的便捷函数"""
    return JWTManager.validate_token(token)


def revoke_token(token: str, reason: str = 'logout') -> bool:
    """撤销Token的便捷函数"""
    return JWTManager.revoke_token(token, reason)


def refresh_token(token: str) -> Optional[Tuple[str, str]]:
    """刷新Token的便捷函数"""
    return JWTManager.refresh_token(token)