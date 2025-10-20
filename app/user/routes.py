"""
用户管理路由
用户个人信息管理、密码修改等功能
"""
from flask import Blueprint, request
import logging

from ..utils.responses import success_response, error_response, validation_error_response
from ..auth.validators import (
    UserProfileUpdateSchema, PasswordChangeSchema,
    validate_request_json
)
from ..auth.jwt_utils import validate_token
from ..storage.manager import get_user_storage, get_log_storage

# 创建用户管理蓝图
user_bp = Blueprint('user', __name__)
logger = logging.getLogger(__name__)


def get_current_user_from_token():
    """从Token获取当前用户信息"""
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return None, "缺少认证Token"

    token = auth_header[7:]
    is_valid, payload, error_msg = validate_token(token)
    if not is_valid:
        return None, f"Token验证失败: {error_msg}"

    user_storage = get_user_storage()
    user = user_storage.get_user_by_id(payload.get('user_id'))
    if not user:
        return None, "用户不存在"

    if not user.is_active():
        return None, "用户已被禁用"

    return user, None


@user_bp.route('/profile', methods=['GET'])
def get_profile():
    """
    获取用户个人信息

    请求头:
    Authorization: Bearer <token>
    """
    user, error_msg = get_current_user_from_token()
    if not user:
        return error_response(error_msg, 401, "UNAUTHORIZED")

    try:
        return success_response("获取用户信息成功", user.to_public_dict())
    except Exception as e:
        logger.error(f"获取用户信息失败: {e}")
        return error_response("获取用户信息失败", 500, "PROFILE_ERROR")


@user_bp.route('/profile', methods=['PUT'])
def update_profile():
    """
    更新用户个人信息

    请求头:
    Authorization: Bearer <token>

    请求体:
    {
        "email": "string (可选)",
        "real_name": "string (可选)"
    }
    """
    user, error_msg = get_current_user_from_token()
    if not user:
        return error_response(error_msg, 401, "UNAUTHORIZED")

    # 验证请求数据
    is_valid, data, errors = validate_request_json(UserProfileUpdateSchema())
    if not is_valid:
        return validation_error_response(errors)

    try:
        user_storage = get_user_storage()

        # 检查邮箱是否已被其他用户使用
        email = data.get('email')
        if email and email != user.email:
            if user_storage.email_exists(email):
                return error_response("邮箱已被其他用户使用", 400, "EMAIL_EXISTS")

        # 更新用户信息
        user.update_info(**data)
        success = user_storage.update_user(user)

        if success:
            logger.info(f"用户信息更新成功: {user.username}")
            return success_response("用户信息更新成功", user.to_public_dict())
        else:
            return error_response("用户信息更新失败", 500, "UPDATE_FAILED")

    except Exception as e:
        logger.error(f"更新用户信息失败: {e}")
        return error_response("更新用户信息失败", 500, "UPDATE_ERROR")


@user_bp.route('/password', methods=['PUT'])
def change_password():
    """
    修改用户密码

    请求头:
    Authorization: Bearer <token>

    请求体:
    {
        "old_password": "string",
        "new_password": "string"
    }
    """
    user, error_msg = get_current_user_from_token()
    if not user:
        return error_response(error_msg, 401, "UNAUTHORIZED")

    # 验证请求数据
    is_valid, data, errors = validate_request_json(PasswordChangeSchema())
    if not is_valid:
        return validation_error_response(errors)

    old_password = data['old_password']
    new_password = data['new_password']

    try:
        # 验证当前密码
        if not user.verify_password(old_password):
            return error_response("当前密码错误", 400, "INVALID_PASSWORD")

        # 更新密码
        user.update_password(new_password)
        user_storage = get_user_storage()
        success = user_storage.update_user(user)

        if success:
            logger.info(f"用户密码修改成功: {user.username}")
            return success_response("密码修改成功")
        else:
            return error_response("密码修改失败", 500, "UPDATE_FAILED")

    except Exception as e:
        logger.error(f"修改密码失败: {e}")
        return error_response("修改密码失败", 500, "PASSWORD_ERROR")


@user_bp.route('/login-history', methods=['GET'])
def get_login_history():
    """
    获取用户登录历史

    请求头:
    Authorization: Bearer <token>

    查询参数:
    - limit: 返回记录数量限制，默认20，最大100
    """
    user, error_msg = get_current_user_from_token()
    if not user:
        return error_response(error_msg, 401, "UNAUTHORIZED")

    try:
        # 获取查询参数
        limit = request.args.get('limit', '20')
        try:
            limit = int(limit)
            if limit > 100:
                limit = 100
            elif limit < 1:
                limit = 20
        except ValueError:
            limit = 20

        # 获取登录历史
        log_storage = get_log_storage()
        logs = log_storage.get_logs_by_user(user.id, limit)

        # 转换为公开格式
        log_data = [log.to_public_dict() for log in logs]

        return success_response("获取登录历史成功", {
            'logs': log_data,
            'total': len(log_data)
        })

    except Exception as e:
        logger.error(f"获取登录历史失败: {e}")
        return error_response("获取登录历史失败", 500, "HISTORY_ERROR")