"""
认证相关路由
包括登录、注册、登出、Token刷新和验证功能
"""
from flask import Blueprint, request, current_app
from flask_limiter import Limiter
import logging

from ..utils.responses import success_response, error_response, validation_error_response
from ..auth.validators import (
    UserLoginSchema, UserRegistrationSchema,
    validate_request_json
)
from ..auth.jwt_utils import generate_token, validate_token, revoke_token, refresh_token
from ..storage.manager import get_user_storage, get_log_storage, get_permission_storage
from ..models.user import User

# 创建认证蓝图
auth_bp = Blueprint('auth', __name__)
logger = logging.getLogger(__name__)


def get_client_info():
    """获取客户端信息"""
    return {
        'ip_address': request.headers.get('X-Real-IP') or
                     request.headers.get('X-Forwarded-For', '').split(',')[0].strip() or
                     request.remote_addr or 'unknown',
        'user_agent': request.headers.get('User-Agent', 'unknown')
    }


@auth_bp.route('/login', methods=['POST'])
def login():
    """
    用户登录

    请求体:
    {
        "username": "string",
        "password": "string"
    }
    """
    # 验证请求数据
    is_valid, data, errors = validate_request_json(UserLoginSchema())
    if not is_valid:
        return validation_error_response(errors)

    username = data['username']
    password = data['password']
    client_info = get_client_info()

    # 获取存储实例
    user_storage = get_user_storage()
    log_storage = get_log_storage()

    try:
        # 查找用户
        user = user_storage.get_user_by_username(username)

        if not user:
            # 记录失败日志
            log_storage.add_log(
                user_id=0,
                username=username,
                ip_address=client_info['ip_address'],
                user_agent=client_info['user_agent'],
                success=False,
                error_message="用户不存在"
            )
            return error_response("用户名或密码错误", 401, "INVALID_CREDENTIALS")

        # 检查用户状态
        if not user.is_active():
            log_storage.add_log(
                user_id=user.id,
                username=username,
                ip_address=client_info['ip_address'],
                user_agent=client_info['user_agent'],
                success=False,
                error_message="用户已被禁用"
            )
            return error_response("账号已被禁用，请联系管理员", 401, "ACCOUNT_DISABLED")

        # 验证密码
        if not user.verify_password(password):
            log_storage.add_log(
                user_id=user.id,
                username=username,
                ip_address=client_info['ip_address'],
                user_agent=client_info['user_agent'],
                success=False,
                error_message="密码错误"
            )
            return error_response("用户名或密码错误", 401, "INVALID_CREDENTIALS")

        # 生成Token
        token, expires_at = generate_token(user)

        # 更新用户登录信息
        user.update_last_login()
        user_storage.update_user(user)

        # 记录成功日志
        log_storage.add_log(
            user_id=user.id,
            username=username,
            ip_address=client_info['ip_address'],
            user_agent=client_info['user_agent'],
            success=True
        )

        # 返回登录成功响应
        response_data = {
            'token': token,
            'expires_at': expires_at,
            'user': user.to_public_dict()
        }

        logger.info(f"用户登录成功: {username} ({client_info['ip_address']})")
        return success_response("登录成功", response_data)

    except Exception as e:
        logger.error(f"登录处理失败: {e}")
        return error_response("登录处理失败，请稍后重试", 500, "LOGIN_ERROR")


@auth_bp.route('/register', methods=['POST'])
def register():
    """
    用户注册

    请求体:
    {
        "username": "string",
        "password": "string",
        "email": "string (可选)",
        "real_name": "string (可选)"
    }
    """
    # 验证请求数据
    is_valid, data, errors = validate_request_json(UserRegistrationSchema())
    if not is_valid:
        return validation_error_response(errors)

    username = data['username']
    password = data['password']
    email = data.get('email')
    real_name = data.get('real_name')

    # 获取存储实例
    user_storage = get_user_storage()

    try:
        # 检查用户名是否已存在
        if user_storage.username_exists(username):
            return error_response("用户名已存在", 400, "USERNAME_EXISTS")

        # 检查邮箱是否已存在
        if email and user_storage.email_exists(email):
            return error_response("邮箱已被使用", 400, "EMAIL_EXISTS")

        # 创建新用户
        user = user_storage.create_user(
            username=username,
            password=password,
            email=email,
            real_name=real_name,
            role=current_app.config.get('DEFAULT_ROLE', 'user')
        )

        logger.info(f"新用户注册成功: {username}")

        # 返回注册成功响应
        response_data = {
            'user_id': user.id,
            'username': user.username,
            'message': '注册成功，请使用用户名和密码登录'
        }

        return success_response("注册成功", response_data, 201)

    except ValueError as e:
        return error_response(str(e), 400, "REGISTRATION_ERROR")
    except Exception as e:
        logger.error(f"注册处理失败: {e}")
        return error_response("注册处理失败，请稍后重试", 500, "REGISTRATION_ERROR")


@auth_bp.route('/logout', methods=['POST'])
def logout():
    """
    用户登出

    请求头:
    Authorization: Bearer <token>
    """
    # 获取Token
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return error_response("缺少认证Token", 401, "MISSING_TOKEN")

    token = auth_header[7:]  # 去掉 "Bearer " 前缀

    try:
        # 验证Token
        is_valid, payload, error_msg = validate_token(token)
        if not is_valid:
            return error_response(f"Token验证失败: {error_msg}", 401, "INVALID_TOKEN")

        # 撤销Token
        if revoke_token(token, 'logout'):
            username = payload.get('username', 'unknown')
            logger.info(f"用户登出成功: {username}")
            return success_response("登出成功")
        else:
            return error_response("登出处理失败", 500, "LOGOUT_ERROR")

    except Exception as e:
        logger.error(f"登出处理失败: {e}")
        return error_response("登出处理失败", 500, "LOGOUT_ERROR")


@auth_bp.route('/refresh', methods=['POST'])
def refresh():
    """
    刷新Token

    请求头:
    Authorization: Bearer <token>
    """
    # 获取Token
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return error_response("缺少认证Token", 401, "MISSING_TOKEN")

    old_token = auth_header[7:]  # 去掉 "Bearer " 前缀

    try:
        # 刷新Token
        result = refresh_token(old_token)
        if result:
            new_token, expires_at = result
            response_data = {
                'token': new_token,
                'expires_at': expires_at
            }
            logger.info("Token刷新成功")
            return success_response("Token刷新成功", response_data)
        else:
            return error_response("Token刷新失败，请重新登录", 401, "REFRESH_FAILED")

    except Exception as e:
        logger.error(f"Token刷新失败: {e}")
        return error_response("Token刷新失败", 500, "REFRESH_ERROR")


@auth_bp.route('/validate', methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'])
def validate():
    """
    Token验证（用于Nginx auth_request）

    Nginx会传递以下头部：
    - X-Original-URI: 原始请求路径
    - X-Original-Method: 原始请求方法
    - Authorization: Bearer token 或 Cookie
    """
    try:
        # 获取原始请求信息
        original_uri = request.headers.get('X-Original-URI', request.path)
        original_method = request.headers.get('X-Original-Method', request.method)

        # 获取Token
        token = None

        # 优先从Authorization头部获取
        auth_header = request.headers.get('Authorization', '')
        if auth_header.startswith('Bearer '):
            token = auth_header[7:]
        else:
            # 从Cookie获取
            token = request.cookies.get('auth_token')

        if not token:
            logger.warning(f"访问被拒绝 - 缺少Token: {original_method} {original_uri}")
            return '', 401

        # 验证Token
        is_valid, payload, error_msg = validate_token(token)
        if not is_valid:
            logger.warning(f"访问被拒绝 - Token无效: {original_method} {original_uri}, 错误: {error_msg}")
            return '', 401

        # 获取用户信息
        user_id = payload.get('user_id')
        username = payload.get('username')
        user_role = payload.get('role')

        # 检查权限
        permission_storage = get_permission_storage()
        has_permission = permission_storage.check_permission(original_uri, original_method, user_role)

        if not has_permission:
            logger.warning(f"访问被拒绝 - 权限不足: 用户 {username} 尝试访问 {original_method} {original_uri}")
            return '', 403

        # 返回成功响应，并在头部传递用户信息给Nginx
        response = current_app.response_class('', 200)
        response.headers['X-User-ID'] = str(user_id)
        response.headers['X-User-Role'] = user_role
        response.headers['X-User-Name'] = username

        return response

    except Exception as e:
        logger.error(f"认证验证失败: {e}")
        return '', 500


# 添加限流装饰器（如果启用了限流）
if current_app and current_app.limiter:
    login = current_app.limiter.limit(
        current_app.config.get('RATE_LIMIT_LOGIN', '10/minute')
    )(login)

    register = current_app.limiter.limit(
        current_app.config.get('RATE_LIMIT_LOGIN', '10/minute')
    )(register)