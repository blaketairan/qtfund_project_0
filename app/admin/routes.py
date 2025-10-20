"""
管理员功能路由
用户管理、权限管理、系统统计等管理功能
"""
from flask import Blueprint, request
import logging

from ..utils.responses import (
    success_response, error_response, validation_error_response, paginated_response
)
from ..auth.validators import (
    AdminUserRoleUpdateSchema, AdminUserStatusUpdateSchema,
    PaginationSchema, validate_request_json, validate_query_params
)
from ..auth.jwt_utils import validate_token, revoke_all_user_tokens
from ..storage.manager import get_user_storage, get_log_storage, get_storage_manager

# 创建管理员蓝图
admin_bp = Blueprint('admin', __name__)
logger = logging.getLogger(__name__)


def get_admin_user_from_token():
    """从Token获取管理员用户信息"""
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

    if not user.is_admin():
        return None, "权限不足，需要管理员权限"

    return user, None


@admin_bp.route('/users', methods=['GET'])
def get_users():
    """
    获取用户列表

    请求头:
    Authorization: Bearer <token>

    查询参数:
    - page: 页码，默认1
    - size: 每页大小，默认10
    - role: 角色筛选（可选）
    - status: 状态筛选（可选）
    - keyword: 搜索关键词（可选）
    """
    admin_user, error_msg = get_admin_user_from_token()
    if not admin_user:
        return error_response(error_msg, 401, "UNAUTHORIZED")

    # 验证查询参数
    is_valid, pagination_data, errors = validate_query_params(PaginationSchema())
    if not is_valid:
        return validation_error_response(errors)

    try:
        user_storage = get_user_storage()
        page = pagination_data['page']
        size = pagination_data['size']

        # 获取筛选参数
        role = request.args.get('role')
        status = request.args.get('status')
        keyword = request.args.get('keyword')

        # 获取用户列表
        if keyword:
            # 搜索用户
            all_users = user_storage.search_users(keyword)
        elif role:
            # 按角色筛选
            all_users = user_storage.get_users_by_role(role)
        elif status:
            # 按状态筛选
            all_users = user_storage.get_users_by_status(status)
        else:
            # 获取所有用户
            all_users = user_storage.get_all_users()

        # 分页处理
        total = len(all_users)
        start = (page - 1) * size
        end = start + size
        users = all_users[start:end]

        # 转换为公开格式
        user_data = [user.to_public_dict() for user in users]

        return paginated_response(user_data, page, size, total, "获取用户列表成功")

    except Exception as e:
        logger.error(f"获取用户列表失败: {e}")
        return error_response("获取用户列表失败", 500, "USERS_ERROR")


@admin_bp.route('/users/<int:user_id>', methods=['GET'])
def get_user_detail(user_id):
    """
    获取用户详细信息

    请求头:
    Authorization: Bearer <token>
    """
    admin_user, error_msg = get_admin_user_from_token()
    if not admin_user:
        return error_response(error_msg, 401, "UNAUTHORIZED")

    try:
        user_storage = get_user_storage()
        user = user_storage.get_user_by_id(user_id)

        if not user:
            return error_response("用户不存在", 404, "USER_NOT_FOUND")

        # 获取用户的登录历史
        log_storage = get_log_storage()
        recent_logs = log_storage.get_logs_by_user(user_id, limit=10)

        response_data = {
            'user': user.to_public_dict(),
            'recent_logins': [log.to_public_dict() for log in recent_logs]
        }

        return success_response("获取用户详情成功", response_data)

    except Exception as e:
        logger.error(f"获取用户详情失败: {e}")
        return error_response("获取用户详情失败", 500, "USER_DETAIL_ERROR")


@admin_bp.route('/users/<int:user_id>/role', methods=['PUT'])
def update_user_role(user_id):
    """
    更新用户角色

    请求头:
    Authorization: Bearer <token>

    请求体:
    {
        "role": "admin|user|readonly"
    }
    """
    admin_user, error_msg = get_admin_user_from_token()
    if not admin_user:
        return error_response(error_msg, 401, "UNAUTHORIZED")

    # 验证请求数据
    is_valid, data, errors = validate_request_json(AdminUserRoleUpdateSchema())
    if not is_valid:
        return validation_error_response(errors)

    new_role = data['role']

    try:
        user_storage = get_user_storage()
        user = user_storage.get_user_by_id(user_id)

        if not user:
            return error_response("用户不存在", 404, "USER_NOT_FOUND")

        # 防止管理员修改自己的角色
        if user.id == admin_user.id:
            return error_response("不能修改自己的角色", 400, "CANNOT_MODIFY_SELF")

        old_role = user.role
        user.update_info(role=new_role)
        success = user_storage.update_user(user)

        if success:
            # 如果角色降级，撤销用户的所有Token
            if new_role in ['readonly', 'user'] and old_role == 'admin':
                revoke_all_user_tokens(user.id, f'role_change_by_{admin_user.username}')

            logger.info(f"用户角色更新成功: {user.username} {old_role} -> {new_role} (操作者: {admin_user.username})")
            return success_response("用户角色更新成功", user.to_public_dict())
        else:
            return error_response("用户角色更新失败", 500, "UPDATE_FAILED")

    except Exception as e:
        logger.error(f"更新用户角色失败: {e}")
        return error_response("更新用户角色失败", 500, "ROLE_UPDATE_ERROR")


@admin_bp.route('/users/<int:user_id>/status', methods=['PUT'])
def update_user_status(user_id):
    """
    更新用户状态

    请求头:
    Authorization: Bearer <token>

    请求体:
    {
        "status": "active|disabled"
    }
    """
    admin_user, error_msg = get_admin_user_from_token()
    if not admin_user:
        return error_response(error_msg, 401, "UNAUTHORIZED")

    # 验证请求数据
    is_valid, data, errors = validate_request_json(AdminUserStatusUpdateSchema())
    if not is_valid:
        return validation_error_response(errors)

    new_status = data['status']

    try:
        user_storage = get_user_storage()
        user = user_storage.get_user_by_id(user_id)

        if not user:
            return error_response("用户不存在", 404, "USER_NOT_FOUND")

        # 防止管理员禁用自己
        if user.id == admin_user.id:
            return error_response("不能修改自己的状态", 400, "CANNOT_MODIFY_SELF")

        old_status = user.status
        user.update_info(status=new_status)
        success = user_storage.update_user(user)

        if success:
            # 如果用户被禁用，撤销其所有Token
            if new_status == 'disabled':
                revoke_all_user_tokens(user.id, f'disabled_by_{admin_user.username}')

            logger.info(f"用户状态更新成功: {user.username} {old_status} -> {new_status} (操作者: {admin_user.username})")
            return success_response("用户状态更新成功", user.to_public_dict())
        else:
            return error_response("用户状态更新失败", 500, "UPDATE_FAILED")

    except Exception as e:
        logger.error(f"更新用户状态失败: {e}")
        return error_response("更新用户状态失败", 500, "STATUS_UPDATE_ERROR")


@admin_bp.route('/users/<int:user_id>', methods=['DELETE'])
def delete_user(user_id):
    """
    删除用户

    请求头:
    Authorization: Bearer <token>
    """
    admin_user, error_msg = get_admin_user_from_token()
    if not admin_user:
        return error_response(error_msg, 401, "UNAUTHORIZED")

    try:
        user_storage = get_user_storage()
        user = user_storage.get_user_by_id(user_id)

        if not user:
            return error_response("用户不存在", 404, "USER_NOT_FOUND")

        # 防止管理员删除自己
        if user.id == admin_user.id:
            return error_response("不能删除自己", 400, "CANNOT_DELETE_SELF")

        # 撤销用户的所有Token
        revoke_all_user_tokens(user.id, f'deleted_by_{admin_user.username}')

        # 删除用户
        success = user_storage.delete_user(user_id)

        if success:
            logger.info(f"用户删除成功: {user.username} (操作者: {admin_user.username})")
            return success_response("用户删除成功")
        else:
            return error_response("用户删除失败", 500, "DELETE_FAILED")

    except Exception as e:
        logger.error(f"删除用户失败: {e}")
        return error_response("删除用户失败", 500, "DELETE_ERROR")


@admin_bp.route('/stats', methods=['GET'])
def get_system_stats():
    """
    获取系统统计信息

    请求头:
    Authorization: Bearer <token>
    """
    admin_user, error_msg = get_admin_user_from_token()
    if not admin_user:
        return error_response(error_msg, 401, "UNAUTHORIZED")

    try:
        storage_manager = get_storage_manager()
        stats = storage_manager.get_system_statistics()

        return success_response("获取系统统计成功", stats)

    except Exception as e:
        logger.error(f"获取系统统计失败: {e}")
        return error_response("获取系统统计失败", 500, "STATS_ERROR")


@admin_bp.route('/logs', methods=['GET'])
def get_system_logs():
    """
    获取系统日志

    请求头:
    Authorization: Bearer <token>

    查询参数:
    - hours: 最近几小时的日志，默认24
    - limit: 返回记录数量限制，默认100
    """
    admin_user, error_msg = get_admin_user_from_token()
    if not admin_user:
        return error_response(error_msg, 401, "UNAUTHORIZED")

    try:
        # 获取查询参数
        hours = request.args.get('hours', '24')
        limit = request.args.get('limit', '100')

        try:
            hours = int(hours)
            if hours > 168:  # 最多一周
                hours = 168
        except ValueError:
            hours = 24

        try:
            limit = int(limit)
            if limit > 1000:
                limit = 1000
        except ValueError:
            limit = 100

        # 获取日志
        log_storage = get_log_storage()
        logs = log_storage.get_recent_logs(hours=hours, limit=limit)

        # 转换为字典格式
        log_data = [log.to_dict() for log in logs]

        return success_response("获取系统日志成功", {
            'logs': log_data,
            'total': len(log_data),
            'hours': hours
        })

    except Exception as e:
        logger.error(f"获取系统日志失败: {e}")
        return error_response("获取系统日志失败", 500, "LOGS_ERROR")


@admin_bp.route('/cleanup', methods=['POST'])
def cleanup_data():
    """
    清理旧数据

    请求头:
    Authorization: Bearer <token>

    请求体:
    {
        "days_to_keep": 30  // 可选，默认30天
    }
    """
    admin_user, error_msg = get_admin_user_from_token()
    if not admin_user:
        return error_response(error_msg, 401, "UNAUTHORIZED")

    try:
        # 获取保留天数
        days_to_keep = 30
        if request.is_json:
            json_data = request.get_json() or {}
            days_to_keep = json_data.get('days_to_keep', 30)

        storage_manager = get_storage_manager()
        results = storage_manager.cleanup_old_data(days_to_keep)

        logger.info(f"数据清理完成 (操作者: {admin_user.username}): {results}")
        return success_response("数据清理完成", results)

    except Exception as e:
        logger.error(f"数据清理失败: {e}")
        return error_response("数据清理失败", 500, "CLEANUP_ERROR")