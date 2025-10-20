"""
输入验证器
提供API输入参数的验证功能
"""
import re
from typing import Dict, Any, List, Optional, Tuple
from marshmallow import Schema, fields, ValidationError, validates, validates_schema
from flask import request
from email_validator import validate_email, EmailNotValidError


class UserRegistrationSchema(Schema):
    """用户注册验证模式"""
    username = fields.Str(required=True, validate=[
        fields.Length(min=3, max=20, error="用户名长度必须在3-20个字符之间"),
    ])
    password = fields.Str(required=True, validate=[
        fields.Length(min=8, max=50, error="密码长度必须在8-50个字符之间"),
    ])
    email = fields.Email(required=False, allow_none=True, error="邮箱格式无效")
    real_name = fields.Str(required=False, allow_none=True, validate=[
        fields.Length(max=50, error="真实姓名长度不能超过50个字符")
    ])

    @validates('username')
    def validate_username(self, value):
        """验证用户名格式"""
        if not re.match(r'^[a-zA-Z0-9_]+$', value):
            raise ValidationError("用户名只能包含字母、数字和下划线")

    @validates('password')
    def validate_password(self, value):
        """验证密码强度"""
        if not re.search(r'[a-zA-Z]', value):
            raise ValidationError("密码必须包含至少一个字母")
        if not re.search(r'[0-9]', value):
            raise ValidationError("密码必须包含至少一个数字")


class UserLoginSchema(Schema):
    """用户登录验证模式"""
    username = fields.Str(required=True, validate=[
        fields.Length(min=1, max=50, error="用户名不能为空且长度不能超过50个字符")
    ])
    password = fields.Str(required=True, validate=[
        fields.Length(min=1, error="密码不能为空")
    ])


class UserProfileUpdateSchema(Schema):
    """用户信息更新验证模式"""
    email = fields.Email(required=False, allow_none=True, error="邮箱格式无效")
    real_name = fields.Str(required=False, allow_none=True, validate=[
        fields.Length(max=50, error="真实姓名长度不能超过50个字符")
    ])


class PasswordChangeSchema(Schema):
    """密码修改验证模式"""
    old_password = fields.Str(required=True, validate=[
        fields.Length(min=1, error="当前密码不能为空")
    ])
    new_password = fields.Str(required=True, validate=[
        fields.Length(min=8, max=50, error="新密码长度必须在8-50个字符之间")
    ])

    @validates('new_password')
    def validate_new_password(self, value):
        """验证新密码强度"""
        if not re.search(r'[a-zA-Z]', value):
            raise ValidationError("新密码必须包含至少一个字母")
        if not re.search(r'[0-9]', value):
            raise ValidationError("新密码必须包含至少一个数字")

    @validates_schema
    def validate_passwords_different(self, data, **kwargs):
        """验证新旧密码不同"""
        if data.get('old_password') == data.get('new_password'):
            raise ValidationError("新密码不能与当前密码相同")


class AdminUserRoleUpdateSchema(Schema):
    """管理员用户角色更新验证模式"""
    role = fields.Str(required=True, validate=[
        fields.OneOf(['admin', 'user', 'readonly'], error="角色必须是admin、user或readonly之一")
    ])


class AdminUserStatusUpdateSchema(Schema):
    """管理员用户状态更新验证模式"""
    status = fields.Str(required=True, validate=[
        fields.OneOf(['active', 'disabled'], error="状态必须是active或disabled之一")
    ])


class PermissionCreateSchema(Schema):
    """权限规则创建验证模式"""
    path_pattern = fields.Str(required=True, validate=[
        fields.Length(min=1, max=200, error="路径模式长度必须在1-200个字符之间")
    ])
    method = fields.Str(required=True, validate=[
        fields.OneOf(['GET', 'POST', 'PUT', 'DELETE', 'ANY'], error="方法必须是GET、POST、PUT、DELETE或ANY之一")
    ])
    required_role = fields.Str(required=True, validate=[
        fields.OneOf(['admin', 'user', 'readonly', 'any'], error="所需角色必须是admin、user、readonly或any之一")
    ])
    description = fields.Str(required=False, allow_none=True, validate=[
        fields.Length(max=500, error="描述长度不能超过500个字符")
    ])


class PaginationSchema(Schema):
    """分页参数验证模式"""
    page = fields.Int(required=False, missing=1, validate=[
        fields.Range(min=1, error="页码必须大于0")
    ])
    size = fields.Int(required=False, missing=10, validate=[
        fields.Range(min=1, max=100, error="每页大小必须在1-100之间")
    ])


def validate_request_json(schema: Schema) -> Tuple[bool, Dict[str, Any], Dict[str, List[str]]]:
    """
    验证请求的JSON数据

    Args:
        schema: Marshmallow验证模式

    Returns:
        Tuple[bool, Dict, Dict]: (是否有效, 验证后的数据, 错误信息)
    """
    try:
        # 检查Content-Type
        if not request.is_json:
            return False, {}, {'_error': ['请求必须使用JSON格式']}

        # 获取JSON数据
        json_data = request.get_json()
        if json_data is None:
            return False, {}, {'_error': ['请求体不能为空']}

        # 验证数据
        validated_data = schema.load(json_data)
        return True, validated_data, {}

    except ValidationError as e:
        return False, {}, e.messages
    except Exception as e:
        return False, {}, {'_error': [f'数据解析失败: {str(e)}']}


def validate_query_params(schema: Schema) -> Tuple[bool, Dict[str, Any], Dict[str, List[str]]]:
    """
    验证查询参数

    Args:
        schema: Marshmallow验证模式

    Returns:
        Tuple[bool, Dict, Dict]: (是否有效, 验证后的数据, 错误信息)
    """
    try:
        # 获取查询参数
        query_data = request.args.to_dict()

        # 验证数据
        validated_data = schema.load(query_data)
        return True, validated_data, {}

    except ValidationError as e:
        return False, {}, e.messages
    except Exception as e:
        return False, {}, {'_error': [f'参数解析失败: {str(e)}']}


def validate_username_format(username: str) -> bool:
    """
    验证用户名格式

    Args:
        username: 用户名

    Returns:
        bool: 是否有效
    """
    if not username or len(username) < 3 or len(username) > 20:
        return False
    return re.match(r'^[a-zA-Z0-9_]+$', username) is not None


def validate_password_strength(password: str) -> Tuple[bool, List[str]]:
    """
    验证密码强度

    Args:
        password: 密码

    Returns:
        Tuple[bool, List[str]]: (是否有效, 错误信息列表)
    """
    errors = []

    if not password:
        errors.append("密码不能为空")
        return False, errors

    if len(password) < 8:
        errors.append("密码长度不能少于8个字符")

    if len(password) > 50:
        errors.append("密码长度不能超过50个字符")

    if not re.search(r'[a-zA-Z]', password):
        errors.append("密码必须包含至少一个字母")

    if not re.search(r'[0-9]', password):
        errors.append("密码必须包含至少一个数字")

    # 可选的额外强度检查
    # if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
    #     errors.append("密码建议包含特殊字符")

    return len(errors) == 0, errors


def validate_email_format(email: str) -> Tuple[bool, str]:
    """
    验证邮箱格式

    Args:
        email: 邮箱地址

    Returns:
        Tuple[bool, str]: (是否有效, 标准化的邮箱地址或错误信息)
    """
    if not email:
        return True, ""  # 邮箱可选

    try:
        # 使用email-validator库验证
        validated = validate_email(email)
        return True, validated.email
    except EmailNotValidError as e:
        return False, str(e)


def validate_ip_address(ip: str) -> bool:
    """
    验证IP地址格式

    Args:
        ip: IP地址字符串

    Returns:
        bool: 是否有效
    """
    if not ip:
        return False

    # IPv4格式验证
    ipv4_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    if re.match(ipv4_pattern, ip):
        return True

    # IPv6格式验证（简化版）
    ipv6_pattern = r'^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$'
    if re.match(ipv6_pattern, ip):
        return True

    return False


def sanitize_input(text: str, max_length: int = None) -> str:
    """
    清理输入文本

    Args:
        text: 输入文本
        max_length: 最大长度限制

    Returns:
        str: 清理后的文本
    """
    if not text:
        return ""

    # 去除首尾空白
    text = text.strip()

    # 长度限制
    if max_length and len(text) > max_length:
        text = text[:max_length]

    # 移除潜在的危险字符（可根据需要调整）
    # text = re.sub(r'[<>"\']', '', text)

    return text


class ValidationUtils:
    """验证工具类"""

    @staticmethod
    def is_valid_role(role: str) -> bool:
        """检查角色是否有效"""
        return role in ['admin', 'user', 'readonly']

    @staticmethod
    def is_valid_status(status: str) -> bool:
        """检查状态是否有效"""
        return status in ['active', 'disabled']

    @staticmethod
    def is_valid_http_method(method: str) -> bool:
        """检查HTTP方法是否有效"""
        return method.upper() in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD', 'ANY']

    @staticmethod
    def validate_path_pattern(pattern: str) -> Tuple[bool, str]:
        """
        验证路径模式

        Args:
            pattern: 路径模式

        Returns:
            Tuple[bool, str]: (是否有效, 错误信息)
        """
        if not pattern:
            return False, "路径模式不能为空"

        if len(pattern) > 200:
            return False, "路径模式长度不能超过200个字符"

        # 检查是否是有效的路径格式
        if not pattern.startswith('/'):
            return False, "路径模式必须以/开头"

        return True, ""