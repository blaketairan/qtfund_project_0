"""
统一响应格式工具
提供标准化的API响应格式
"""
from flask import jsonify
from typing import Any, Dict, Optional


def success_response(
    message: str = "操作成功",
    data: Any = None,
    code: int = 200
) -> tuple:
    """
    成功响应

    Args:
        message: 响应消息
        data: 响应数据
        code: HTTP状态码

    Returns:
        tuple: (响应数据, HTTP状态码)
    """
    response = {
        'code': code,
        'message': message,
        'success': True
    }

    if data is not None:
        response['data'] = data

    return jsonify(response), code


def error_response(
    message: str = "操作失败",
    code: int = 400,
    error_code: str = "ERROR",
    details: Optional[Dict] = None
) -> tuple:
    """
    错误响应

    Args:
        message: 错误消息
        code: HTTP状态码
        error_code: 错误代码
        details: 错误详情

    Returns:
        tuple: (响应数据, HTTP状态码)
    """
    response = {
        'code': code,
        'message': message,
        'success': False,
        'error': error_code
    }

    if details:
        response['details'] = details

    return jsonify(response), code


def validation_error_response(errors: Dict) -> tuple:
    """
    验证错误响应

    Args:
        errors: 验证错误字典

    Returns:
        tuple: (响应数据, HTTP状态码)
    """
    return error_response(
        message="输入参数验证失败",
        code=400,
        error_code="VALIDATION_ERROR",
        details=errors
    )


def paginated_response(
    data: list,
    page: int,
    size: int,
    total: int,
    message: str = "查询成功"
) -> tuple:
    """
    分页响应

    Args:
        data: 数据列表
        page: 当前页码
        size: 每页大小
        total: 总记录数
        message: 响应消息

    Returns:
        tuple: (响应数据, HTTP状态码)
    """
    total_pages = (total + size - 1) // size

    response_data = {
        'items': data,
        'pagination': {
            'page': page,
            'size': size,
            'total': total,
            'total_pages': total_pages,
            'has_next': page < total_pages,
            'has_prev': page > 1
        }
    }

    return success_response(message, response_data)