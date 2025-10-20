#!/usr/bin/env python3
"""
简化版认证服务启动脚本
"""
import os
import sys
import json
from flask import Flask, request, jsonify
from flask_cors import CORS
import jwt
import bcrypt
from datetime import datetime, timedelta

# 创建Flask应用
app = Flask(__name__)
app.config['SECRET_KEY'] = 'dev-secret-key-for-testing'
CORS(app)

# 数据目录
DATA_DIR = 'data'

def load_users():
    """加载用户数据"""
    try:
        with open(f'{DATA_DIR}/users.json', 'r') as f:
            return json.load(f)
    except:
        return {'users': {}, 'next_id': 1}

def save_users(users_data):
    """保存用户数据"""
    with open(f'{DATA_DIR}/users.json', 'w') as f:
        json.dump(users_data, f, indent=2, ensure_ascii=False)

@app.route('/health')
def health():
    """健康检查"""
    return {'status': 'healthy', 'service': 'qtfund-auth', 'version': '1.0.0'}

@app.route('/api/v1/auth/login', methods=['POST'])
def login():
    """用户登录"""
    data = request.get_json()
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({'error': 'Missing username or password'}), 400

    username = data['username']
    password = data['password']
    use_cookie = data.get('use_cookie', False)  # 是否使用Cookie方式

    # 加载用户数据
    users_data = load_users()

    # 查找用户
    user = None
    for uid, u in users_data['users'].items():
        if u['username'] == username:
            user = u
            break

    if not user:
        return jsonify({'error': 'Invalid credentials'}), 401

    # 验证密码
    if not bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
        return jsonify({'error': 'Invalid credentials'}), 401

    # 生成JWT token
    payload = {
        'user_id': user['id'],
        'username': user['username'],
        'role': user['role'],
        'exp': datetime.utcnow() + timedelta(hours=1)  # 1小时有效期
    }

    token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')
    print(f"DEBUG: Generated token for {username}, expires at {payload['exp']}")

    response_data = {
        'code': 200,
        'message': '登录成功',
        'data': {
            'token': token,
            'user': {
                'id': user['id'],
                'username': user['username'],
                'role': user['role'],
                'real_name': user.get('real_name', '')
            }
        }
    }

    response = jsonify(response_data)

    # 如果请求使用Cookie方式，设置HttpOnly Cookie
    if use_cookie:
        response.set_cookie(
            'token',
            token,
            max_age=3600,  # 1小时
            secure=True,   # 仅HTTPS
            httponly=True, # 防止XSS
            samesite='Strict'  # 防止CSRF
        )
        print(f"DEBUG: Set token in HttpOnly cookie for {username}")

    return response

@app.route('/api/v1/auth/logout', methods=['POST'])
def logout():
    """用户登出 - 清除Cookie"""
    response = jsonify({
        'code': 200,
        'message': '登出成功',
        'data': {}
    })

    # 清除token cookie
    response.set_cookie(
        'token',
        '',
        max_age=0,  # 立即过期
        secure=True,
        httponly=True,
        samesite='Strict'
    )

    print("DEBUG: Token cookie cleared")
    return response

@app.route('/api/v1/auth/validate', methods=['GET', 'POST', 'PUT', 'DELETE'])
def validate():
    """Token验证 - 供nginx auth_request使用 (支持Authorization头和Cookie)"""
    token = None

    # 方式1: 从Authorization头获取token
    auth_header = request.headers.get('Authorization')
    if auth_header and auth_header.startswith('Bearer '):
        token = auth_header[7:]
        print(f"DEBUG: Token from Authorization header: {token[:20]}...")

    # 方式2: 从Cookie获取token
    if not token:
        token = request.cookies.get('token')
        if token:
            print(f"DEBUG: Token from Cookie: {token[:20]}...")

    # 如果都没有token，返回401
    if not token:
        print("DEBUG: No token found in Authorization header or Cookie")
        return '', 401

    try:
        # 验证token
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        print(f"DEBUG: Token validated successfully for user {payload.get('username')}")

        # 设置响应头供nginx使用
        response = app.make_response('')
        response.status_code = 200
        response.headers['X-User-ID'] = str(payload.get('user_id'))
        response.headers['X-User-Role'] = payload.get('role', 'user')
        response.headers['X-User-Name'] = payload.get('username', '')

        return response

    except jwt.ExpiredSignatureError as e:
        print(f"DEBUG: Token expired: {e}")
        return '', 401
    except jwt.InvalidTokenError as e:
        print(f"DEBUG: Invalid token: {e}")
        return '', 401
    except Exception as e:
        print(f"DEBUG: Validation error: {e}")
        return '', 401

if __name__ == '__main__':
    print("🚀 启动简化版 QTFund 认证服务...")
    print("📡 服务地址: http://localhost:9000")
    print("👤 管理员账号: admin/admin123")
    print("-" * 40)

    app.run(host='0.0.0.0', port=9000, debug=True)