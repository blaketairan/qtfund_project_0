#!/usr/bin/env python3
"""
QTFund 用户管理脚本
用法：
  python manage_users.py add <username> <password>   # 添加用户
  python manage_users.py delete <username>           # 删除用户
  python manage_users.py list                        # 列出所有用户
  python manage_users.py passwd <username> <new_password>  # 修改密码
"""

import sys
import json
import bcrypt
from datetime import datetime
import os

USERS_FILE = 'data/users.json'

def load_users():
    """加载用户数据"""
    try:
        with open(USERS_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        return {
            "users": {},
            "next_id": 1,
            "version": "1.0",
            "last_updated": datetime.utcnow().isoformat() + 'Z'
        }

def save_users(users_data):
    """保存用户数据"""
    users_data['last_updated'] = datetime.utcnow().isoformat() + 'Z'

    # 创建目录如果不存在
    os.makedirs(os.path.dirname(USERS_FILE), exist_ok=True)

    with open(USERS_FILE, 'w', encoding='utf-8') as f:
        json.dump(users_data, f, indent=2, ensure_ascii=False)

def hash_password(password):
    """生成密码哈希"""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def find_user_by_username(users_data, username):
    """根据用户名查找用户"""
    for user_id, user in users_data['users'].items():
        if user['username'] == username:
            return user_id, user
    return None, None

def add_user(username, password, role='user'):
    """添加用户"""
    users_data = load_users()

    # 检查用户名是否已存在
    existing_id, existing_user = find_user_by_username(users_data, username)
    if existing_user:
        print(f"❌ 错误: 用户名 '{username}' 已存在")
        return False

    # 创建新用户
    user_id = users_data['next_id']
    password_hash = hash_password(password)

    new_user = {
        'id': user_id,
        'username': username,
        'password_hash': password_hash,
        'email': f'{username}@qtfund.local',
        'real_name': username,
        'role': role,
        'status': 'active',
        'created_at': datetime.utcnow().isoformat() + 'Z',
        'updated_at': datetime.utcnow().isoformat() + 'Z',
        'login_count': 0
    }

    users_data['users'][str(user_id)] = new_user
    users_data['next_id'] = user_id + 1

    save_users(users_data)
    print(f"✅ 用户 '{username}' 添加成功")
    print(f"   用户ID: {user_id}")
    print(f"   角色: {role}")
    print(f"   邮箱: {new_user['email']}")
    return True

def delete_user(username):
    """删除用户"""
    users_data = load_users()

    # 查找用户
    user_id, user = find_user_by_username(users_data, username)
    if not user:
        print(f"❌ 错误: 用户 '{username}' 不存在")
        return False

    # 不允许删除admin用户
    if user['role'] == 'admin' and len([u for u in users_data['users'].values() if u['role'] == 'admin']) <= 1:
        print(f"❌ 错误: 不能删除最后一个管理员用户")
        return False

    # 删除用户
    del users_data['users'][user_id]
    save_users(users_data)

    print(f"✅ 用户 '{username}' 删除成功")
    return True

def change_password(username, new_password):
    """修改用户密码"""
    users_data = load_users()

    # 查找用户
    user_id, user = find_user_by_username(users_data, username)
    if not user:
        print(f"❌ 错误: 用户 '{username}' 不存在")
        return False

    # 更新密码
    users_data['users'][user_id]['password_hash'] = hash_password(new_password)
    users_data['users'][user_id]['updated_at'] = datetime.utcnow().isoformat() + 'Z'

    save_users(users_data)
    print(f"✅ 用户 '{username}' 密码修改成功")
    return True

def list_users():
    """列出所有用户"""
    users_data = load_users()

    if not users_data['users']:
        print("📝 没有用户")
        return

    print("📝 用户列表:")
    print("-" * 70)
    print(f"{'ID':<4} {'用户名':<15} {'角色':<8} {'状态':<8} {'真实姓名':<15} {'邮箱'}")
    print("-" * 70)

    for user in users_data['users'].values():
        print(f"{user['id']:<4} {user['username']:<15} {user['role']:<8} {user['status']:<8} {user['real_name']:<15} {user['email']}")

    print("-" * 70)
    print(f"总计: {len(users_data['users'])} 个用户")

def show_help():
    """显示帮助信息"""
    print(__doc__)

def main():
    """主函数"""
    if len(sys.argv) < 2:
        show_help()
        return

    command = sys.argv[1].lower()

    if command == 'add':
        if len(sys.argv) != 4:
            print("❌ 用法: python manage_users.py add <username> <password>")
            return
        username, password = sys.argv[2], sys.argv[3]

        # 如果用户名是admin，设置为admin角色
        role = 'admin' if username == 'admin' else 'user'
        add_user(username, password, role)

    elif command == 'delete':
        if len(sys.argv) != 3:
            print("❌ 用法: python manage_users.py delete <username>")
            return
        username = sys.argv[2]
        delete_user(username)

    elif command == 'passwd':
        if len(sys.argv) != 4:
            print("❌ 用法: python manage_users.py passwd <username> <new_password>")
            return
        username, new_password = sys.argv[2], sys.argv[3]
        change_password(username, new_password)

    elif command == 'list':
        list_users()

    else:
        print(f"❌ 未知命令: {command}")
        show_help()

if __name__ == '__main__':
    main()