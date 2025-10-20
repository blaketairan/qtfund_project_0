#!/usr/bin/env python3
"""
QTFund 认证服务数据初始化脚本
创建必要的数据文件和默认管理员账户
"""
import os
import sys
import json
import bcrypt
from datetime import datetime
from pathlib import Path

# 添加项目根目录到路径
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from config.settings import get_config


def create_directories(config):
    """创建必要的目录"""
    directories = [
        config.DATA_DIR,
        config.BACKUP_DIR,
        config.LOG_DIR
    ]

    for directory in directories:
        Path(directory).mkdir(parents=True, exist_ok=True)
        print(f"✓ 目录已创建: {directory}")


def create_users_file(config):
    """创建用户数据文件"""
    file_path = config.users_file_path

    if file_path.exists():
        print(f"⚠ 用户数据文件已存在: {file_path}")
        return

    # 创建默认管理员
    password_hash = bcrypt.hashpw('admin123'.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    current_time = datetime.utcnow().isoformat() + 'Z'

    users_data = {
        'users': {
            '1': {
                'id': 1,
                'username': 'admin',
                'password_hash': password_hash,
                'email': 'admin@qtfund.local',
                'real_name': '系统管理员',
                'role': 'admin',
                'status': 'active',
                'created_at': current_time,
                'updated_at': current_time,
                'last_login': None,
                'login_count': 0
            }
        },
        'next_id': 2,
        'metadata': {
            'version': '1.0',
            'created_at': current_time,
            'last_updated': current_time,
            'user_count': 1
        }
    }

    with open(file_path, 'w', encoding='utf-8') as f:
        json.dump(users_data, f, indent=2, ensure_ascii=False)

    # 设置文件权限
    os.chmod(file_path, 0o600)

    print(f"✓ 用户数据文件已创建: {file_path}")
    print("  默认管理员账号: admin / admin123")


def create_login_logs_file(config):
    """创建登录日志文件"""
    file_path = config.login_logs_file_path

    if file_path.exists():
        print(f"⚠ 登录日志文件已存在: {file_path}")
        return

    logs_data = {
        'logs': [],
        'next_id': 1,
        'metadata': {
            'version': '1.0',
            'created_at': datetime.utcnow().isoformat() + 'Z',
            'last_updated': datetime.utcnow().isoformat() + 'Z',
            'log_count': 0
        }
    }

    with open(file_path, 'w', encoding='utf-8') as f:
        json.dump(logs_data, f, indent=2, ensure_ascii=False)

    os.chmod(file_path, 0o600)
    print(f"✓ 登录日志文件已创建: {file_path}")


def create_permissions_file(config):
    """创建权限配置文件"""
    file_path = config.permissions_file_path

    if file_path.exists():
        print(f"⚠ 权限配置文件已存在: {file_path}")
        return

    current_time = datetime.utcnow().isoformat() + 'Z'

    # 默认权限规则
    default_permissions = [
        {
            'id': 1,
            'path_pattern': '/api/v1/admin/*',
            'method': 'ANY',
            'required_role': 'admin',
            'description': '管理员接口，仅管理员可访问',
            'enabled': True,
            'created_at': current_time,
            'updated_at': current_time
        },
        {
            'id': 2,
            'path_pattern': '/api/v1/user/*',
            'method': 'ANY',
            'required_role': 'user',
            'description': '用户接口，普通用户及以上可访问',
            'enabled': True,
            'created_at': current_time,
            'updated_at': current_time
        },
        {
            'id': 3,
            'path_pattern': '/api/v1/auth/login',
            'method': 'POST',
            'required_role': 'any',
            'description': '登录接口，公开访问',
            'enabled': True,
            'created_at': current_time,
            'updated_at': current_time
        },
        {
            'id': 4,
            'path_pattern': '/api/v1/auth/register',
            'method': 'POST',
            'required_role': 'any',
            'description': '注册接口，公开访问',
            'enabled': True,
            'created_at': current_time,
            'updated_at': current_time
        },
        {
            'id': 5,
            'path_pattern': '/api/v1/auth/validate',
            'method': 'ANY',
            'required_role': 'readonly',
            'description': 'Nginx认证验证接口',
            'enabled': True,
            'created_at': current_time,
            'updated_at': current_time
        },
        {
            'id': 6,
            'path_pattern': '/health',
            'method': 'GET',
            'required_role': 'any',
            'description': '健康检查接口，公开访问',
            'enabled': True,
            'created_at': current_time,
            'updated_at': current_time
        }
    ]

    permissions_data = {
        'permissions': default_permissions,
        'next_id': 7,
        'metadata': {
            'version': '1.0',
            'created_at': current_time,
            'last_updated': current_time,
            'permission_count': len(default_permissions)
        }
    }

    with open(file_path, 'w', encoding='utf-8') as f:
        json.dump(permissions_data, f, indent=2, ensure_ascii=False)

    os.chmod(file_path, 0o600)
    print(f"✓ 权限配置文件已创建: {file_path}")
    print(f"  已配置 {len(default_permissions)} 条默认权限规则")


def create_token_blacklist_file(config):
    """创建Token黑名单文件"""
    file_path = config.token_blacklist_file_path

    if file_path.exists():
        print(f"⚠ Token黑名单文件已存在: {file_path}")
        return

    blacklist_data = {
        'blacklist': [],
        'next_id': 1,
        'metadata': {
            'version': '1.0',
            'created_at': datetime.utcnow().isoformat() + 'Z',
            'last_updated': datetime.utcnow().isoformat() + 'Z',
            'item_count': 0
        }
    }

    with open(file_path, 'w', encoding='utf-8') as f:
        json.dump(blacklist_data, f, indent=2, ensure_ascii=False)

    os.chmod(file_path, 0o600)
    print(f"✓ Token黑名单文件已创建: {file_path}")


def create_admin_user(config, username=None, password=None, email=None):
    """创建额外的管理员用户"""
    if not username:
        username = input("请输入管理员用户名: ").strip()
    if not password:
        password = input("请输入管理员密码: ").strip()
    if not email:
        email = input("请输入管理员邮箱 (可选): ").strip() or None

    if not username or not password:
        print("❌ 用户名和密码不能为空")
        return False

    file_path = config.users_file_path
    if not file_path.exists():
        print("❌ 用户数据文件不存在，请先运行基本初始化")
        return False

    try:
        # 读取现有数据
        with open(file_path, 'r', encoding='utf-8') as f:
            users_data = json.load(f)

        # 检查用户名是否已存在
        for user_data in users_data['users'].values():
            if user_data['username'] == username:
                print(f"❌ 用户名 {username} 已存在")
                return False

        # 创建新管理员
        user_id = users_data['next_id']
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        current_time = datetime.utcnow().isoformat() + 'Z'

        new_user = {
            'id': user_id,
            'username': username,
            'password_hash': password_hash,
            'email': email,
            'real_name': f'管理员-{username}',
            'role': 'admin',
            'status': 'active',
            'created_at': current_time,
            'updated_at': current_time,
            'last_login': None,
            'login_count': 0
        }

        # 更新数据
        users_data['users'][str(user_id)] = new_user
        users_data['next_id'] = user_id + 1
        users_data['metadata']['user_count'] = len(users_data['users'])
        users_data['metadata']['last_updated'] = current_time

        # 写入文件
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(users_data, f, indent=2, ensure_ascii=False)

        print(f"✓ 管理员用户已创建: {username}")
        return True

    except Exception as e:
        print(f"❌ 创建管理员失败: {e}")
        return False


def show_status(config):
    """显示初始化状态"""
    print("\n=== QTFund 认证服务状态 ===")

    files_to_check = [
        ('用户数据', config.users_file_path),
        ('登录日志', config.login_logs_file_path),
        ('权限配置', config.permissions_file_path),
        ('Token黑名单', config.token_blacklist_file_path)
    ]

    all_exist = True
    for name, file_path in files_to_check:
        if file_path.exists():
            size = file_path.stat().st_size
            print(f"✓ {name}: {file_path} ({size} bytes)")
        else:
            print(f"❌ {name}: {file_path} (不存在)")
            all_exist = False

    if all_exist:
        print("\n🎉 所有数据文件已就绪，服务可以启动！")
    else:
        print("\n⚠ 部分数据文件缺失，请运行初始化命令")

    # 显示用户统计
    if config.users_file_path.exists():
        try:
            with open(config.users_file_path, 'r', encoding='utf-8') as f:
                users_data = json.load(f)
            user_count = len(users_data.get('users', {}))
            admin_count = sum(1 for u in users_data.get('users', {}).values() if u.get('role') == 'admin')
            print(f"\n📊 用户统计: 总用户数 {user_count}, 管理员数 {admin_count}")
        except Exception as e:
            print(f"⚠ 读取用户统计失败: {e}")


def main():
    """主函数"""
    import argparse

    parser = argparse.ArgumentParser(description='QTFund 认证服务数据初始化')
    parser.add_argument('command', nargs='?', choices=['init', 'status', 'create-admin'],
                        default='status', help='执行的命令')
    parser.add_argument('--username', help='管理员用户名')
    parser.add_argument('--password', help='管理员密码')
    parser.add_argument('--email', help='管理员邮箱')
    parser.add_argument('--force', action='store_true', help='强制覆盖现有文件')

    args = parser.parse_args()

    # 获取配置
    config = get_config()

    print(f"数据目录: {config.DATA_DIR}")
    print(f"备份目录: {config.BACKUP_DIR}")
    print(f"日志目录: {config.LOG_DIR}")
    print("-" * 50)

    if args.command == 'init':
        print("开始初始化数据...")
        create_directories(config)
        create_users_file(config)
        create_login_logs_file(config)
        create_permissions_file(config)
        create_token_blacklist_file(config)
        print("\n✅ 初始化完成！")
        show_status(config)

    elif args.command == 'create-admin':
        print("创建新管理员用户...")
        create_admin_user(config, args.username, args.password, args.email)

    else:  # status
        show_status(config)

    print("\n" + "=" * 50)
    print("启动服务命令: python run.py")
    print("默认管理员: admin / admin123")
    print("服务端口: 9000")


if __name__ == '__main__':
    main()