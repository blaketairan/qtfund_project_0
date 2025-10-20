#!/usr/bin/env python3
"""
QTFund 认证服务开发环境启动脚本
"""
import os
import sys
from pathlib import Path

# 添加项目根目录到Python路径
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from app import create_app
from app.storage.manager import init_storage_manager


def main():
    """主函数"""
    print("🚀 启动 QTFund 认证服务...")

    # 创建Flask应用
    app = create_app()

    # 在应用上下文中初始化存储
    with app.app_context():
        init_storage_manager(app.config)
        print("✅ 存储系统初始化完成")

    # 显示服务信息
    host = app.config.get('SERVER_HOST', '0.0.0.0')
    port = app.config.get('SERVER_PORT', 9000)
    debug = app.config.get('DEBUG', False)

    print(f"📡 服务地址: http://{host}:{port}")
    print(f"🔧 调试模式: {'开启' if debug else '关闭'}")
    print(f"📁 数据目录: {app.config.get('DATA_DIR')}")
    print("-" * 50)

    try:
        # 启动开发服务器
        app.run(
            host=host,
            port=port,
            debug=debug,
            use_reloader=debug,
            threaded=True
        )
    except KeyboardInterrupt:
        print("\n👋 服务已停止")
    except Exception as e:
        print(f"❌ 服务启动失败: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()