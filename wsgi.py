"""
QTFund 认证服务 WSGI 入口
用于生产环境部署
"""
import os
import sys
from pathlib import Path

# 添加项目根目录到Python路径
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from app import create_app
from app.storage.manager import init_storage_manager

# 创建应用实例
app = create_app()

# 初始化存储系统
with app.app_context():
    init_storage_manager(app.config)

# WSGI应用对象
application = app

if __name__ == "__main__":
    # 如果直接运行此文件，启动开发服务器
    app.run(
        host=app.config.get('SERVER_HOST', '0.0.0.0'),
        port=app.config.get('SERVER_PORT', 9000),
        debug=False
    )