"""
QTFund 认证服务 Flask 应用工厂
"""
import logging
from flask import Flask
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from config.settings import get_config


def create_app(config_name=None):
    """
    Flask 应用工厂函数

    Args:
        config_name: 配置名称，如果为None则从环境变量读取

    Returns:
        Flask: 配置好的Flask应用实例
    """
    app = Flask(__name__)

    # 加载配置
    if config_name:
        from config.settings import config_map
        config_class = config_map.get(config_name, get_config())
    else:
        config_class = get_config()

    app.config.from_object(config_class)

    # 初始化目录
    config_class.init_directories()

    # 配置日志
    setup_logging(app)

    # 初始化扩展
    CORS(app, origins=app.config['CORS_ORIGINS'])

    # 配置限流器
    if app.config.get('RATE_LIMIT_ENABLED', True):
        limiter = Limiter(
            app,
            key_func=get_remote_address,
            default_limits=[app.config.get('RATE_LIMIT_DEFAULT', '100/hour')]
        )
        app.limiter = limiter
    else:
        app.limiter = None

    # 注册蓝图
    register_blueprints(app)

    # 注册错误处理器
    register_error_handlers(app)

    # 注册应用上下文处理器
    register_context_processors(app)

    app.logger.info(f"QTFund Auth Service initialized with config: {config_class.__name__}")

    return app


def setup_logging(app):
    """配置应用日志"""
    if not app.debug:
        # 生产环境配置文件日志
        import os
        from logging.handlers import RotatingFileHandler

        log_dir = app.config['LOG_DIR']
        os.makedirs(log_dir, exist_ok=True)

        log_file = os.path.join(log_dir, 'qtfund_auth.log')
        handler = RotatingFileHandler(
            log_file,
            maxBytes=10240000,  # 10MB
            backupCount=10
        )

        handler.setFormatter(logging.Formatter(
            app.config['LOG_FORMAT']
        ))

        log_level = getattr(logging, app.config['LOG_LEVEL'].upper(), logging.INFO)
        handler.setLevel(log_level)
        app.logger.addHandler(handler)
        app.logger.setLevel(log_level)


def register_blueprints(app):
    """注册所有蓝图"""
    from app.auth.routes import auth_bp
    from app.user.routes import user_bp
    from app.admin.routes import admin_bp

    # 认证相关路由
    app.register_blueprint(auth_bp, url_prefix='/api/v1/auth')

    # 用户管理路由
    app.register_blueprint(user_bp, url_prefix='/api/v1/user')

    # 管理员路由
    app.register_blueprint(admin_bp, url_prefix='/api/v1/admin')

    # 健康检查路由
    @app.route('/health')
    def health_check():
        return {
            'status': 'healthy',
            'service': 'qtfund-auth',
            'version': '1.0.0'
        }


def register_error_handlers(app):
    """注册错误处理器"""
    from app.utils.responses import error_response

    @app.errorhandler(400)
    def bad_request(error):
        return error_response('请求参数错误', 400, 'BAD_REQUEST')

    @app.errorhandler(401)
    def unauthorized(error):
        return error_response('未认证或认证已过期', 401, 'UNAUTHORIZED')

    @app.errorhandler(403)
    def forbidden(error):
        return error_response('权限不足', 403, 'FORBIDDEN')

    @app.errorhandler(404)
    def not_found(error):
        return error_response('资源不存在', 404, 'NOT_FOUND')

    @app.errorhandler(429)
    def too_many_requests(error):
        return error_response('请求过于频繁，请稍后再试', 429, 'TOO_MANY_REQUESTS')

    @app.errorhandler(500)
    def internal_error(error):
        app.logger.error(f'服务器内部错误: {error}')
        return error_response('服务器内部错误', 500, 'INTERNAL_ERROR')


def register_context_processors(app):
    """注册应用上下文处理器"""
    @app.before_request
    def before_request():
        """每个请求前的处理"""
        pass

    @app.after_request
    def after_request(response):
        """每个请求后的处理"""
        # 添加安全头
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        return response