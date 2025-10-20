"""
QTFund 认证服务配置管理
支持从环境变量读取配置，提供开发和生产环境的不同配置
"""
import os
from pathlib import Path


class Config:
    """基础配置类"""

    # 项目根目录
    BASE_DIR = Path(__file__).parent.parent

    # Flask 基本配置
    SECRET_KEY = os.getenv('SECRET_KEY', 'qtfund-auth-dev-secret-key-2024')
    DEBUG = os.getenv('DEBUG', 'False').lower() == 'true'

    # JWT 配置
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', 'qtfund-jwt-secret-key-2024')
    JWT_EXPIRATION_HOURS = int(os.getenv('JWT_EXPIRATION_HOURS', '24'))
    JWT_ALGORITHM = 'HS256'

    # 服务器配置
    SERVER_HOST = os.getenv('SERVER_HOST', '0.0.0.0')
    SERVER_PORT = int(os.getenv('SERVER_PORT', '9000'))

    # 文件存储配置
    DATA_DIR = os.getenv('DATA_DIR', str(BASE_DIR / 'data'))
    BACKUP_DIR = os.getenv('BACKUP_DIR', str(BASE_DIR / 'backups'))
    LOG_DIR = os.getenv('LOG_DIR', str(BASE_DIR / 'logs'))

    # 数据文件名
    USERS_FILE = os.getenv('USERS_FILE', 'users.json')
    LOGIN_LOGS_FILE = os.getenv('LOGIN_LOGS_FILE', 'login_logs.json')
    PERMISSIONS_FILE = os.getenv('PERMISSIONS_FILE', 'permissions.json')
    TOKEN_BLACKLIST_FILE = os.getenv('TOKEN_BLACKLIST_FILE', 'token_blacklist.json')

    # 日志配置
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
    LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    LOG_DATE_FORMAT = '%Y-%m-%d %H:%M:%S'

    # 备份配置
    BACKUP_ENABLED = os.getenv('BACKUP_ENABLED', 'True').lower() == 'true'
    BACKUP_INTERVAL_HOURS = int(os.getenv('BACKUP_INTERVAL_HOURS', '24'))
    BACKUP_RETENTION_DAYS = int(os.getenv('BACKUP_RETENTION_DAYS', '30'))

    # 安全配置
    BCRYPT_ROUNDS = int(os.getenv('BCRYPT_ROUNDS', '12'))
    PASSWORD_MIN_LENGTH = int(os.getenv('PASSWORD_MIN_LENGTH', '8'))
    PASSWORD_MAX_LENGTH = int(os.getenv('PASSWORD_MAX_LENGTH', '50'))
    USERNAME_MIN_LENGTH = int(os.getenv('USERNAME_MIN_LENGTH', '3'))
    USERNAME_MAX_LENGTH = int(os.getenv('USERNAME_MAX_LENGTH', '20'))

    # CORS 配置
    CORS_ORIGINS = os.getenv('CORS_ORIGINS', '*').split(',')

    # 限流配置
    RATE_LIMIT_ENABLED = os.getenv('RATE_LIMIT_ENABLED', 'True').lower() == 'true'
    RATE_LIMIT_DEFAULT = os.getenv('RATE_LIMIT_DEFAULT', '100/hour')
    RATE_LIMIT_LOGIN = os.getenv('RATE_LIMIT_LOGIN', '10/minute')

    # 权限配置
    DEFAULT_ROLE = os.getenv('DEFAULT_ROLE', 'user')
    ROLES = ['admin', 'user', 'readonly']

    @classmethod
    def init_directories(cls):
        """初始化必要的目录"""
        for directory in [cls.DATA_DIR, cls.BACKUP_DIR, cls.LOG_DIR]:
            Path(directory).mkdir(parents=True, exist_ok=True)

    @property
    def users_file_path(self):
        """用户数据文件完整路径"""
        return Path(self.DATA_DIR) / self.USERS_FILE

    @property
    def login_logs_file_path(self):
        """登录日志文件完整路径"""
        return Path(self.DATA_DIR) / self.LOGIN_LOGS_FILE

    @property
    def permissions_file_path(self):
        """权限配置文件完整路径"""
        return Path(self.DATA_DIR) / self.PERMISSIONS_FILE

    @property
    def token_blacklist_file_path(self):
        """Token黑名单文件完整路径"""
        return Path(self.DATA_DIR) / self.TOKEN_BLACKLIST_FILE


class DevelopmentConfig(Config):
    """开发环境配置"""
    DEBUG = True
    LOG_LEVEL = 'DEBUG'


class ProductionConfig(Config):
    """生产环境配置"""
    DEBUG = False
    LOG_LEVEL = 'INFO'

    # 生产环境更严格的安全设置
    BCRYPT_ROUNDS = 14
    RATE_LIMIT_LOGIN = '5/minute'


class TestingConfig(Config):
    """测试环境配置"""
    TESTING = True
    DEBUG = True

    # 测试环境使用临时目录
    DATA_DIR = '/tmp/qtfund_test_data'
    BACKUP_DIR = '/tmp/qtfund_test_backups'
    LOG_DIR = '/tmp/qtfund_test_logs'

    # 测试环境更宽松的设置
    BCRYPT_ROUNDS = 4  # 测试时使用更少的rounds以提高速度
    JWT_EXPIRATION_HOURS = 1


# 根据环境变量选择配置
config_map = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}


def get_config():
    """获取当前环境的配置"""
    env = os.getenv('FLASK_ENV', 'default')
    return config_map.get(env, DevelopmentConfig)