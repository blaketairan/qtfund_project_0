"""
登录日志数据模型
记录用户登录历史和相关信息
"""
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Optional, Dict, Any


@dataclass
class LoginLog:
    """登录日志数据模型"""
    id: int
    user_id: int
    username: str
    ip_address: str
    user_agent: str
    login_time: str = field(default_factory=lambda: datetime.utcnow().isoformat() + 'Z')
    success: bool = True
    error_message: Optional[str] = None
    session_duration: Optional[int] = None  # 会话持续时间（秒）
    logout_time: Optional[str] = None

    @classmethod
    def create_success_log(
        cls,
        log_id: int,
        user_id: int,
        username: str,
        ip_address: str,
        user_agent: str
    ) -> 'LoginLog':
        """
        创建成功登录日志

        Args:
            log_id: 日志ID
            user_id: 用户ID
            username: 用户名
            ip_address: IP地址
            user_agent: 用户代理

        Returns:
            LoginLog: 登录日志对象
        """
        return cls(
            id=log_id,
            user_id=user_id,
            username=username,
            ip_address=ip_address,
            user_agent=user_agent,
            success=True
        )

    @classmethod
    def create_failure_log(
        cls,
        log_id: int,
        username: str,
        ip_address: str,
        user_agent: str,
        error_message: str,
        user_id: Optional[int] = None
    ) -> 'LoginLog':
        """
        创建失败登录日志

        Args:
            log_id: 日志ID
            username: 用户名
            ip_address: IP地址
            user_agent: 用户代理
            error_message: 错误信息
            user_id: 用户ID（可选，用户不存在时为None）

        Returns:
            LoginLog: 登录日志对象
        """
        return cls(
            id=log_id,
            user_id=user_id or 0,  # 用户不存在时设为0
            username=username,
            ip_address=ip_address,
            user_agent=user_agent,
            success=False,
            error_message=error_message
        )

    def set_logout(self):
        """设置登出时间并计算会话持续时间"""
        self.logout_time = datetime.utcnow().isoformat() + 'Z'

        # 计算会话持续时间
        if self.login_time:
            try:
                login_dt = datetime.fromisoformat(self.login_time.replace('Z', '+00:00'))
                logout_dt = datetime.fromisoformat(self.logout_time.replace('Z', '+00:00'))
                self.session_duration = int((logout_dt - login_dt).total_seconds())
            except (ValueError, AttributeError):
                self.session_duration = None

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return asdict(self)

    def to_public_dict(self) -> Dict[str, Any]:
        """转换为公开信息字典（隐藏敏感信息）"""
        data = self.to_dict()
        # 可以选择性隐藏某些敏感信息
        # 比如只显示IP地址的前几位
        if self.ip_address:
            ip_parts = self.ip_address.split('.')
            if len(ip_parts) == 4:
                data['ip_address'] = f"{ip_parts[0]}.{ip_parts[1]}.*.* "

        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'LoginLog':
        """从字典创建登录日志对象"""
        required_fields = {'id', 'user_id', 'username', 'ip_address', 'user_agent'}
        if not all(field in data for field in required_fields):
            raise ValueError(f"缺少必需字段: {required_fields - set(data.keys())}")

        return cls(**data)

    def is_successful(self) -> bool:
        """检查登录是否成功"""
        return self.success

    def get_formatted_login_time(self) -> str:
        """获取格式化的登录时间"""
        try:
            dt = datetime.fromisoformat(self.login_time.replace('Z', '+00:00'))
            return dt.strftime('%Y-%m-%d %H:%M:%S')
        except (ValueError, AttributeError):
            return self.login_time or ''

    def get_session_duration_str(self) -> str:
        """获取会话持续时间的字符串表示"""
        if not self.session_duration:
            return '未知'

        hours, remainder = divmod(self.session_duration, 3600)
        minutes, seconds = divmod(remainder, 60)

        if hours > 0:
            return f"{hours}小时{minutes}分钟"
        elif minutes > 0:
            return f"{minutes}分钟{seconds}秒"
        else:
            return f"{seconds}秒"

    def __str__(self) -> str:
        status = "成功" if self.success else "失败"
        return f"LoginLog(id={self.id}, user='{self.username}', status='{status}', time='{self.get_formatted_login_time()}')"

    def __repr__(self) -> str:
        return self.__str__()