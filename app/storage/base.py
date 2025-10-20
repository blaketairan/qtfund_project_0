"""
文件存储基类
提供安全的JSON文件存储功能，支持文件锁和原子写入
"""
import json
import os
import tempfile
import shutil
from pathlib import Path
from typing import Dict, Any, Optional, List, TypeVar, Generic
from filelock import FileLock
from datetime import datetime
import logging

T = TypeVar('T')

logger = logging.getLogger(__name__)


class BaseFileStorage(Generic[T]):
    """
    文件存储基类

    提供通用的JSON文件存储功能：
    - 文件锁保证并发安全
    - 原子写入防止数据损坏
    - 自动备份机制
    - 数据验证
    """

    def __init__(self, file_path: str, backup_enabled: bool = True):
        """
        初始化文件存储

        Args:
            file_path: 数据文件路径
            backup_enabled: 是否启用自动备份
        """
        self.file_path = Path(file_path)
        self.lock_path = Path(f"{file_path}.lock")
        self.backup_enabled = backup_enabled

        # 确保目录存在
        self.file_path.parent.mkdir(parents=True, exist_ok=True)

        # 设置文件权限（仅owner可读写）
        if self.file_path.exists():
            os.chmod(self.file_path, 0o600)

    def _acquire_lock(self) -> FileLock:
        """获取文件锁"""
        return FileLock(self.lock_path, timeout=10)

    def _create_backup(self):
        """创建备份文件"""
        if not self.backup_enabled or not self.file_path.exists():
            return

        try:
            backup_dir = self.file_path.parent / 'backups'
            backup_dir.mkdir(exist_ok=True)

            timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
            backup_name = f"{self.file_path.stem}_{timestamp}{self.file_path.suffix}"
            backup_path = backup_dir / backup_name

            shutil.copy2(self.file_path, backup_path)
            logger.debug(f"已创建备份: {backup_path}")

            # 清理旧备份（保留最近7个）
            self._cleanup_old_backups(backup_dir, self.file_path.stem)

        except Exception as e:
            logger.warning(f"创建备份失败: {e}")

    def _cleanup_old_backups(self, backup_dir: Path, file_stem: str, keep_count: int = 7):
        """清理旧备份文件"""
        try:
            backup_files = list(backup_dir.glob(f"{file_stem}_*{self.file_path.suffix}"))
            backup_files.sort(key=lambda x: x.stat().st_mtime, reverse=True)

            # 删除超出保留数量的备份
            for old_backup in backup_files[keep_count:]:
                old_backup.unlink()
                logger.debug(f"已删除旧备份: {old_backup}")

        except Exception as e:
            logger.warning(f"清理旧备份失败: {e}")

    def read_data(self) -> Dict[str, Any]:
        """
        读取数据文件

        Returns:
            Dict: 文件内容
        """
        if not self.file_path.exists():
            return self._get_empty_structure()

        with self._acquire_lock():
            try:
                with open(self.file_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)

                # 验证数据结构
                if not self._validate_data_structure(data):
                    logger.warning(f"数据结构验证失败，使用默认结构: {self.file_path}")
                    return self._get_empty_structure()

                return data

            except (json.JSONDecodeError, FileNotFoundError) as e:
                logger.error(f"读取数据文件失败: {self.file_path}, 错误: {e}")
                return self._get_empty_structure()

    def write_data(self, data: Dict[str, Any]):
        """
        写入数据文件（原子操作）

        Args:
            data: 要写入的数据
        """
        # 验证数据结构
        if not self._validate_data_structure(data):
            raise ValueError("数据结构验证失败")

        with self._acquire_lock():
            # 创建备份
            self._create_backup()

            # 原子写入
            temp_file = None
            try:
                # 创建临时文件
                temp_fd, temp_path = tempfile.mkstemp(
                    suffix='.tmp',
                    prefix=f"{self.file_path.stem}_",
                    dir=self.file_path.parent
                )
                temp_file = Path(temp_path)

                # 写入临时文件
                with os.fdopen(temp_fd, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=2, ensure_ascii=False, default=str)
                    f.flush()
                    os.fsync(f.fileno())  # 强制写入磁盘

                # 设置文件权限
                os.chmod(temp_file, 0o600)

                # 原子替换
                shutil.move(temp_file, self.file_path)
                logger.debug(f"数据已写入: {self.file_path}")

            except Exception as e:
                # 清理临时文件
                if temp_file and temp_file.exists():
                    try:
                        temp_file.unlink()
                    except:
                        pass
                raise RuntimeError(f"写入数据文件失败: {e}")

    def update_data(self, update_func):
        """
        更新数据（读取-修改-写入）

        Args:
            update_func: 更新函数，接收当前数据并返回新数据
        """
        with self._acquire_lock():
            data = self.read_data()
            updated_data = update_func(data)
            if updated_data is not None:
                self.write_data(updated_data)

    def _get_empty_structure(self) -> Dict[str, Any]:
        """
        获取空的数据结构

        Returns:
            Dict: 空数据结构
        """
        return {
            'data': [],
            'metadata': {
                'version': '1.0',
                'created_at': datetime.utcnow().isoformat() + 'Z',
                'last_updated': datetime.utcnow().isoformat() + 'Z',
                'count': 0
            }
        }

    def _validate_data_structure(self, data: Dict[str, Any]) -> bool:
        """
        验证数据结构

        Args:
            data: 要验证的数据

        Returns:
            bool: 是否有效
        """
        # 基本结构检查
        if not isinstance(data, dict):
            return False

        # 检查必需字段
        required_fields = {'data', 'metadata'}
        if not all(field in data for field in required_fields):
            return False

        # 检查数据字段类型
        if not isinstance(data.get('data'), (list, dict)):
            return False

        # 检查元数据
        metadata = data.get('metadata', {})
        if not isinstance(metadata, dict):
            return False

        return True

    def backup_data(self, backup_path: Optional[str] = None) -> str:
        """
        手动备份数据

        Args:
            backup_path: 备份文件路径，如果为None则自动生成

        Returns:
            str: 备份文件路径
        """
        if not self.file_path.exists():
            raise FileNotFoundError(f"数据文件不存在: {self.file_path}")

        if backup_path is None:
            timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
            backup_path = f"{self.file_path.stem}_backup_{timestamp}{self.file_path.suffix}"

        backup_path = Path(backup_path)
        backup_path.parent.mkdir(parents=True, exist_ok=True)

        with self._acquire_lock():
            shutil.copy2(self.file_path, backup_path)
            os.chmod(backup_path, 0o600)

        logger.info(f"数据已备份到: {backup_path}")
        return str(backup_path)

    def restore_data(self, backup_path: str):
        """
        从备份恢复数据

        Args:
            backup_path: 备份文件路径
        """
        backup_path = Path(backup_path)
        if not backup_path.exists():
            raise FileNotFoundError(f"备份文件不存在: {backup_path}")

        # 验证备份文件
        try:
            with open(backup_path, 'r', encoding='utf-8') as f:
                backup_data = json.load(f)
            if not self._validate_data_structure(backup_data):
                raise ValueError("备份文件数据结构无效")
        except (json.JSONDecodeError, ValueError) as e:
            raise ValueError(f"备份文件无效: {e}")

        with self._acquire_lock():
            # 创建当前数据的备份
            if self.file_path.exists():
                self._create_backup()

            # 恢复数据
            shutil.copy2(backup_path, self.file_path)
            os.chmod(self.file_path, 0o600)

        logger.info(f"数据已从备份恢复: {backup_path}")

    def get_file_info(self) -> Dict[str, Any]:
        """
        获取文件信息

        Returns:
            Dict: 文件信息
        """
        if not self.file_path.exists():
            return {
                'exists': False,
                'path': str(self.file_path)
            }

        stat = self.file_path.stat()
        return {
            'exists': True,
            'path': str(self.file_path),
            'size': stat.st_size,
            'created_at': datetime.fromtimestamp(stat.st_ctime).isoformat(),
            'modified_at': datetime.fromtimestamp(stat.st_mtime).isoformat(),
            'permissions': oct(stat.st_mode)[-3:]
        }