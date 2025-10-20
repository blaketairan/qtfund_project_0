#!/bin/bash

# QTFund nginx配置管理脚本
# 用于在项目配置和系统配置之间同步

PROJECT_DIR="/data/terrell/workspace/qtfund_project_0"
PROJECT_NGINX_CONFIG="$PROJECT_DIR/nginx/qtfund.com.conf"
SYSTEM_NGINX_CONFIG="/etc/nginx/conf.d/qtfund.com.conf"

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 打印帮助信息
show_help() {
    echo -e "${BLUE}QTFund nginx配置管理脚本${NC}"
    echo ""
    echo "用法: $0 [命令]"
    echo ""
    echo "命令:"
    echo "  deploy    - 将项目配置部署到nginx系统目录"
    echo "  backup    - 从系统目录备份配置到项目"
    echo "  diff      - 比较项目配置和系统配置的差异"
    echo "  test      - 测试nginx配置文件语法"
    echo "  reload    - 重新加载nginx配置"
    echo "  status    - 查看nginx状态"
    echo "  help      - 显示此帮助信息"
    echo ""
    echo "示例:"
    echo "  $0 deploy   # 部署项目配置到系统"
    echo "  $0 backup   # 备份系统配置到项目"
    echo "  $0 diff     # 查看配置差异"
}

# 检查文件是否存在
check_files() {
    if [ ! -f "$PROJECT_NGINX_CONFIG" ]; then
        echo -e "${RED}错误: 项目nginx配置文件不存在: $PROJECT_NGINX_CONFIG${NC}"
        exit 1
    fi
}

# 部署配置到系统
deploy_config() {
    echo -e "${BLUE}部署nginx配置到系统...${NC}"

    check_files

    # 备份当前系统配置
    if [ -f "$SYSTEM_NGINX_CONFIG" ]; then
        sudo cp "$SYSTEM_NGINX_CONFIG" "$SYSTEM_NGINX_CONFIG.backup.$(date +%Y%m%d_%H%M%S)"
        echo -e "${YELLOW}已备份当前系统配置${NC}"
    fi

    # 复制项目配置到系统
    sudo cp "$PROJECT_NGINX_CONFIG" "$SYSTEM_NGINX_CONFIG"
    echo -e "${GREEN}✅ 配置文件已复制到系统目录${NC}"

    # 测试配置
    if sudo nginx -t; then
        echo -e "${GREEN}✅ nginx配置语法检查通过${NC}"

        # 重新加载nginx
        if sudo nginx -s reload; then
            echo -e "${GREEN}✅ nginx配置已重新加载${NC}"
            echo -e "${GREEN}🎉 部署完成！${NC}"
        else
            echo -e "${RED}❌ nginx重新加载失败${NC}"
            exit 1
        fi
    else
        echo -e "${RED}❌ nginx配置语法错误，部署失败${NC}"
        exit 1
    fi
}

# 备份系统配置到项目
backup_config() {
    echo -e "${BLUE}备份系统nginx配置到项目...${NC}"

    if [ ! -f "$SYSTEM_NGINX_CONFIG" ]; then
        echo -e "${RED}错误: 系统nginx配置文件不存在: $SYSTEM_NGINX_CONFIG${NC}"
        exit 1
    fi

    # 创建目录
    mkdir -p "$(dirname "$PROJECT_NGINX_CONFIG")"

    # 备份当前项目配置
    if [ -f "$PROJECT_NGINX_CONFIG" ]; then
        cp "$PROJECT_NGINX_CONFIG" "$PROJECT_NGINX_CONFIG.backup.$(date +%Y%m%d_%H%M%S)"
        echo -e "${YELLOW}已备份当前项目配置${NC}"
    fi

    # 复制系统配置到项目
    sudo cp "$SYSTEM_NGINX_CONFIG" "$PROJECT_NGINX_CONFIG"
    echo -e "${GREEN}✅ 系统配置已备份到项目目录${NC}"
}

# 比较配置差异
diff_config() {
    echo -e "${BLUE}比较项目配置和系统配置...${NC}"

    if [ ! -f "$PROJECT_NGINX_CONFIG" ]; then
        echo -e "${RED}项目配置文件不存在${NC}"
        return 1
    fi

    if [ ! -f "$SYSTEM_NGINX_CONFIG" ]; then
        echo -e "${RED}系统配置文件不存在${NC}"
        return 1
    fi

    echo -e "${YELLOW}项目配置: $PROJECT_NGINX_CONFIG${NC}"
    echo -e "${YELLOW}系统配置: $SYSTEM_NGINX_CONFIG${NC}"
    echo ""

    if diff -u "$SYSTEM_NGINX_CONFIG" "$PROJECT_NGINX_CONFIG"; then
        echo -e "${GREEN}✅ 配置文件相同${NC}"
    else
        echo -e "${YELLOW}⚠️  配置文件有差异${NC}"
    fi
}

# 测试nginx配置
test_config() {
    echo -e "${BLUE}测试nginx配置语法...${NC}"

    if sudo nginx -t; then
        echo -e "${GREEN}✅ nginx配置语法正确${NC}"
    else
        echo -e "${RED}❌ nginx配置语法错误${NC}"
        exit 1
    fi
}

# 重新加载nginx
reload_nginx() {
    echo -e "${BLUE}重新加载nginx配置...${NC}"

    if sudo nginx -s reload; then
        echo -e "${GREEN}✅ nginx配置已重新加载${NC}"
    else
        echo -e "${RED}❌ nginx重新加载失败${NC}"
        exit 1
    fi
}

# 查看nginx状态
nginx_status() {
    echo -e "${BLUE}nginx服务状态:${NC}"
    systemctl status nginx --no-pager -l

    echo ""
    echo -e "${BLUE}nginx进程:${NC}"
    ps aux | grep nginx | grep -v grep

    echo ""
    echo -e "${BLUE}nginx监听端口:${NC}"
    ss -tlnp | grep nginx
}

# 主逻辑
case "${1:-help}" in
    "deploy")
        deploy_config
        ;;
    "backup")
        backup_config
        ;;
    "diff")
        diff_config
        ;;
    "test")
        test_config
        ;;
    "reload")
        reload_nginx
        ;;
    "status")
        nginx_status
        ;;
    "help"|*)
        show_help
        ;;
esac