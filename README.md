# 服务器病毒扫描管理系统 - B/S 架构版

## 项目结构
```
virus/
├── app.py                  # Flask 后端主程序
├── servers_config.json     # 服务器配置文件（含密码/密钥）
├── requirements.txt        # Python 依赖
├── templates/
│   └── index.html          # 前端页面
├── static/
│   ├── css/
│   └── js/
└── virus_downloads/        # 病毒文件下载目录
```

## 安装依赖
```bash
pip install -r requirements.txt
```

## 启动服务
```bash
python app.py
```
启动后访问: http://127.0.0.1:5000

## 功能说明
1. **扫描控制** - 配置主控服务器(136)，执行 Ansible 批量扫描，查看结果
2. **服务器配置** - 管理所有子服务器认证，批量测试连通性
3. **病毒处理** - 收集病毒文件 → 下载到本地 → 火绒二次扫描 → 确认后批量删除
4. **ClamAV 管理** - 检查版本/病毒库日期，一键执行 freshclam 更新病毒库
5. **系统信息** - 收集所有服务器的 OS/内核/CPU/内存信息

## 关于 ClamAV 误报问题
- 病毒库过旧是误报的主要原因 → 在「ClamAV管理」页点击「更新病毒库」
- 建议每周执行一次 freshclam 更新
- 如果业务目录稳定，可以在 scan.yml 中添加排除路径:
  ```
  clamscan:
    exclude:
      - '/opt/your_biz_dir'
      - '/home/your_data'
  ```

## 从桌面版迁移说明
- 原 tkinter 桌面版的所有功能已完整迁移到 Web 版
- 配置文件 servers_config.json 已直接复用
- 所有操作改为浏览器点击，无需再装 Python GUI 环境
