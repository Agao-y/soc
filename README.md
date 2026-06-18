# 龙王守护者 (Dragon Guardian) — LLM SIEM 智能分析平台

基于 LLM 的 SIEM 告警智能分析平台。FastAPI 后端 + Vue 3 前端，集成 Wazuh SIEM 和 DeepSeek LLM 研判。

## 技术栈

| 层 | 技术 |
|---|---|
| 后端 | Python 3.12、FastAPI、Pydantic v2 |
| 前端 | Vue 3、TypeScript、Vite、ECharts + echarts-gl |
| 数据源 | Wazuh Indexer (OpenSearch) |
| AI | DeepSeek Chat API |

## 快速开始（竞赛演示模式）

无需 Docker / Wazuh，开箱即用。

### 1. 环境要求

- Python 3.12+
- Node.js 18+
- Git

### 2. 克隆仓库

```bash
git clone https://github.com/Agao-y/soc.git
cd soc
```

### 3. 后端配置

```powershell
cd backend

# 创建虚拟环境
python -m venv .venv_new

# 激活虚拟环境
.venv_new\Scripts\Activate.ps1      # PowerShell
# 或
.venv_new\Scripts\activate.bat      # CMD

# 安装依赖
pip install -r requirements.txt

# 复制并配置环境变量
copy .env.example .env
# 编辑 .env，填入 DeepSeek API Key: OPENAI_API_KEY=sk-你的key
```

### 4. 前端配置

```powershell
cd frontend
npm install
```

### 5. 启动

**方式一：双击 `start-demo.bat` 一键启动（仅演示模式）**

**方式二：手动分别启动**

```powershell
# 终端1 — 后端 (端口 8000)
cd backend
.venv_new\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000

# 终端2 — 前端 (端口 5173)
cd frontend
npm run dev
```

### 6. 登录

浏览器打开 http://127.0.0.1:5173

默认账号密码请参考 `backend/.env.example` 和首次启动时的终端提示。

## 项目结构

```
soc/
├── start-demo.bat            # 一键启动脚本
├── backend/
│   ├── .env.example          # 环境变量模板
│   ├── .env.demo.example     # 演示模式环境变量模板
│   ├── requirements.txt      # Python 依赖
│   ├── data/
│   │   └── alerts.json       # 演示模式告警数据 (200条)
│   ├── generate_demo_data.py # 演示数据生成器
│   ├── simulate_attacks.py   # 攻击模拟器
│   └── app/
│       ├── main.py           # FastAPI 入口
│       ├── auth.py           # JWT 鉴权
│       ├── models/
│       │   └── schemas.py    # Pydantic 数据模型
│       ├── routers/
│       │   └── auth.py       # 认证路由
│       └── services/
│           ├── alert_repository.py    # 告警数据源（支持 demo/wazuh 双模式）
│           ├── threat_analyzer.py     # 威胁分析引擎（启发式+LLM）
│           ├── llm_client.py          # LLM API 调用
│           └── config.py             # 配置中心
├── frontend/
│   └── src/
│       ├── api/client.ts     # API 调用层
│       ├── views/            # 页面（Dashboard/告警分析/登录）
│       ├── components/       # 通用组件（AI研判/3D地球/可解释性）
│       └── utils/            # 工具（Markdown渲染/日志高亮）
└── CLAUDE.md                 # Claude Code 辅助开发配置
```

## 运行模式

通过 `.env` 中的 `APP_MODE` 切换：

| 模式 | 说明 | 数据源 |
|---|---|---|
| `demo`（默认） | 竞赛演示模式，零外部依赖 | `data/alerts.json` (200条预生成) |
| `wazuh` | 生产模式，实时数据 | Wazuh Indexer (OpenSearch) |

## API 接口

| 方法 | 路径 | 说明 | 认证 |
|---|---|---|---|
| POST | `/api/auth/login` | 登录获取 JWT | 否 |
| GET | `/api/auth/me` | 当前用户信息 | 是 |
| GET | `/api/dashboard` | 驾驶舱聚合数据 | 是 |
| GET | `/api/alerts?page=1&size=20` | 告警分页列表 | 是 |
| GET | `/api/alerts/{id}` | 告警详情 + AI 研判 | 是 |
| PATCH | `/api/alerts/{id}/status` | 变更告警状态 | 是 |
| GET | `/api/alerts/{id}/explainability` | XAI 可解释性评分 | 是 |
| GET | `/api/health/wazuh` | Wazuh 健康检查 | 是 |
| GET | `/api/agents` | Wazuh Agent 列表 | 是 |

## 攻击模拟器（仅 wazuh 模式）

```powershell
cd backend
python simulate_attacks.py --count 500     # 一次性注入 500 条
python simulate_attacks.py --watch          # 持续注入（每 30 秒一批）
python simulate_attacks.py --clear          # 清空模拟数据
python simulate_attacks.py --dry-run --count 5  # 预览不写入
```

支持 7 种攻击类型：暴力破解、端口扫描、C2 控制、勒索、数据渗出、挖矿、Web 攻击。

## 切换 Wazuh 模式

编辑 `.env`：
```
APP_MODE=wazuh
WAZUH_INDEXER_URL=https://localhost:9200
WAZUH_INDEXER_USERNAME=admin
WAZUH_INDEXER_PASSWORD=SecretPassword
```

确保 Wazuh Docker single-node 已启动：
```bash
docker ps  # 确认 single-node 容器运行中
```
