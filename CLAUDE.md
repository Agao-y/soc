# SOC 项目 — 龙王守护者

## 项目概述

基于 LLM 的 SIEM 告警智能分析平台。FastAPI 后端 + Vue 3 前端，集成 Wazuh SIEM 数据源和 DeepSeek LLM 研判。

## 技术栈

- 后端：Python 3.12、FastAPI、Pydantic v2、httpx
- 前端：Vue 3、TypeScript、Vite、ECharts + echarts-gl 3D 地球
- 数据源：Wazuh Indexer (OpenSearch) + Wazuh Manager API
- LLM：DeepSeek Chat API (OpenAI 兼容接口)

## 启动命令

### 后端
```powershell
cd D:\soc\soc\backend
.venv_new\Scripts\Activate.ps1
python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```
- 健康检查：http://127.0.0.1:8000/health
- Swagger：http://127.0.0.1:8000/docs
- 告警接口：http://127.0.0.1:8000/api/alerts

### 前端
```powershell
cd D:\soc\soc\frontend
npm run dev
```
- 前端地址：http://127.0.0.1:5173
- Vite 代理 /api → 127.0.0.1:8000

### Wazuh
```powershell
docker ps  # 确认 single-node 容器在运行
```
- Dashboard：https://localhost (admin/SecretPassword)
- Indexer API：https://localhost:9200

## 当前配置状态

- `.env` 中 APP_MODE=wazuh，数据源从 Wazuh 实时读取
- LLM 已配置 DeepSeek：`deepseek-chat` 模型
- Wazuh Docker single-node 已部署
- 虚拟环境：`backend\.venv_new`（旧的 `.venv` 损坏无法删除）

## API 接口

| 方法 | 路径 | 功能 |
|------|------|------|
| GET | /health | 健康检查（无需认证） |
| POST | /api/auth/login | JWT登录（无需认证） |
| GET | /api/alerts | 告警列表 |
| GET | /api/alerts/{id} | 告警详情+AI研判 |
| PATCH | /api/alerts/{id}/status | 变更告警状态（resolved/ignored/escalated） |
| GET | /api/alerts/{id}/explainability | XAI解释 |
| GET | /api/dashboard | 驾驶舱聚合 |
| GET | /api/health/wazuh | Wazuh状态 |
| GET | /api/agents | Agent列表 |
| GET | /api/agents/{id} | Agent详情 |

所有 `/api/alerts*` `/api/dashboard` `/api/agents*` 需带 `Authorization: Bearer <token>`

## JWT 鉴权

- 默认账号：admin / admin123
- Token 有效期：8 小时
- 401 时前端自动跳转 /login
- 后端模块：`backend/app/auth.py`、`backend/app/routers/auth.py`

## 8 个前端模块

CockpitHeader / AlertFlowTicker / AiAnalysisBoard / ResponseAdvicePanel / SituationVisualizationPanel / ExplainabilityPanel / TicketFlowPanel / DashboardPage

## 攻击模拟器

```powershell
cd D:\soc\soc\backend
.venv_new\Scripts\Activate.ps1
python simulate_attacks.py --count 500     # 一次性注入500条
python simulate_attacks.py --watch          # 持续注入(每30秒一批)
python simulate_attacks.py --clear          # 清空模拟数据
python simulate_attacks.py --dry-run --count 5  # 预览不写入
```
- 直接写 Wazuh Indexer (OpenSearch)，生成7种攻击类型
- 告警带有标记 `sim_tag: soc-simulation`，方便批量清理
- 含暴力破解/端口扫描/C2/勒索/渗出/挖矿/Web攻击

## 状态持久化

- 告警状态保存到 `backend/data/alert_status.json`
- 刷新/重启后状态不丢失

## Git

- 仓库：https://github.com/Agao-y/soc.git
- 分支：main

## 团队分组

- 第一组（前端展示组）：页面展示、交互流程、截图
- 第二组（后端接口组）：接口、路由、数据返回
- 第三组（数据分析组）：告警数据、风险评分、AI研判
