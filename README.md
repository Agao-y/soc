# 龙王守护者-基于LLM的SIME的告警智能分析平台

这是一个面向 SOC 场景的高级威胁检测项目骨架，聚合 SIEM 告警、进行轻量机器学习风险评分，并结合大语言模型生成威胁研判和处置建议。

## 项目能力

- 告警聚合：统一接入 Wazuh / ELK / Suricata 风格告警数据
- 威胁研判：结合规则特征、资产上下文和日志内容估算风险分
- 误报压降：输出误报概率，辅助分析师快速筛选高价值告警
- 处置建议：利用 LLM 自动生成简洁中文研判与处置动作
- 溯源分析：根据时间线输出追踪摘要
- 可解释性：展示风险评分主要因子，提升分析透明度

## 技术栈

- 后端：Python、FastAPI、Pydantic
- 智能分析：启发式规则评分、轻量“ML 风格”异常分、LLM 研判接口
- 前端：Vue 3、TypeScript、Vite
- SIEM 数据：内置 Wazuh / ELK / Suricata 示例数据，可扩展为真实 API 对接

## 目录结构

```text
backend/
  app/
    main.py
    models/
    routers/
    services/
  data/alerts.json
frontend/
  src/
    api/
    components/
    styles/
README.md
```

## 快速启动

### 1. 启动后端

```bash
cd backend
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env
uvicorn app.main:app --reload
```

PowerShell 中请按行执行，不要使用 `&&`。例如：

```powershell
cd F:\soc\backend
python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

默认启动地址：`http://127.0.0.1:8000`

可访问：

- 健康检查：`http://127.0.0.1:8000/health`
- Swagger：`http://127.0.0.1:8000/docs`

### 2. 启动前端

```bash
cd frontend
npm install
npm run dev
```

PowerShell 示例：

```powershell
cd F:\soc\frontend
npm run dev
```

默认前端地址：`http://127.0.0.1:5173`

前端开发环境默认通过 Vite 代理把 `/api` 请求转发到本机后端 `http://127.0.0.1:8000`，因此本机和局域网访问都不需要再手动修改前端接口地址。

### 局域网访问说明

如果需要让同一局域网内的其他主机访问，请使用本机 IP，而不是 `127.0.0.1`。

1. 后端必须监听局域网地址：

```powershell
cd F:\soc\backend
python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

2. 前端保持默认启动即可：

```powershell
cd F:\soc\frontend
npm run dev
```

3. 在其他主机浏览器访问：

- 前端：`http://你的主机IP:5173`
- 后端文档：`http://你的主机IP:8000/docs`

前端开发环境会把浏览器中的 `/api` 请求先发送到 `5173`，再由 Vite 代理转发到运行前端的这台主机上的 `8000` 后端。因此其他主机访问 `http://你的主机IP:5173` 时，也能通过同一台主机拿到后端数据。

如果你的后端不是默认地址，可在前端启动前设置：

```bash
set VITE_API_BASE_URL=http://127.0.0.1:8000/api
```

## LLM 接入方式

当前后端内置两种模式：

1. 未配置 `OPENAI_API_KEY` 时，系统使用本地回退分析逻辑，项目可以直接演示
2. 配置 `OPENAI_API_KEY` 后，后端会调用兼容 OpenAI Chat Completions 的接口生成真实研判结论

可在 `backend/.env` 中配置：

```env
OPENAI_API_KEY=your_key
OPENAI_BASE_URL=https://api.openai.com/v1
OPENAI_MODEL=gpt-4o-mini
```

## 当前实现说明

- 示例数据位于 `backend/data/alerts.json`
- `ThreatAnalyzer` 负责风险评分、误报概率估算、处置建议与溯源摘要
- `LLMClient` 负责调用大模型或执行本地回退逻辑
- 前端已升级为 8 大模块安全运营驾驶舱：
  - 全局态势驾驶舱
  - 实时告警流
  - AI 智能研判大屏
  - AI 生成处置建议
  - 攻击态势热力图
  - 告警类型分布图
  - 可解释性面板（XAI）
  - 处置工单流转面板

## 下一步可扩展方向

- 对接真实 Wazuh API / Elasticsearch 检索接口
- 使用向量库做历史告警相似性召回
- 引入 XGBoost / Isolation Forest / AutoEncoder 实现真实异常检测
- 增加 SOAR 工单联动、封禁 IP、隔离主机等自动化动作
- 接入 RBAC、审计日志与多租户能力
