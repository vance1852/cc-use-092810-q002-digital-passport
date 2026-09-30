# 大型储能电池全生命周期协同平台

本项目是一套可离线运行的 Python 服务端平台，服务于大型储能电池从入库、状态评估、组件检测、场站调拨到退役处置的协同管理。平台将资产流转、评估协议、质量决定、幂等结果和审计事件保存在 SQLite 中，供运营、质量、维修和审计人员在单个 Linux 应用容器内使用。

## 目录

- `src/battery_logistics/`：储能场站、调拨走廊、资产批次、容量申请、分配与处置情景；
- `src/battery_assurance/`：电池资产、证据版本、评估协议、观测导入、排除复核、分析任务与准入决定；
- `src/component_quality/`：电芯组件批次、响应测量、统计分析、账号权限和质量审批；
- `src/product_passport/`：数字产品护照——把确定版本的资产、组件谱系、质量决定与流转/维修记录组装成可复算、可冻结、可吊销的护照版本；
- `fixtures/`：离线验收使用的评估协议与结构化观测；
- `tests/`：领域规则、错误边界、事务、权限、HTTP API 和命令行验收测试。

## 环境

- Linux
- Python 3.11 或更高版本
- 运行时仅使用 Python 标准库和 SQLite

## 测试

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

## 构建检查

```bash
python3 -m compileall -q src tests
```

## 离线验收

```bash
PYTHONPATH=src python3 -m battery_logistics.acceptance --workspace .
PYTHONPATH=src python3 -m battery_assurance.acceptance --workspace .
PYTHONPATH=src python3 -m component_quality.acceptance
PYTHONPATH=src python3 -m product_passport.acceptance --workspace .
```

四条命令会在临时 SQLite 数据库中完成资产调拨、状态评估、组件质量和数字产品护照续保全流程，不访问外部网络。

## HTTP 服务

```bash
PYTHONPATH=src python3 -m battery_logistics.api --database battery-logistics.sqlite3 --host 127.0.0.1 --port 8080
PYTHONPATH=src python3 -m battery_assurance.api --database battery-assurance.sqlite3 --host 127.0.0.1 --port 8081
PYTHONPATH=src python3 -m component_quality.api --database component-quality.sqlite3 --host 127.0.0.1 --port 8082
PYTHONPATH=src python3 -m product_passport.api --database product-passport.sqlite3 --host 127.0.0.1 --port 8083
```

服务提供 JSON 接口与健康检查。进程重启后可以继续读取 SQLite 中的业务状态和审计历史。

## 数字产品护照

护照模块（`src/product_passport/`）面向续保风控：运营方需要向保险方解释每套电池的当前声明究竟依据了哪些**出厂组件、检测结论、维修记录和所有权事实**。护照本身不产生事实，只把四个来源系统中**确定版本**的证据冻结进版本。

角色与权限：`registrar` 登记/撤销证据，`operator` 组装候选版本，`issuer` 签发/吊销，`auditor` 读取溯源与审计链，`consumer`（如保险方）读取有效护照并登记下游引用。所有写接口携带 `X-Actor-Id`。

核心保证：

- **证据门禁，绝不被最新值覆盖**：组装候选时逐份校验证据；缺失（`missing`）、撤销（`revoked`）、争议冲突（`conflicted`）、未形成终态决定（`not_decided`）、归属资产不一致（`asset_mismatch`）或声明摘要不匹配都会在 409 `evidence_gate_blocked` 的 `blockers` 中逐项列出并阻断签发；候选仍会持久化留痕。签发瞬间还会复查组装后是否有证据被撤销/删除/替换。
- **签发即冻结**：签发后内容摘要（SHA-256）与逐份证据依据冻结；后续维修、复检只能 `assemble` 出**新版本**（`previous_version`/`replaces_version` 形成版本链），不能改写已交付给保险方的历史。
- **确定性重试与冲突**：相同业务编号 + 相同材料（规范化 SHA-256）的重试返回**原护照/原版本**；同业务编号复用幂等键但材料不同返回 409 `conflict`；业务编号不可跨资产复用。
- **吊销与下游失效**：吊销必须填写原因，原因永久保留；该版本上所有 `pending` 的下游引用被级联置为 `invalidated` 并记录原因，已 `completed` 的引用不受影响。
- **时点有效 + 逐项溯源**：`GET /passports/{no}/effective?at=...` 取回某一时点有效的护照（后来吊销不影响对吊销前历史时点的复算）；`.../versions/{v}/provenance` 逐项给出声明来源（证据类别/编号/版本/摘要/冻结内容/登记时间）、签署责任（组装人/签发人/吊销人）与新旧版本关系（`lineage`/`successors`）。所有事件写入带前向哈希的审计链，可由 `GET /audit/chain` 校验。

主要接口：

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/evidence` | 登记确定版本证据（`category` ∈ asset/component/quality/transfer） |
| POST | `/evidence/revoke` | 撤销证据（不回写已签发历史，仅阻断后续组装/签发） |
| POST | `/passports/assemble` | 组装候选版本（带幂等键；门禁失败返回结构化 blockers） |
| POST | `/passports/{no}/versions/{v}/issue` | 签发候选（签发瞬间复查证据有效性） |
| POST | `/passports/{no}/versions/{v}/abandon` | 放弃干净候选 |
| POST | `/passports/{no}/revoke` | 吊销（保留原因，失效未完成下游引用） |
| GET | `/passports/{no}/versions` | 列出版本链 |
| GET | `/passports/{no}/versions/{v}` | 读取某版本冻结内容 |
| GET | `/passports/{no}/versions/{v}/provenance` | 逐项声明溯源 + 签署责任 + 版本关系 |
| GET | `/passports/{no}/effective?at=ISO8601` | 某一时点有效的护照 |
| POST | `/references` | 保险方等登记对已签发版本的下游引用 |
| POST | `/references/{id}/complete` | 完成下游引用（吊销后不受影响） |
| GET | `/passports/{no}/references` | 查看下游引用及失效情况 |
| GET | `/audit/chain` | 校验审计哈希链 |
