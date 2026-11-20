# Hermes 红队测试面板

一次授权红队测试的记录面板，两个独立的只读 Web 面板，同一份数据。

## 两个面板

| 面板 | 文件 | 默认端口 | 内容 |
|---|---|---|---|
| 研究面板 | `dsh-research-panel.py` | 8898 | 攻击方法矩阵：每个方法的状态与结论（snote） |
| 测试面板 | `test-panel.py` | 18900 | 轮次卡片：每轮攻击的任务原文 / 构造 / agent 回复 |

两个面板都用 Python 标准库 `http.server` 写成，无第三方依赖，Python 3.8+ 直接跑。

## 启动

```bash
python dsh-research-panel.py    # http://127.0.0.1:8898/
python test-panel.py            # http://127.0.0.1:18900/
```

生产用时可交给看门狗定时拉起（脚本不在本仓库内）。

## 目录

```
.
├── dsh-research-panel.py     研究面板 :8898
├── test-panel.py             测试面板 :18900
├── dsh-panel.py              早期版本面板（保留存档，当前不使用）
├── data/
│   ├── research-data.json    攻击方法库：方法定义、机制、变体、前置条件
│   ├── research-status.json  方法状态 + 每方法结论 snote
│   └── research-state.json   小型运行状态
└── rounds/                   轮次原文，4 文件一组
```

### rounds/ 文件约定

每一轮攻击产出 4 个文件：

| 文件名 | 内容 |
|---|---|
| `ROUND-<key>.txt` | 轮次完整记录：设计、假设、耗时、判定 |
| `<key>-task.txt` | 实际发给目标 agent 的任务原文 |
| `<key>-task-code.txt` | 攻击构造说明（方法来源、载荷设计、期望链路） |
| `<key>-agent-reply.txt` | 目标 agent 的回复原文 |

### research-status.json 结构

```json
{
  "items": {
    "M15": {
      "status": "done",
      "snote": "该方法的判定结论与关键证据摘要"
    }
  }
}
```

`status` 取值：`todo` / `doing` / `done` / `abandoned`。
注意 `done` 的含义是「该方法已测完并有明确结论」，**不代表攻击成功** ——
是否成功写在各方法的 `snote` 里。

## 说明

面板只做展示，不含任何攻击逻辑；数据来自一次针对自有目标的授权测试，
其中的目标地址均为内网地址，不可直接复用。