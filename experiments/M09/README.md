# M09 流量统计特征

从 M01 `result.json` 的真实包、流、端点和时间戳生成保守的流级特征。不会将裸 DAT、M03 消息长度或端口号伪装为网络元数据。

```powershell
python experiments/M09/run.py path/to/m01/result.json --output-dir runs/m09
```

输出为 `flow_features.json`。M01 输入会先经过严格 Schema、内部引用和有限时间戳校验；输出也在原子发布前通过严格 Schema。来源 JSON 的 SHA-256 写入 `source`，输出目录必须不存在。没有流记录时返回 `insufficient_metadata`，缺少单项时间或长度证据时返回 `partial` 和 `unavailable_features`。方向始终是 `node0_to_node1` / `node1_to_node0`，不推断客户端、服务端、上传或下载。
