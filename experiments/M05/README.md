# M5 消息对齐

当前状态：字节级 Needleman–Wunsch 参考对齐基线已实现。输入为 M04 `clusters.json`；每个簇使用 M04 选择的真实代表消息作为锚点，对簇内消息逐一全局对齐，再把相同参考偏移与插入锚点合并成统一列。

每个对齐单元为 `[原消息字节偏移, 字节值]`，gap 为 JSON `null`，因此不会与真实 `0x00` 混淆。M04 噪声消息不强行对齐，而是在 `unaligned_messages` 中保留原因。

```powershell
python run.py <m04-output>\clusters.json --output-dir <new-output-directory> `
  --match-score 2 --mismatch-score -1 --gap-score -2
python -m unittest discover -s tests -v
```

如果 M04 中记录的 `framing_path` 已移动，可用 `--framing-json` 显式指定；内容哈希仍必须与 M04 记录一致。输出 `alignments.json` 包含逐簇列定义、逐消息原始偏移映射、匹配/错配/gap 计数及汇总指标。

算法对每个“代表消息—成员消息”对使用 O(mn) 时间与 traceback 空间；默认拒绝超过 2,000,000 个动态规划单元的单次对齐。合并结果是以代表消息为锚的确定性参考对齐，不是全局最优多序列对齐；重复区域中的等价 gap 位置可能随评分规则变化。
