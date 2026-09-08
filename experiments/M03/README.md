# M3 消息边界识别

当前状态：可解释规则基线已实现，等待真实 DAT 的协议线索与参数验证。

支持三类显式假设：

- `length`：可选 Magic + 固定位置长度字段，支持大小端、长度表示 payload/整帧、尾字段和最大帧长约束。
- `delimiter`：按字节分隔符切分，可选择消息是否包含分隔符。
- `fixed`：从指定偏移按固定长度切分。

模块只接受完整且不越界的消息。前导噪声、伪 Magic、非法长度、未终止数据和尾部残片不会丢弃，统一写入 `unparsed_ranges`；候选拒绝原因写入 `diagnostics`。每条接受消息保存独立 `.bin` 产物，并保留原始流的零起点半开区间。

长度字段示例：

```powershell
python run.py stream.dat --output-dir output --rule length `
  --magic-hex cafe --length-offset 3 --length-width 2 --byteorder big `
  --length-mode payload --header-size 5 --trailer-size 1 --max-frame-length 4096
```

运行测试：

```powershell
python -m unittest discover -s tests -v
```

当前算法只验证“给定规则是否与字节结构一致”，不会把命中结果冒充协议真值。Magic 出现在 payload 中、长度字段偶然合理或错误配置都可能产生误切；真实使用时需结合多样本一致性与后续模块反证。
