# M1 数据输入与预处理 实验

当前状态：已实现输入内容探测、裸字节保全、抓包包/流/方向流提取；正在恢复可复现测试。

当前入口：

```powershell
python run.py <input> --output-dir <new-output-directory>
python -m unittest discover -s tests -v
```

实现与验证范围：

- `.dat` 后缀不作为格式证据；PCAP/PCAPNG 先做内部结构校验。
- 若可用，`capinfos` 提供第二重格式证据；缺失时仍可完成结构探测，并显式警告。
- 抓包内容提取需要 `tshark`；未安装时相关测试自动跳过，不伪造结果。
- `data/fixtures/` 和 `data/ground-truth/m01-ground-truth.json` 提供正常、伪 magic、截断、重传及多流样例。
- 输出契约见 `research/M01-input/input-artifact.schema.json`。

历史运行记录位于 `runs/`；它们不代表当前机器已复测通过。

