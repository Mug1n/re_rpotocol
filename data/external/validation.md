# 真实 DAT 验证记录

验证日期：2026-09-08。当前验证只说明样本能够进入本项目 M01～M06，不代表未知规则自动推断或对所有同类文件泛化成功。完整临时输出位于 `tmp/validation/`，不进入 Git。

## 结果

| 样本 | M01 | M02 | M03 | M04 | 字节覆盖 |
|---|---|---|---|---|---|
| Audiobeat `dsp_m2.dat` | `raw_bytes`，2387 字节，哈希与 manifest 一致 | 全局熵 4.093036 bit/byte；可打印 ASCII 比例 0.358190；零字节比例 0.286552 | 从偏移 5 起按 238 字节固定块切出 10 条；`[0,5)` 为 `US002` Magic，`[2385,2387)` 为 footer | 默认参数为 1 簇；探索参数 `eps=0.11` 为 4 簇、0 噪声。以相邻双通道作探索性标签时 ARI 0.6667、NMI 0.9098；首尾两对被合并 | 消息 2380 字节 + 未解析 7 字节 = 2387，完整覆盖 |
| WatchPAT `testdata.dat` | `raw_bytes`，8469 字节，哈希与 manifest 一致 | 全局熵 5.310145 bit/byte；可打印 ASCII 比例 0.238635；零字节比例 0.234975 | 按 `[u32le payload_length][payload]` 切出 15 条，状态 `complete`，无未解析范围 | 默认参数为 1 簇、0 噪声；与来源所述单一 DATA_PACKET 集合一致，但不构成类型识别 | 15 条消息共 8469 字节，完整覆盖 |

M03 写出的每个消息 artifact 均与源文件对应半开区间逐字节一致。

## M05 对齐结果

| 样本与 M04 参数 | 对齐簇/消息 | 统一列 | 平均配对字节一致率 | 解释 |
|---|---:|---:|---:|---|
| Audiobeat，`eps=0.11` | 4 簇，10/10 条 | 955（各簇列数之和） | 0.968390 | 同长度通道块高度相似；4 簇仍沿用 M04 首尾通道对合并的限制 |
| WatchPAT，默认 `eps=0.25` | 1 簇，15/15 条 | 801 | 0.487364 | 完整覆盖，但低一致率提示单簇过粗；代表消息长度为 563 |
| WatchPAT，探索 `eps=0.11` | 4 簇，13/15 条，2 条噪声 | 2399（各簇列数之和） | 0.613779 | 一致率提高，但 M04 轮廓系数仅 0.139845，不能视为可靠真值 |

所有 M05 行均通过偏移和值重建检查：去除 gap 后，偏移严格为 `0..length-1`，字节序列与对应 M03 artifact 完全一致。

## M06 字段与长度关系结果

| 样本与 M04 参数 | 列分类摘要 | 统计区间/边界 | 长度关系 | 解释 |
|---|---|---:|---|---|
| Audiobeat，`eps=0.11` | 901 fixed、48 variable、6 optional fixed | 79 / 75 | 0 | 高度固定；全体消息同长，严格规则不报告长度字段 |
| WatchPAT，默认 `eps=0.25` | 144 fixed、239 variable、180 optional variable、238 sparse | 402 / 401 | 4 | 偏移 0 的 `u32le` 精确等于字段后剩余长度；偏移 20 有重复值；2/4 字节宽度均可能成立 |
| WatchPAT，探索 `eps=0.11` | 763 fixed、1343 variable、114 optional variable、46 optional fixed、133 sparse | 883 / 879 | 0 | 分簇后内部长度变化不足，无法满足严格关系条件；高碎片率不应解释为 883 个真实字段 |

真实回归明确断言 WatchPAT 15 条消息均满足偏移 0 的 4 字节小端 payload-length 关系；Audiobeat 各簇没有长度假设。

## 重跑命令

```powershell
$base = 'tmp\validation\20260908-real-dat'

python experiments\M01\run.py data\external\raw\audiobeat-octapro\dsp_m2.dat --output-dir "$base\audiobeat-m01"
python experiments\M02\run.py data\external\raw\audiobeat-octapro\dsp_m2.dat --output-dir "$base\audiobeat-m02" --window-size 238 --window-step 238
python experiments\M03\run.py data\external\raw\audiobeat-octapro\dsp_m2.dat --output-dir "$base\audiobeat-m03" --rule fixed --start-offset 5 --frame-size 238

python experiments\M01\run.py data\external\raw\watchpat\testdata.dat --output-dir "$base\watchpat-m01"
python experiments\M02\run.py data\external\raw\watchpat\testdata.dat --output-dir "$base\watchpat-m02" --window-size 1024 --window-step 1024
python experiments\M03\run.py data\external\raw\watchpat\testdata.dat --output-dir "$base\watchpat-m03" --rule length --length-offset 0 --length-width 4 --byteorder little --length-mode payload --header-size 4 --max-frame-length 2048

python experiments\M04\run.py "$base\audiobeat-m03\framing.json" --output-dir "$base\audiobeat-m04" --eps 0.11 --min-samples 2 --truth-labels data\ground-truth\m04-audiobeat-channel-pairs.json
python experiments\M04\run.py "$base\watchpat-m03\framing.json" --output-dir "$base\watchpat-m04"

python experiments\M05\run.py "$base\audiobeat-m04\clusters.json" --output-dir "$base\audiobeat-m05"
python experiments\M05\run.py "$base\watchpat-m04\clusters.json" --output-dir "$base\watchpat-m05"

python experiments\M04\run.py "$base\watchpat-m03\framing.json" --output-dir "$base\watchpat-m04-eps011" --eps 0.11
python experiments\M05\run.py "$base\watchpat-m04-eps011\clusters.json" --output-dir "$base\watchpat-m05-eps011"

python experiments\M06\run.py "$base\audiobeat-m05\alignments.json" --output-dir "$base\audiobeat-m06"
python experiments\M06\run.py "$base\watchpat-m05\alignments.json" --output-dir "$base\watchpat-m06"
python experiments\M06\run.py "$base\watchpat-m05-eps011\alignments.json" --output-dir "$base\watchpat-m06-eps011"
```

输出目录必须不存在；复测前使用新的验证目录名，不覆盖旧结果。

自动回归入口为 `python -m unittest discover -s experiments\tests -v`；测试会重新读取 manifest 与真实 DAT，不依赖上述临时输出目录。

Audiobeat 标签文件表达上游格式说明支持的相邻双通道结构，仅用于参数探索和指标复现；它不是独立人工标注的课程真值。
