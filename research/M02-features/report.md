# M2 二进制基础特征分析

状态：已调研。检索日期：2026-09-07；仅资料比较，未安装或测试。

用途：为字节流、消息及局部窗口建立可解释的基础特征。

| 候选 | 主要特点与优势 | 输入输出及前置条件 | 限制 | 来源 |
|---|---|---|---|---|
| Python 标准库：bytes、Counter、math | 可统计长度、字节次数、比例、熵及重复片段；依赖少 | 原始 bytes → 特征字典及原始偏移；无需网络头或标签 | 是拟组合开发的方案，不是现成协议识别器；大规模窗口统计需控制开销 | [Counter](https://docs.python.org/3/library/collections.html#collections.Counter)、[log2](https://docs.python.org/3/library/math.html#math.log2) |
| NumPy | frombuffer 将缓冲区解释为数组，bincount 统计整数取值，适合批量特征计算 | bytes → uint8 数组 → 256 维频率与窗口特征；需 NumPy | 不能自动推断字段或消息；视图可能共享底层内存，窗口中间结果仍有开销 | [frombuffer](https://numpy.org/doc/stable/reference/generated/numpy.frombuffer.html)、[bincount](https://numpy.org/doc/stable/reference/generated/numpy.bincount.html) |

初步建议：标准库作为基础，批量处理时考虑 NumPy。拟采用以下统计口径：长度按字节计；频率 p(b)=count(b)/N；Shannon 熵 H=-Σp(b)log2p(b)，仅计非零项，范围 0～8 bit/byte；空输入的熵及比例输出“不可计算”。ASCII 可打印比例明确为 0x20～0x7E，换行与制表符另计；零字节比例单列。

重复模式先统计有限长度的字节 n-gram 和连续重复段，保存偏移；重叠计数和窗口长度属于可配置设计。全文件统计可能掩盖局部结构，应同时保留窗口结果。上述口径是本项目建议，不是文档声称已提供的成品能力。

待核实：真实数据长度与窗口尺度。高熵也可能来自压缩或随机数据；短样本熵偏差较大，不能用一个阈值证明加密。
