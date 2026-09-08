# M11 行为类型分类

状态：已调研。检索日期：2026-09-07；仅资料比较，未安装、训练或测试。

用途：在标签定义明确时，将流级统计映射到已知行为类别，并保留无法判断的情况。

| 候选 | 主要特点与优势 | 输入输出及前置条件 | 限制 | 来源 |
|---|---|---|---|---|
| Random Forest | 树集成适合表格特征，支持类别权重；适合作为初始基线 | 带标签的固定维流特征 → 类别与预测分数 | 需要训练数据；特征重要性不等于因果解释；分数需评估校准 | [官方 API](https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.RandomForestClassifier.html) |
| XGBoost | 梯度提升树，支持分类和验证集 early stopping | 对齐的特征、标签及验证集 → 模型和分类输出 | 参数及训练管理更复杂；不能无标签直接获得行为语义；无本地优于 RF 的证据 | [官方入门](https://xgboost.readthedocs.io/en/stable/python/python_intro.html) |
| SVM / SVC | 核方法适合中小规模特征分类 | 缩放后的特征及标签 → 类别/决策分数 | 核与 C 等需选择；核 SVC 训练复杂度至少二次级，不适合大量样本；决策分数不是概率 | [官方 API](https://scikit-learn.org/stable/modules/generated/sklearn.svm.SVC.html) |

初步建议：RF 作为后续有标签条件下的首选基线，XGBoost 作比较候选，SVM 仅在样本规模合适时考虑；此推荐是实现复杂度与数据形态的判断，不是性能排名。

可用的数据集与论文线索：UNB 的 ISCXVPN2016 提供抓包及流 CSV，包含浏览、邮件、聊天、流媒体、文件传输、VoIP、P2P，并提供业务类别及 VPN/非 VPN 两个标签维度；本项目应分别定义和评测业务分类与 VPN 状态分类，不把二者混成单一任务。关联论文是 Gil 等的 “Characterization of Encrypted and VPN Traffic Using Time-Related Features”（ICISSP 2016）。官方页面说明采集环境和研究使用引用条件：[数据集与论文入口](https://www.unb.ca/cic/datasets/vpn.html)。该资料支持时间特征分类路线，不证明上述三个候选在本项目上的效果。

公开集应用与年代可能不代表真实 DAT；VPN 标签和业务标签也不能混为同一概念。包级标签、流级标签与任务级标签应明确映射；M4 的无监督簇号不能直接充当业务真值。后续训练需按采集会话/时间或主机分组隔离，避免相邻流泄漏；预处理只在训练部分拟合，参见 [官方数据泄漏说明](https://scikit-learn.org/stable/common_pitfalls.html)。

待核实：目标类别、真实标签及元数据、特征口径和领域偏移。没有标签就保留 M10 的模式描述，不给虚构分类准确率；未知业务拒识需要额外阈值/校准设计，三种分类器均不能默认解决开放集问题。
