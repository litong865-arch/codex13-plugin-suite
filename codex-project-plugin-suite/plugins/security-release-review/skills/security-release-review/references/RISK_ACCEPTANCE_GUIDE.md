# Risk Acceptance Guide

风险接受不是跳过修复。

默认只允许接受 `medium/low`。

每条接受记录必须包含：

- finding fingerprint
- owner
- expiry date
- compensating control
- review date
- approval evidence

`critical/high` 或 `blocks_release=true` 默认不允许接受，必须修复后 retest。
