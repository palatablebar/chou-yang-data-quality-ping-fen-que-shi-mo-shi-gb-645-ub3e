"""共享面脱敏：受保护列的确定性假名化。

裁决（与 docs/DATA-DICTIONARY.md 第 10 节同源）：
- 保护 `config.PROTECTED_COLUMNS`（工单号 / 客户编号 / 客服姓名）的**取值**，
  不擦列、不动状态：缺失仍是缺失，格式不合格仍带原因码；
- 令牌 = HMAC-SHA256(pepper, 政策版本 ∥ 列名 ∥ 原值) 截断，同值同牌——
  重复分组、同键冲突、高频取值的「相同 / 不同」关系完整保留，身份不可反推；
- 小定义域标识（3-8 位客户号、规则化工单号）可枚举，必须带钥哈希；
  胡椒只存在于服务端环境变量，不进快照、不进导出；
- 应用边界只有一个：M6 装配运行快照时。页面、API、七种导出全部读同一
  脱敏快照，因此报告与导出天然同步；原始字节留在内部 datasets 存储，
  审计凭「行号 + 令牌」回查。
"""
from __future__ import annotations

import hashlib
import hmac

from . import config
from .modules.m1_ingest import sniff
from .modules.m4_duplicates.keydup import EMPTY_KEY_LABEL

QUARANTINE_RAW_LIMIT = 300


def token(column: str, raw: str, pepper: str) -> str:
    """单列取值 → 展示令牌，如 `工单#9f3c2a1b04`。确定性：同政策同值同牌。"""
    message = f"{config.PROTECT_VERSION}\0{column}\0{raw}".encode("utf-8")
    digest = hmac.new(pepper.encode("utf-8"), message, hashlib.sha256).hexdigest()
    prefix = config.PROTECT_PREFIX.get(column, "id")
    return f"{prefix}#{digest[:config.PROTECT_TOKEN_HEX]}"


def mask_value(column: str, raw: str | None, pepper: str) -> str:
    """缺失保持缺失（空串不换令牌），其余受保护取值换令牌。"""
    if raw is None or raw == "":
        return ""
    return token(column, raw, pepper)


def mask_key(key: str, pepper: str) -> str:
    """业务键展示值：空键保留（缺失证据），格式不合格保留 `!` 前缀。"""
    column = config.BUSINESS_KEYS[0]
    if key == EMPTY_KEY_LABEL:
        return key
    if key.startswith("!"):
        return "!" + token(column, key[1:], pepper)
    return token(column, key, pepper)


def apply(result: dict, pepper: str) -> dict:
    """把运行快照里所有受保护取值就地换成令牌；数值、行号、原因码不动。"""
    dataset = result.get("dataset", {})
    positions = _protected_positions(dataset.get("header", {}).get("cells", []))
    for item in dataset.get("quarantine", []):
        cells = item.pop("cells", None)
        if cells is None:  # 兼容没有 cells 的旧装配
            cells = str(item.get("raw_value", "")).split(",")
        item["raw_value"] = _mask_row(cells, positions, pepper)

    profile = result.get("profile", {})
    for column in profile.get("profile", []):
        if column.get("name") in config.PROTECTED_COLUMNS:
            for top in column.get("top", []):
                top["value"] = mask_value(column["name"], top["value"], pepper)

    duplicates = result.get("duplicates", {})
    for item in duplicates.get("key_repeats", []):
        item["key"] = mask_key(item["key"], pepper)
    for item in duplicates.get("conflicts", []):
        item["key"] = mask_key(item["key"], pepper)
        for row in item.get("rows", []):
            column = row.get("column")
            if column in config.PROTECTED_COLUMNS:
                for entry in row.get("entries", []):
                    entry["raw"] = mask_value(column, entry.get("raw"), pepper)
    return result


def policy_parts(pepper: str) -> list[str]:
    """参与规则摘要的保护政策：改任何一项，同输入都必须重算。"""
    return [
        f"protect={config.PROTECT_VERSION}",
        "columns=" + ",".join(config.PROTECTED_COLUMNS),
        f"token_hex={config.PROTECT_TOKEN_HEX}",
        f"pepper_id={pepper_id(pepper)}",
    ]


def policy_summary(pepper: str) -> dict:
    """写进运行清单的自描述：审计能验证政策，却拿不到胡椒本身。"""
    return {
        "policy": config.PROTECT_VERSION,
        "columns": list(config.PROTECTED_COLUMNS),
        "column_labels": [config.COLUMN_MAP[name].label
                          for name in config.PROTECTED_COLUMNS],
        "token": f"HMAC-SHA256 截断 {config.PROTECT_TOKEN_HEX} 位，同值同牌",
        "pepper_id": pepper_id(pepper),
        "kept": "行号 / 原因码 / 三态 / 计数 / 令牌相等性 / 全行哈希",
        "raw": "原始值只留在内部数据集存储，不进共享快照",
    }


def pepper_id(pepper: str) -> str:
    """胡椒指纹：清单里只放指纹，轮换胡椒即换指纹并触发重算。"""
    return hashlib.sha256(pepper.encode("utf-8")).hexdigest()[:8]


def _protected_positions(header_cells: list[str]) -> dict[int, str]:
    """表头位置 → 受保护列名；复用 M1 的别名映射，位置判定与采信同源。"""
    if not header_cells:
        return {}
    indexes = sniff.map_header(list(header_cells)).indexes
    return {index: name for name, index in indexes.items()
            if name in config.PROTECTED_COLUMNS}


def _mask_row(cells: list[str], positions: dict[int, str], pepper: str) -> str:
    masked = []
    for index, cell in enumerate(cells):
        column = positions.get(index)
        if column is not None and str(cell).strip():
            masked.append(token(column, str(cell), pepper))
        else:
            masked.append(str(cell))
    return ",".join(masked)[:QUARANTINE_RAW_LIMIT]
