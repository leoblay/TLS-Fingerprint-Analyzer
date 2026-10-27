"""Comparison helpers for recorded, server-side ClientHello captures."""

from __future__ import annotations

from collections import Counter


def _difference(left: list[int], right: list[int]) -> dict:
    return {"only_selenium": [item for item in left if item not in right], "only_requests": [item for item in right if item not in left]}


def summarize(records: list[dict]) -> dict:
    groups = {name: sorted((item for item in records if item.get("client") == name and item.get("status") == "completed"), key=lambda item: item.get("run") or 0) for name in ("selenium", "requests")}
    summary = {"records": groups, "clients": {}}
    all_completed = [item for items in groups.values() for item in items]
    summary["loopback_peer_only"] = all(item.get("peer", "").startswith("127.0.0.1:") for item in all_completed) if all_completed else None
    for name, items in groups.items():
        ja3_values = [item["ja3_md5"] for item in items]
        normalized_values = [item["normalized_comparison_md5"] for item in items]
        summary["clients"][name] = {
            "count": len(items),
            "ja3_hashes": dict(Counter(ja3_values)),
            "normalized_hashes": dict(Counter(normalized_values)),
            "consistent_ja3": len(set(ja3_values)) <= 1 if items else None,
            "consistent_normalized": len(set(normalized_values)) <= 1 if items else None,
        }

    selenium = groups["selenium"][0] if groups["selenium"] else None
    requests = groups["requests"][0] if groups["requests"] else None
    if selenium and requests:
        same_ja3 = selenium["ja3_md5"] == requests["ja3_md5"]
        summary["comparison"] = {
            "available": True,
            "same_ja3": same_ja3,
            "verdict": "구별 불가" if same_ja3 else "TLS ClientHello 차이 관찰",
            "cipher_suites": _difference(selenium["cipher_suites_without_grease"], requests["cipher_suites_without_grease"]),
            "extensions": _difference(selenium["extensions_without_grease"], requests["extensions_without_grease"]),
            "supported_groups": _difference(selenium["supported_groups_without_grease"], requests["supported_groups_without_grease"]),
            "extension_order_equal": selenium["extensions_without_grease"] == requests["extensions_without_grease"],
        }
    else:
        summary["comparison"] = {"available": False, "verdict": "비교 대기 중"}
    return summary

