"""共享面保护裁决的落地验证：

- 受保护列（工单号 / 客户号 / 受理人）的取值不出现在任何共享面；
- 审计线索（行号、原因码、计数、令牌相等性、空键）完整保留；
- 保护政策进输入摘要：政策变 → 同输入重算新版本；政策不变 → 幂等复用；
- 落库单事务：中断保留上一完整版本；同批重试不重复计分、不叠加版本。
"""
from __future__ import annotations

import json

import pytest

from app import config, protect, store as store_mod
from app.modules.m6_score import service as score_service
from app.store import Store
from fixtures import dirty_cases, expected

PEPPER = config.MASK_PEPPER_DEFAULT
SAMPLE_DIR = config.PROJECT_ROOT / "sample_data"

# 脏样例里出现过的受保护原值：任何一个出现在共享面都是泄露
PROTECTED_RAW = [
    "陈允", "李迟", "王柯", "周砚",                    # 受理人
    "T-2026-000101", "T-2026-000204", "T-2026-000102",  # 工单号
    "1234567890123456789",                              # 19 位大工单号
    "00123", "00155", "00160",                          # 客户号（前导零保形）
]

PAGES = ("/", "/profile", "/missing", "/duplicates", "/outliers", "/batches")
EXPORTS = ("report.csv", "profile.csv", "missing.csv", "duplicates.csv",
           "outliers.csv", "quarantine.csv", "flags.csv", "manifest.json")
APIS = ("/api/profile", "/api/missing", "/api/duplicates", "/api/outliers",
        "/api/reconcile", "/api/score/latest")


def tok(column: str, raw: str) -> str:
    return protect.token(column, raw, PEPPER)


# ---------- 令牌本身 ----------

def test_token_format_determinism_and_isolation():
    token = protect.token("customer_id", "00123", "pepper-x")
    assert token.startswith("客户#")
    assert len(token.split("#", 1)[1]) == config.PROTECT_TOKEN_HEX
    assert token == protect.token("customer_id", "00123", "pepper-x")   # 同值同牌
    assert token != protect.token("customer_id", "00124", "pepper-x")   # 异值异牌
    assert token != protect.token("customer_id", "00123", "pepper-y")   # 换钥全换
    assert token != protect.token("ticket_id", "00123", "pepper-x")     # 列间隔离


def test_missing_and_bad_key_states_not_tokenized():
    assert protect.mask_value("agent", "", "p") == ""        # 缺失仍是缺失
    assert protect.mask_value("agent", None, "p") == ""
    assert protect.mask_key("空键", "p") == "空键"            # 空键保留，可复核缺失模式
    assert protect.mask_key("!abc", "p").startswith("!")     # 格式不合格标记保留


# ---------- 共享面不泄露 ----------

def test_shared_surfaces_hide_protected_values(client_with_run):
    surfaces = [(page, client_with_run.get(page).text) for page in PAGES]
    surfaces += [(name, client_with_run.get(f"/api/export/{name}").content.decode("utf-8"))
                 for name in EXPORTS]
    surfaces += [(api, client_with_run.get(api).text) for api in APIS]
    run_id = client_with_run.get("/api/score/latest").json()["run"]["run_id"]
    surfaces.append(("/api/runs", client_with_run.get(f"/api/runs/{run_id}").text))
    assert len(surfaces) == len(PAGES) + len(EXPORTS) + len(APIS) + 1
    for surface, text in surfaces:
        for raw in PROTECTED_RAW:
            assert raw not in text, f"{surface} 泄露受保护原值 {raw}"


def test_snapshot_contains_no_protected_raw(dirty_result):
    blob = json.dumps(dirty_result, ensure_ascii=False)
    for raw in PROTECTED_RAW:
        assert raw not in blob, f"运行快照泄露 {raw}"


def test_internal_preview_keeps_raw_for_audit(client_with_run):
    """内部审计面：采信预览仍给原值，审计凭行号回到具体记录。"""
    body = client_with_run.get("/api/datasets/tickets_dirty.csv/rows").json()
    text = json.dumps(body, ensure_ascii=False)
    assert "陈允" in text and "T-2026-000101" in text


# ---------- 审计线索保留 ----------

def test_quarantine_masked_by_position_keeps_audit_trail(dirty_result):
    items = dirty_result["dataset"]["quarantine"]
    assert [(item["lineno"], item["code"]) for item in items] == expected.QUARANTINE
    first = items[0]
    assert first["raw_value"].startswith(tok("ticket_id", "T-2026-000144"))
    assert tok("customer_id", "00162") in first["raw_value"]
    assert "多余列" in first["raw_value"]          # 非保护溢出列原样保留
    assert "cells" not in first                     # 单元格列表不进共享快照


def test_missing_patterns_fully_reviewable(dirty_result):
    missing = dirty_result["missing"]
    assert missing["account"]["cells_total"] == expected.DIRTY["cells_total"]
    assert missing["account"]["missing"] == expected.DIRTY["cells_missing"]
    runs = {item["column"]: (item["start_lineno"], item["end_lineno"], item["length"])
            for item in missing["runs"]}
    assert runs["agent"] == expected.MISSING_RUNS["agent"]
    assert runs["region"] == expected.MISSING_RUNS["region"]
    pairs = {(item["left"], item["right"]): item["count"]
             for item in missing["co_missing"]}
    assert pairs == expected.CO_MISSING


def test_top_values_keep_distribution(settings, dirty_result):
    raw = dirty_cases.pipeline_sample(settings, "tickets_dirty.csv")
    raw_top = next(c for c in raw["profile"]["profile"] if c["name"] == "agent")["top"]
    masked_top = next(c for c in dirty_result["profile"]["profile"]
                      if c["name"] == "agent")["top"]
    assert [item["count"] for item in masked_top] == [item["count"] for item in raw_top]
    assert [item["value"] for item in masked_top] == \
        [tok("agent", item["value"]) for item in raw_top]


def test_conflict_audit_trail_with_tokens(dirty_result):
    conflict = dirty_result["duplicates"]["conflicts"][0]
    assert conflict["key"] == tok("ticket_id", "T-2026-000204")
    assert conflict["linenos"] == [36, 37]                # 行号原样保留
    assert conflict["fields"] == ["satisfaction", "agent"]
    values = {item["column"]: [entry["raw"] for entry in item["entries"]]
              for item in conflict["rows"]}
    assert values["satisfaction"] == ["4", "2"]           # 非保护列仍是原值
    assert values["agent"] == [tok("agent", "王柯"), tok("agent", "李迟")]
    # 跨表面同值同牌：冲突里的客服令牌与高频取值里的令牌是同一套
    top_tokens = {item["value"] for c in dirty_result["profile"]["profile"]
                  if c["name"] == "agent" for item in c["top"]}
    assert set(values["agent"]) <= top_tokens


def test_empty_business_key_stays_visible(settings, store):
    rows = [dirty_cases.make_row(ticket=""), dirty_cases.make_row(ticket=""),
            dirty_cases.make_row(ticket="T-2026-970009")]
    result = dirty_cases.run_text(settings, store, dirty_cases.frame(rows),
                                  name="emptykey.csv")
    assert [item["key"] for item in result["duplicates"]["key_repeats"]] == ["空键"]


def test_manifest_declares_protection_policy(client_with_run):
    payload = json.loads(client_with_run.get("/api/export/manifest.json").content)
    protection = payload["protection"]
    assert protection["policy"] == config.PROTECT_VERSION
    assert protection["columns"] == list(config.PROTECTED_COLUMNS)
    assert protection["pepper_id"] == protect.pepper_id(PEPPER)
    assert PEPPER not in json.dumps(payload)              # 胡椒本身不进共享包


def test_report_page_declares_protection(client_with_run):
    html = client_with_run.get("/").text
    assert "共享面保护" in html
    assert "工单号" in html and "客户号" in html and "受理人" in html


# ---------- 政策更新 → 同步重算 ----------

def _settings(db_path: str, pepper: str) -> config.Settings:
    return config.Settings(db_path=db_path, sample_dir=str(SAMPLE_DIR),
                           mask_pepper=pepper)


def test_startup_recomputes_when_policy_changes(tmp_path):
    """换胡椒重启：启动即同步重算，报告与导出读同一条新快照。"""
    from fastapi.testclient import TestClient

    from app.main import create_app

    db = str(tmp_path / "q.sqlite")
    first_client = TestClient(create_app(_settings(db, "pepper-A")))
    first_client.post("/api/score", json={"sample": "tickets_dirty.csv"})
    token_a = first_client.get("/api/duplicates").json()["conflicts"][0]["key"]
    assert Store(db).count_runs() == 1

    app = create_app(_settings(db, "pepper-B"))
    assert app.state.protection_refreshed == {"refreshed": ["tickets_dirty.csv"],
                                              "failed": []}
    client = TestClient(app)
    token_b = client.get("/api/duplicates").json()["conflicts"][0]["key"]
    assert token_b != token_a                                # 令牌已重算
    assert client.get("/api/batches").json()["runs"][0]["version"] == 2
    export_text = client.get("/api/export/duplicates.csv").content.decode("utf-8")
    assert token_b in export_text and token_a not in export_text  # 导出与报告同步
    manifest = json.loads(client.get("/api/export/manifest.json").content)
    assert manifest["protection"]["pepper_id"] == protect.pepper_id("pepper-B")

    restarted = create_app(_settings(db, "pepper-B"))        # 政策没变 → 不再重算
    assert restarted.state.protection_refreshed == {"refreshed": [], "failed": []}
    assert Store(db).count_runs() == 2


def test_policy_change_forces_recompute(tmp_path):
    db = str(tmp_path / "q.sqlite")
    first = score_service.run(_settings(db, "pepper-A"), Store(db),
                              name="tickets_dirty.csv")
    assert first["run"]["version"] == 1

    second = score_service.run(_settings(db, "pepper-B"), Store(db),
                               name="tickets_dirty.csv")
    assert second["replay"] is False                       # 同输入也重算
    assert second["run"]["version"] == 2                   # 新版本而不是复用
    assert second["run"]["digest"] != first["run"]["digest"]
    assert second["run"]["score"] == first["run"]["score"]  # 分数口径不变
    assert second["manifest"]["rules_digest"] != first["manifest"]["rules_digest"]
    assert (second["duplicates"]["conflicts"][0]["key"]
            != first["duplicates"]["conflicts"][0]["key"])  # 令牌全换
    assert Store(db).count_runs() == 2

    third = score_service.run(_settings(db, "pepper-A"), Store(db),
                              name="tickets_dirty.csv")
    assert third["replay"] is True                         # 回到旧政策 → 复用旧记录
    assert third["run"]["run_id"] == first["run"]["run_id"]
    assert Store(db).count_runs() == 2                     # 不叠加版本


def test_same_batch_retry_never_double_scores(settings, store):
    first = score_service.run(settings, store, name="tickets_dirty.csv")
    for _ in range(3):
        again = score_service.run(settings, store, name="tickets_dirty.csv")
        assert again["replay"] is True
        assert again["run"]["run_id"] == first["run"]["run_id"]
        assert again["run"]["version"] == first["run"]["version"]
        assert again["run"]["score"] == first["run"]["score"]
    assert store.count_runs() == 1
    assert store.latest_version("tickets_dirty.csv") == 1


def test_identity_race_falls_back_to_replay(settings, store, monkeypatch):
    """预检与落库之间被同批抢先：撞幂等键 → 复用已落库记录，不叠加版本。"""
    first = score_service.run(settings, store, name="tickets_dirty.csv")
    monkeypatch.setattr(store, "find_run", lambda *args, **kwargs: None)
    second = score_service.run(settings, store, name="tickets_dirty.csv")
    assert second["replay"] is True
    assert second["run"]["run_id"] == first["run"]["run_id"]
    assert second["run"]["version"] == first["run"]["version"]
    assert store.count_runs() == 1


# ---------- 中断与原子性 ----------

def test_interrupted_run_keeps_last_complete_version(settings, store, monkeypatch):
    first = score_service.run(settings, store, name="tickets_dirty.csv")
    stored_before = store.get_dataset("tickets_dirty.csv")

    def crash(*args, **kwargs):
        raise RuntimeError("模拟落库中途断电")

    monkeypatch.setattr(store, "save_run_bundle", crash)
    changed = dirty_cases.frame(dirty_cases.count_rows(6, agent=""))
    with pytest.raises(RuntimeError):
        score_service.run(settings, store, name="tickets_dirty.csv",
                          data=changed.encode("utf-8"))
    latest = store.latest_run()
    assert latest["run_id"] == first["run"]["run_id"]      # 上一完整版本还在
    assert store.count_runs() == 1
    assert store.get_dataset("tickets_dirty.csv")["digest"] == stored_before["digest"]


def test_bundle_rolls_back_dataset_when_run_insert_fails(store):
    store.save_dataset(name="atomic.csv", digest="d0", encoding="utf-8",
                       declared_encoding=None, data=b"old", stamp="t0")
    run = {"run_id": "QS-T-0001", "name": "atomic.csv", "digest": "d1",
           "rules_version": "v", "version": None, "score": "100.00", "grade": "A",
           "rows_in": 1, "rows_accepted": 1, "rows_unique": 1, "rows_dup": 0,
           "rows_quarantine": 0, "rows_blank": 0, "cells_total": 10,
           "cells_missing": 0, "created_at": "t", "finished_at": "t"}
    summary = {"run": {}, "manifest": {}, "bad": object()}  # 不可序列化 → 插入前失败
    with pytest.raises(TypeError):
        store.save_run_bundle(
            dataset={"name": "atomic.csv", "digest": "d9", "encoding": "utf-8",
                     "declared_encoding": None, "data": b"new", "stamp": "t1"},
            run=run, summary=summary)
    assert store.get_dataset("atomic.csv")["digest"] == "d0"  # 数据集回滚
    assert store.count_runs() == 0                            # 运行记录也没留下


def test_duplicate_identity_raises_run_exists(store):
    dataset = {"name": "dup.csv", "digest": "d0", "encoding": "utf-8",
               "declared_encoding": None, "data": b"x", "stamp": "t"}
    run = {"run_id": "QS-T-0002", "name": "dup.csv", "digest": "d1",
           "rules_version": "v", "version": None, "score": "100.00", "grade": "A",
           "rows_in": 1, "rows_accepted": 1, "rows_unique": 1, "rows_dup": 0,
           "rows_quarantine": 0, "rows_blank": 0, "cells_total": 10,
           "cells_missing": 0, "created_at": "t", "finished_at": "t"}
    store.save_run_bundle(dataset=dataset, run=dict(run),
                          summary={"run": {}, "manifest": {}})
    with pytest.raises(store_mod.RunExists):
        store.save_run_bundle(dataset=dataset, run=dict(run),
                              summary={"run": {}, "manifest": {}})
    assert store.count_runs() == 1
    assert store.latest_version("dup.csv") == 1


def test_version_assigned_inside_persist(settings, store):
    """版本号由落库事务分配：结果对象与库里一致，连续内容得到连续版本。"""
    first = dirty_cases.run_text(settings, store,
                                 dirty_cases.frame(dirty_cases.count_rows(4)),
                                 name="seq.csv")
    second = dirty_cases.run_text(settings, store,
                                  dirty_cases.frame(dirty_cases.count_rows(5)),
                                  name="seq.csv")
    assert first["run"]["version"] == 1
    assert second["run"]["version"] == 2
    assert second["manifest"]["version"] == 2
    persisted = store.latest_run("seq.csv")
    assert persisted["version"] == 2
    assert json.loads(persisted["summary_json"])["run"]["version"] == 2
