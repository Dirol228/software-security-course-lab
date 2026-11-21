"""Власні тести варіанта 19 (M1 + D3, аномалії А4 і А2)."""
from datetime import datetime, timedelta

import pytest  # у середовищі курсу pytest є (requirements.txt)

from accesscontrol.monitor import Permission, ReferenceMonitor, subjects_with_access
from mydetector import VariantDetector
from mypolicy import SUBJECTS, VariantPolicy, build_demo_policy, objects_accessible_by

R, W, D = Permission.READ, Permission.WRITE, Permission.DELETE


class FakeLog:
    """Мінімальний журнал: детектору потрібен лише метод entries()."""
    def __init__(self, entries):
        self._e = entries

    def entries(self):
        return list(self._e)


def entry(ts, subject="alice", action=R, allowed=True, obj="doc1"):
    return {"ts": ts, "subject": subject, "object": obj, "action": action,
            "allowed": allowed, "reason": ""}


# ---------- крок 2–3: ACL, успадкування, безпечні значення ----------
def test_inheritance_from_directory():
    p = build_demo_policy()
    assert p.evaluate("alice", "hr/doc2", W).allowed          # право на каталог hr діє на файл
    assert p.evaluate("alice", "hr", D).allowed


def test_inheritance_can_be_blocked():
    p = build_demo_policy()
    assert p.evaluate("alice", "hr/doc6", R).allowed          # явний запис на файлі
    assert not p.evaluate("alice", "hr/doc6", W).allowed      # успадкований ADMIN більше не діє


def test_default_deny():
    p = build_demo_policy()
    assert not p.evaluate("frank", "hr/doc2", R).allowed      # немає запису
    assert not p.evaluate("nobody", "hr/doc1", R).allowed     # невідомий суб'єкт
    assert not p.evaluate("alice", "ghost", R).allowed        # невідомий об'єкт
    assert not p.evaluate("alice", "hr", Permission.NONE).allowed


def test_rights_are_exact_not_broader():
    p = build_demo_policy()
    assert p.evaluate("frank", "hr/doc1", R).allowed
    assert not p.evaluate("frank", "hr/doc1", W).allowed
    assert not p.evaluate("frank", "hr/doc1", R | W).allowed  # частково наданий набір не проходить


# ---------- додаткове правило D3: делегування з обмеженням глибини ----------
def test_delegation_chain_within_limit():
    p = build_demo_policy()
    assert p.delegation_depth("heidi", "eng/doc3", R) == 1
    assert p.delegation_depth("ivan", "eng/doc3", R) == 2
    d = p.evaluate("ivan", "eng/doc3", R)
    assert d.allowed and "делегування" in d.reason


def test_delegation_depth_limit_blocks_third_step():
    p = build_demo_policy()
    with pytest.raises(PermissionError, match="глибину"):
        p.delegate("ivan", "judy", "eng", R)                  # це був би 3-й крок
    assert not p.evaluate("judy", "eng/doc3", R).allowed


def test_cannot_delegate_more_than_held():
    p = build_demo_policy()
    with pytest.raises(PermissionError):
        p.delegate("ivan", "judy", "eng", W)                  # у ivan є лише READ
    with pytest.raises(PermissionError):
        p.delegate("heidi", "judy", "eng", D)                 # DELETE heidi не отримала
    assert not p.evaluate("ivan", "eng/doc3", W).allowed


def test_revoke_cascades_through_delegations():
    p = build_demo_policy()
    p.revoke("dave", "eng", Permission.ADMIN)
    assert not p.evaluate("heidi", "eng/doc3", R).allowed
    assert not p.evaluate("ivan", "eng/doc3", R).allowed


def test_delegation_changes_decision_vs_base_acl():
    p = build_demo_policy()
    assert p.delegation_depth("ivan", "eng/doc3", R) == 2     # лише через делегування
    assert p._rights("ivan", "eng/doc3", 0) == Permission.NONE  # у «чистому» ACL прав немає


# ---------- крок 4: монітор ----------
def test_monitor_logs_every_request():
    mon = ReferenceMonitor(build_demo_policy())
    calls = [("alice", "hr/doc1", R), ("bob", "hr/doc1", W), ("ivan", "eng/doc1", R),
             ("judy", "eng/doc1", R), ("carol", "pub/doc2", R)]
    for c in calls:
        mon.check(*c)
    assert len(mon.audit.entries()) == len(calls)
    assert [e["allowed"] for e in mon.audit.entries()] == [True, False, True, False, True]


def test_enforce_raises_and_logs_denial():
    mon = ReferenceMonitor(build_demo_policy())
    with pytest.raises(PermissionError):
        mon.enforce("bob", "hr/doc1", W)
    assert len(mon.audit.entries()) == 1 and mon.audit.entries()[0]["allowed"] is False


def test_operation_log_records_only_state_changes():
    p = VariantPolicy(clock=lambda: 0.0)
    p.add_object("a"); p.add_object("a/x")
    p.grant("alice", "a", R)
    n = len(p.operations())
    p.evaluate("alice", "a/x", R)                             # читання стану — не зміна
    with pytest.raises(PermissionError):
        p.delegate("bob", "carol", "a", R)                    # невдала спроба — не зміна
    assert len(p.operations()) == n
    assert [o["op"] for o in p.operations()] == ["add_object", "add_object", "grant"]


# ---------- крок 7: двоїсті запити ----------
def test_who_and_what_queries_are_consistent():
    p = build_demo_policy()
    objs = p.objects()
    assert len(SUBJECTS) == 10 and len(objs) == 28
    for action in (R, W, D):
        for o in objs:
            who = set(subjects_with_access(p, SUBJECTS, o, action))
            for s in SUBJECTS:
                assert (s in who) == (o in objects_accessible_by(p, s, objs, action))


# ---------- крок 5: детектор ----------
def test_a2_off_hours_fires():
    ts = [datetime(2026, 10, 20, 2, m) for m in (5, 15, 40)]
    alerts = VariantDetector().scan(FakeLog([entry(t, "bob") for t in ts]))
    assert len(alerts) == 1 and alerts[0].startswith("А2") and "bob" in alerts[0]


def test_a2_clean_and_threshold():
    day = [entry(datetime(2026, 10, 20, 10, m)) for m in range(0, 50, 10)]
    night2 = [entry(datetime(2026, 10, 20, 23, m), "bob") for m in (1, 2)]   # 2 < порогу 3
    assert VariantDetector().scan(FakeLog(day + night2)) == []
    assert VariantDetector(min_offhours=2).scan(FakeLog(day + night2))      # поріг — параметр


def test_a2_window_boundaries():
    d = VariantDetector(work_start=8, work_end=20, min_offhours=1)
    assert d.scan(FakeLog([entry(datetime(2026, 10, 20, 8, 0))])) == []       # 08:00 — всередині
    assert d.scan(FakeLog([entry(datetime(2026, 10, 20, 20, 0))]))            # 20:00 — поза вікном


def test_a4_read_burst_fires():
    base = datetime(2026, 10, 20, 9, 0)
    normal = [entry(base + timedelta(hours=h, minutes=1), "carol") for h in range(4)]  # 1/год
    burst = [entry(base + timedelta(hours=4, minutes=i), "carol") for i in range(25)]  # 25/год
    alerts = VariantDetector().scan(FakeLog(normal + burst))
    assert len(alerts) == 1 and alerts[0].startswith("А4") and "carol" in alerts[0]


def test_a4_steady_high_volume_and_denied_reads_do_not_fire():
    base = datetime(2026, 10, 20, 9, 0)
    steady = [entry(base + timedelta(hours=h, minutes=i), "dave") for h in range(4) for i in range(12)]
    denied = [entry(base + timedelta(hours=5, minutes=i), "erin", allowed=False) for i in range(30)]
    assert VariantDetector().scan(FakeLog(steady + denied)) == []


def test_both_anomalies_two_alerts_and_clean_log_empty():
    base = datetime(2026, 10, 20, 9, 0)
    log = ([entry(base + timedelta(hours=h, minutes=1), "carol") for h in range(4)]
           + [entry(base + timedelta(hours=4, minutes=i), "carol") for i in range(25)]
           + [entry(datetime(2026, 10, 21, 3, m), "bob") for m in (1, 2, 3)])
    alerts = VariantDetector().scan(FakeLog(log))
    assert len(alerts) == 2 and {a[:2] for a in alerts} == {"А4", "А2"}
    assert VariantDetector().scan(FakeLog([])) == []


def test_detector_works_with_real_audit_log():
    mon = ReferenceMonitor(build_demo_policy())
    for _ in range(3):
        mon.check("carol", "pub/doc1", R)
    VariantDetector(min_offhours=10**6).scan(mon.audit)       # не падає на реальному журналі
