from datetime import datetime, timedelta
from accesscontrol.monitor import Permission as P, ReferenceMonitor, subjects_with_access
from mydetector import VariantDetector
from mypolicy import SUBJECTS, build_demo_policy, objects_accessible_by

p = build_demo_policy()
mon = ReferenceMonitor(p)
R, W, D = P.READ, P.WRITE, P.DELETE

print("== Таблиця очікуваних і фактичних рішень ==")
cases = [("alice", "hr/doc2", W, True), ("alice", "hr/doc6", R, True), ("alice", "hr/doc6", W, False),
         ("frank", "hr/doc1", R, True), ("frank", "hr/doc2", R, False),
         ("carol", "fin/doc3", R, True), ("carol", "fin/doc4", R, False),
         ("heidi", "eng/doc4", W, True), ("heidi", "eng/doc4", D, False),
         ("ivan", "eng/doc3", R, True), ("ivan", "eng/doc3", W, False)]
for s, o, a, exp in cases:
    d = mon.check(s, o, a)
    print(f"{s:6} {o:9} {a.name:6} очік={'так' if exp else 'ні':3} факт={'так' if d.allowed else 'ні':3} "
          f"{'OK' if d.allowed == exp else 'ПОМИЛКА'}  {d.reason}")
try:
    p.delegate("ivan", "judy", "eng", R)
except PermissionError as e:
    print("delegate ivan->judy:", e)
d = mon.check("judy", "eng/doc3", R); print("judy eng/doc3 READ:", d.allowed, d.reason)

print("\n== Реєстраційний журнал: записів", len(mon.audit.entries()), "== звернень", len(cases) + 1)
print("\n== Операційний журнал (зміни стану) — перші/останні записи ==")
ops = p.operations(); print(len(ops), "записів;", [o["op"] for o in ops[-4:]])

print("\n== Запити ==")
objs = p.objects()
print("хто читає eng/doc3:", subjects_with_access(p, SUBJECTS, "eng/doc3", R))
print("що читає ivan:", objects_accessible_by(p, "ivan", objs, R))
print("що читає alice:", objects_accessible_by(p, "alice", objs, R))

class L:
    def __init__(s, e): s.e = e
    def entries(s): return s.e
def e(ts, sub, ok=True): return {"ts": ts, "subject": sub, "object": "pub/doc1", "action": R, "allowed": ok, "reason": ""}
b = datetime(2026, 10, 20, 9, 0)
log = ([e(b + timedelta(hours=h, minutes=1), "carol") for h in range(4)]
       + [e(b + timedelta(hours=4, minutes=i), "carol") for i in range(25)]
       + [e(datetime(2026, 10, 21, 3, m), "bob") for m in (5, 20, 40)])
print("\n== Детектор ==")
for a in VariantDetector().scan(L(log)): print(a)
clean = [e(b + timedelta(hours=h, minutes=1), "carol") for h in range(4)]
print("чистий журнал:", VariantDetector().scan(L(clean)))
