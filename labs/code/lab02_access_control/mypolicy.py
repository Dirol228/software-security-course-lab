"""Варіант 19: M1 — ACL з успадкуванням, D3 — делегування прав з обмеженням глибини.

Об'єкти утворюють дерево шляхів («hr», «hr/doc1»). ACL зберігається за стовпцями матриці
(для кожного об'єкта — «суб'єкт -> права»); права, надані на каталог, успадковуються нащадками,
якщо успадкування не вимкнено. Суб'єкт може делегувати іншому підмножину своїх прав,
але ланцюг делегування не довший за max_depth кроків.
"""
from __future__ import annotations

import time
from typing import Callable

from accesscontrol.monitor import Decision, Permission, Policy

MAX_DELEGATION_DEPTH = 2


class VariantPolicy(Policy):
    def __init__(self, max_depth: int = MAX_DELEGATION_DEPTH,
                 clock: Callable[[], float] = time.time) -> None:
        self._max_depth = max_depth
        self._clock = clock
        self._parent: dict[str, str | None] = {}                # дерево об'єктів
        self._inherit: dict[str, bool] = {}                     # чи успадковує об'єкт права батька
        self._acl: dict[str, dict[str, Permission]] = {}        # об'єкт -> {суб'єкт -> права}
        self._deleg: list[tuple[str, str, str, Permission]] = []  # (від кого, кому, об'єкт, права)
        self._oplog: list[dict] = []                            # операційний журнал

    # ---------- зміна стану (кожна успішна зміна потрапляє в операційний журнал) ----------
    def _log(self, op: str, **kw) -> None:
        self._oplog.append({"ts": self._clock(), "op": op, **kw})

    def operations(self) -> list[dict]:
        return [dict(e) for e in self._oplog]

    def add_object(self, obj: str, inherit: bool = True) -> None:
        if obj in self._parent:
            raise ValueError(f"об'єкт {obj} уже існує")
        parent = obj.rpartition("/")[0] or None
        if parent is not None and parent not in self._parent:
            raise KeyError(f"батьківський об'єкт {parent} не існує")
        self._parent[obj], self._inherit[obj], self._acl[obj] = parent, inherit, {}
        self._log("add_object", obj=obj, inherit=inherit)

    def objects(self) -> list[str]:
        return list(self._parent)

    def set_inherit(self, obj: str, inherit: bool) -> None:
        self._require(obj)
        self._inherit[obj] = inherit
        self._log("set_inherit", obj=obj, inherit=inherit)

    def grant(self, who: str, obj: str, perm: Permission) -> None:
        self._require(obj)
        self._acl[obj][who] = self._acl[obj].get(who, Permission.NONE) | perm
        self._log("grant", who=who, obj=obj, perm=perm.name)

    def revoke(self, who: str, obj: str, perm: Permission = Permission.ADMIN) -> None:
        self._require(obj)
        left = self._acl[obj].get(who, Permission.NONE) & ~perm
        if left == Permission.NONE:
            self._acl[obj].pop(who, None)
        else:
            self._acl[obj][who] = left
        self._prune_delegations()
        self._log("revoke", who=who, obj=obj, perm=perm.name)

    def delegate(self, frm: str, to: str, obj: str, perm: Permission) -> None:
        """Делегування: frm передає to підмножину своїх прав; глибина ланцюга ≤ max_depth."""
        self._require(obj)
        if perm == Permission.NONE or frm == to:
            raise ValueError("порожні права або делегування самому собі")
        if perm & self._rights(frm, obj, self._max_depth - 1) != perm:
            if perm & self._rights(frm, obj, self._max_depth) == perm:
                raise PermissionError(f"перевищено глибину делегування ({self._max_depth})")
            raise PermissionError("не можна делегувати права, яких немає")
        self._deleg.append((frm, to, obj, perm))
        self._log("delegate", frm=frm, to=to, obj=obj, perm=perm.name)

    def _prune_delegations(self) -> None:
        """Після відкликання прибрати делегування, що втратили основу (каскад)."""
        changed = True
        while changed:
            changed = False
            kept = []
            for frm, to, obj, perm in self._deleg:
                still = perm & self._rights(frm, obj, self._max_depth - 1)
                if still != perm:
                    changed = True
                if still != Permission.NONE:
                    kept.append((frm, to, obj, still))
            self._deleg = kept

    # ---------- обчислення прав ----------
    def _require(self, obj: str) -> None:
        if obj not in self._parent:
            raise KeyError(f"невідомий об'єкт {obj}")

    def _chain(self, obj: str) -> list[str]:
        """Об'єкт і предки, з яких він успадковує права (до першого вимкненого успадкування)."""
        chain, node = [], obj
        while node is not None:
            chain.append(node)
            node = self._parent[node] if self._inherit[node] else None
        return chain

    def _rights(self, subject: str, obj: str, k: int) -> Permission:
        """Права суб'єкта на об'єкт при ланцюгах делегування довжиною ≤ k (k=0 — лише ACL)."""
        chain = self._chain(obj)
        rights = Permission.NONE
        for node in chain:
            rights |= self._acl[node].get(subject, Permission.NONE)
        if k > 0:
            for frm, to, dobj, perm in self._deleg:
                if to == subject and dobj in chain:
                    rights |= perm & self._rights(frm, dobj, k - 1)
        return rights

    def delegation_depth(self, subject: str, obj: str, action: Permission) -> int | None:
        for k in range(self._max_depth + 1):
            if action & self._rights(subject, obj, k) == action:
                return k
        return None

    def evaluate(self, subject: str, obj: str, action: Permission) -> Decision:
        if obj not in self._parent:
            return Decision(False, "невідомий об'єкт (safe default)")
        if action == Permission.NONE:
            return Decision(False, "порожня дія (safe default)")
        k = self.delegation_depth(subject, obj, action)
        if k == 0:
            return Decision(True, "надано (ACL, з урахуванням успадкування)")
        if k is not None:
            return Decision(True, f"надано (делегування, глибина {k})")
        # Правило безпечних значень за замовчуванням
        return Decision(False, "явного дозволу немає (safe default)")


def objects_accessible_by(policy, subject, objects, action):
    return [o for o in objects if policy.evaluate(subject, o, action).allowed]


SUBJECTS = ["alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi", "ivan", "judy"]  # 10


def build_demo_policy(clock: Callable[[], float] = time.time) -> VariantPolicy:
    """10 суб'єктів, 28 об'єктів (4 каталоги + 4×6 файлів); усі імена вигадані."""
    p = VariantPolicy(clock=clock)
    for d in ("hr", "fin", "eng", "pub"):
        p.add_object(d)
        for i in range(1, 7):
            p.add_object(f"{d}/doc{i}")
    p.grant("alice", "hr", Permission.ADMIN)
    p.set_inherit("hr/doc6", False)                    # розрив успадкування
    p.grant("alice", "hr/doc6", Permission.READ)
    p.grant("bob", "fin", Permission.READ | Permission.WRITE)
    p.grant("carol", "pub", Permission.READ)
    p.grant("carol", "fin/doc3", Permission.READ)
    p.grant("dave", "eng", Permission.ADMIN)
    p.grant("erin", "eng", Permission.READ)
    p.grant("frank", "hr/doc1", Permission.READ)
    p.grant("grace", "pub", Permission.READ)
    p.delegate("dave", "heidi", "eng", Permission.READ | Permission.WRITE)   # глибина 1
    p.delegate("heidi", "ivan", "eng", Permission.READ)                      # глибина 2
    return p
