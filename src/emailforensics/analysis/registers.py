from __future__ import annotations

from emailforensics.analysis.config import Decision, Person
from emailforensics.case import Case
from emailforensics.store import db


def save_people(case: Case, people: list[Person]) -> int:
    custodians = [p.id for p in people if p.custodian]
    if len(custodians) > 1:
        raise ValueError(f"more than one custodian: {', '.join(custodians)}")
    with db.connect(case.dsn) as conn:
        db.migrate(conn)
        with conn.transaction():
            conn.execute("DELETE FROM person_address")
            conn.execute("DELETE FROM person")
            for p in people:
                conn.execute(
                    "INSERT INTO person (id, name, names, base, role, board, custodian) VALUES (%s,%s,%s,%s,%s,%s,%s)",
                    (p.id, p.name, p.names, p.base, p.role, p.board, p.custodian),
                )
                for a in p.addresses:
                    conn.execute(
                        "INSERT INTO person_address (address, person_id) VALUES (%s, %s)"
                        " ON CONFLICT (address) DO NOTHING",
                        (a, p.id),
                    )
    return len(people)


def save_decisions(case: Case, decisions: list[Decision]) -> int:
    with db.connect(case.dsn) as conn:
        db.migrate(conn)
        with conn.transaction():
            conn.execute("DELETE FROM decision_message")
            conn.execute("DELETE FROM decision")
            for d in decisions:
                conn.execute(
                    "INSERT INTO decision (id, title, formal_date, formal_place, formal_country, source, terms,"
                    " window_start, window_end) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                    (d.id, d.title, d.formal_date, d.formal_place, d.formal_country, d.source, d.terms,
                     d.window_start, d.window_end),
                )
    return len(decisions)
