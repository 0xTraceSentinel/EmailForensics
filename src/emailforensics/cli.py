from __future__ import annotations

import sys
from pathlib import Path
from typing import Annotated, Optional

import typer

from emailforensics.case import Case, create_case

app = typer.Typer(help="Offline POEM analysis of exported mailboxes.", no_args_is_help=True)

INTERRUPTED_EXIT = 3

MinFreeOption = Annotated[
    Optional[int],
    typer.Option(
        "--min-free-mb",
        help="Stop cleanly, keeping progress, if free memory stays below this many MB (default 1024, or "
             "EMAILFORENSICS_MIN_FREE_MB; 0 turns the guard off). Batches shrink below twice this value.",
    ),
]


def _guard(min_free: Optional[int]):
    from emailforensics.memory import Guard, min_free_mb

    return Guard(min_free_mb(min_free), log=lambda s: typer.echo(f"\n{s}", err=True))


def _interrupted(command: str, e: BaseException) -> None:
    import psycopg

    from emailforensics.memory import MemoryPressure

    if isinstance(e, MemoryPressure):
        why = f"stopped to avoid running out of memory: {e}"
    elif isinstance(e, MemoryError):
        why = "ran out of memory"
    elif isinstance(e, psycopg.OperationalError):
        why = f"lost the database connection ({str(e).strip().splitlines()[0] if str(e).strip() else type(e).__name__}); if Docker ran out of memory, raise its limit or close other programs"
    else:
        raise e
    typer.echo(f"\n{command} interrupted: {why}.", err=True)
    typer.echo(f"Progress is saved. Free some memory and run the same `emailforensics {command}` command again to resume.", err=True)
    raise typer.Exit(INTERRUPTED_EXIT)


@app.command(help="Create a case folder and its PostgreSQL database.")
def init(
    case_dir: Annotated[Path, typer.Argument(help="Case folder to create.")],
    name: Annotated[Optional[str], typer.Option(help="Case name (default: folder name).")] = None,
) -> None:
    try:
        case = create_case(case_dir, name)
    except FileExistsError as e:
        typer.echo(f"error: {e}", err=True)
        raise typer.Exit(1)
    typer.echo(f"Created case {case.name!r} in {case.root} (database {case.database})")


@app.command(help="Hash and ingest exported mail into the case. Evidence files are only read.")
def ingest(
    case_dir: Annotated[Path, typer.Argument(help="Case folder created by `init`.")],
    inputs: Annotated[list[str], typer.Argument(help="PST/OST, MSG, EML or MBOX files, folders or glob patterns.")],
    custodian: Annotated[
        Optional[str], typer.Option("--custodian", "-c", help="Whose mailbox these exports come from.")
    ] = None,
    progress: Annotated[
        bool,
        typer.Option(
            "--progress/--no-progress",
            help="Show progress on stderr: a live bar in a terminal, a status line every 15 s when redirected.",
        ),
    ] = True,
    min_free: MinFreeOption = None,
) -> None:
    from emailforensics.console import make_progress
    from emailforensics.ingest.pipeline import ingest_paths

    try:
        case = Case.load(case_dir)
    except FileNotFoundError as e:
        typer.echo(f"error: {e}", err=True)
        raise typer.Exit(1)

    reporter = make_progress(progress)
    try:
        summary = ingest_paths(case, inputs, custodian, argv=sys.argv, progress=reporter, guard=_guard(min_free))
    except Exception as e:
        reporter.close()
        _interrupted("ingest", e)
    reporter.close()

    ingested = [f for f in summary.files if f.status == "ingested"]
    typer.echo(
        f"run {summary.run_id}: {len(ingested)} files, {sum(f.messages for f in ingested)} messages,"
        f" {len(summary.errors)} errors, {len(summary.item_errors)} item errors"
    )
    if summary.errors or summary.item_errors:
        raise typer.Exit(1)


def _load_case(case_dir: Path) -> Case:
    try:
        return Case.load(case_dir)
    except FileNotFoundError as e:
        typer.echo(f"error: {e}", err=True)
        raise typer.Exit(1)


def _settings(config: Optional[Path]):
    from emailforensics.analysis.config import load_settings

    try:
        return load_settings(config)
    except (ValueError, KeyError, TypeError) as e:
        typer.echo(f"error: {config}: {e}", err=True)
        raise typer.Exit(1)


ConfigOption = Annotated[
    Optional[Path],
    typer.Option("--config", help="poem.yaml with places, offsets, IP ranges, entities and phrase lists (defaults: ZA vs MU)."),
]


@app.command(help="Load the people register (identities, addresses, home base, board membership, custodian).")
def people(
    case_dir: Annotated[Path, typer.Argument(help="Case folder.")],
    register: Annotated[Path, typer.Argument(help="people.yaml")],
) -> None:
    from emailforensics.analysis.config import load_people
    from emailforensics.analysis.registers import save_people

    case = _load_case(case_dir)
    try:
        n = save_people(case, load_people(register))
    except (ValueError, KeyError) as e:
        typer.echo(f"error: {e}", err=True)
        raise typer.Exit(1)
    typer.echo(f"loaded {n} people; run `emailforensics analyze` again before reporting")


@app.command(help="Load the decision register (key decisions from the minutes, with search terms and windows).")
def register(
    case_dir: Annotated[Path, typer.Argument(help="Case folder.")],
    decisions: Annotated[Path, typer.Argument(help="decisions.yaml")],
) -> None:
    from emailforensics.analysis.config import load_decisions
    from emailforensics.analysis.registers import save_decisions

    case = _load_case(case_dir)
    try:
        n = save_decisions(case, load_decisions(decisions))
    except (ValueError, KeyError) as e:
        typer.echo(f"error: {e}", err=True)
        raise typer.Exit(1)
    typer.echo(f"loaded {n} decisions; run `emailforensics analyze` again before reporting")


@app.command(help="Run all analyzers: threads, offsets, quoted headers, presence, send-time, language, documents, decisions, anomalies.")
def analyze(
    case_dir: Annotated[Path, typer.Argument(help="Case folder.")],
    config: ConfigOption = None,
    min_free: MinFreeOption = None,
) -> None:
    from emailforensics.analysis.run import analyze_case

    case = _load_case(case_dir)
    settings = _settings(config)
    try:
        stats = analyze_case(case, settings, argv=sys.argv, log=lambda s: typer.echo(s, err=True), guard=_guard(min_free))
    except Exception as e:
        _interrupted("analyze", e)

    for k, v in stats.items():
        typer.echo(f"{k}: {v}")


@app.command(help="Print one decision's timeline in the terminal.")
def timeline(
    case_dir: Annotated[Path, typer.Argument(help="Case folder.")],
    decision_id: Annotated[str, typer.Argument(help="Decision ID from the register, e.g. D1.")],
) -> None:
    from emailforensics.report import print_timeline

    try:
        print_timeline(_load_case(case_dir), decision_id)
    except (KeyError, RuntimeError) as e:
        typer.echo(f"error: {e}", err=True)
        raise typer.Exit(1)


@app.command(help="Write the HTML report and CSV exhibits. Source files are re-hashed first.")
def report(
    case_dir: Annotated[Path, typer.Argument(help="Case folder.")],
    out: Annotated[Path, typer.Option("--out", "-o", help="Output folder.")] = Path("report"),
    config: ConfigOption = None,
    verify: Annotated[bool, typer.Option("--verify/--no-verify", help="Re-hash source files before reporting.")] = True,
) -> None:
    from emailforensics.report import build_report

    settings = _settings(config)
    try:
        path, stale = build_report(_load_case(case_dir), settings, out, verify=verify)
    except RuntimeError as e:
        typer.echo(f"error: {e}", err=True)
        raise typer.Exit(1)
    if stale:
        typer.echo("warning: registers changed since the last analysis; the report is marked stale", err=True)
    typer.echo(f"report written to {path}")


@app.command(help="Score test emails tagged [TAG] in their subject against a ground-truth file (see docs/ground-truth.md).")
def groundtruth(
    case_dir: Annotated[Path, typer.Argument(help="Case folder with the test mailbox ingested and analysed.")],
    truth: Annotated[Path, typer.Argument(help="truth.yaml describing each test email.")],
    out: Annotated[Path, typer.Option("--out", "-o", help="CSV file for the per-copy results.")] = Path("groundtruth.csv"),
) -> None:
    from rich.console import Console
    from rich.table import Table

    from emailforensics.groundtruth import evaluate, load_truth, write_csv

    try:
        rows, summary = evaluate(_load_case(case_dir), load_truth(truth))
    except (RuntimeError, KeyError, ValueError) as e:
        typer.echo(f"error: {e}", err=True)
        raise typer.Exit(1)
    write_csv(rows, out)
    t = Table(title="Ground truth")
    for col in ("tag", "client", "copy", "offset", "expected_offset", "offset_ok", "writer_device", "device_ok", "clock", "place", "place_ok"):
        t.add_column(col, overflow="fold")
    for r in rows:
        t.add_row(*(str(r.get(c, "")) for c in ("tag", "client", "copy", "offset", "expected_offset", "offset_ok",
                                                  "writer_device", "device_ok", "clock", "place", "place_ok")))
    Console().print(t)
    for k, v in summary.items():
        typer.echo(f"{k}: {v}")
    typer.echo(f"details written to {out}")


if __name__ == "__main__":
    app()
