from __future__ import annotations

import sys
from pathlib import Path
from typing import Annotated, Optional

import typer

from emailforensics.case import Case, create_case

app = typer.Typer(help="Offline POEM analysis of exported mailboxes.", no_args_is_help=True)


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
        summary = ingest_paths(case, inputs, custodian, argv=sys.argv, progress=reporter)
    finally:
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
) -> None:
    from emailforensics.analysis.config import load_settings
    from emailforensics.analysis.run import analyze_case

    case = _load_case(case_dir)
    stats = analyze_case(case, load_settings(config), argv=sys.argv, log=lambda s: typer.echo(s, err=True))
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
    from emailforensics.analysis.config import load_settings
    from emailforensics.report import build_report

    try:
        path, stale = build_report(_load_case(case_dir), load_settings(config), out, verify=verify)
    except RuntimeError as e:
        typer.echo(f"error: {e}", err=True)
        raise typer.Exit(1)
    if stale:
        typer.echo("warning: registers changed since the last analysis; the report is marked stale", err=True)
    typer.echo(f"report written to {path}")


if __name__ == "__main__":
    app()
