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


if __name__ == "__main__":
    app()
