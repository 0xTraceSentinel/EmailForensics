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
    inputs: Annotated[list[str], typer.Argument(help="EML/MBOX files, folders or glob patterns.")],
    custodian: Annotated[
        Optional[str], typer.Option("--custodian", "-c", help="Whose mailbox these exports come from.")
    ] = None,
) -> None:
    from emailforensics.ingest.pipeline import ingest_paths

    try:
        case = Case.load(case_dir)
    except FileNotFoundError as e:
        typer.echo(f"error: {e}", err=True)
        raise typer.Exit(1)

    summary = ingest_paths(case, inputs, custodian, argv=sys.argv)
    for f in summary.files:
        counts = f" {f.messages} messages, {f.attachments} attachments" if f.status == "ingested" else ""
        typer.echo(f"{f.status:<12}{f.path}{counts}  {f.detail}".rstrip())

    ingested = [f for f in summary.files if f.status == "ingested"]
    typer.echo(
        f"run {summary.run_id}: {len(ingested)} files, {sum(f.messages for f in ingested)} messages,"
        f" {len(summary.errors)} errors"
    )
    if summary.errors:
        raise typer.Exit(1)


if __name__ == "__main__":
    app()
