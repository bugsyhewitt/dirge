"""dirge CLI — NoSQL injection payload generator and scanner."""

import json
import sys

import click

from dirge.payloads import (
    NoSQLPayload,
    couchbase_payloads,
    generic_nosql_payloads,
    mongodb_payloads,
)
from dirge.prober import probe_param


def _all_payloads() -> list[NoSQLPayload]:
    return mongodb_payloads() + couchbase_payloads() + generic_nosql_payloads()


@click.group()
@click.version_option()
def cli() -> None:
    """dirge — NoSQL injection payload generator and scanner."""


@cli.command("generate")
@click.option(
    "--database",
    type=click.Choice(["mongodb", "couchbase", "generic", "all"], case_sensitive=False),
    default="all",
    show_default=True,
    help="Target database type.",
)
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["json", "query-string", "form", "all"], case_sensitive=False),
    default="all",
    show_default=True,
    help="Payload format filter.",
)
def generate(database: str, fmt: str) -> None:
    """Print NoSQL injection payloads to stdout."""
    payloads = _all_payloads()

    if database != "all":
        payloads = [p for p in payloads if p.database == database]
    if fmt != "all":
        payloads = [p for p in payloads if p.param_format == fmt]

    for p in payloads:
        click.echo(
            json.dumps(
                {
                    "database": p.database,
                    "technique": p.technique,
                    "format": p.param_format,
                    "payload": p.payload,
                    "description": p.description,
                }
            )
        )


@cli.command("scan")
@click.option("--url", required=True, help="Target URL.")
@click.option(
    "--param",
    required=True,
    help="Comma-separated parameter names to test.",
)
@click.option(
    "--method",
    type=click.Choice(["GET", "POST"], case_sensitive=False),
    default="POST",
    show_default=True,
)
@click.option(
    "--database",
    type=click.Choice(["mongodb", "couchbase", "generic", "all"], case_sensitive=False),
    default="all",
    show_default=True,
)
def scan(url: str, param: str, method: str, database: str) -> None:
    """Scan a URL parameter for NoSQL injection vulnerabilities."""
    payloads = _all_payloads()
    if database != "all":
        payloads = [p for p in payloads if p.database == database]

    params = [p.strip() for p in param.split(",") if p.strip()]
    findings = []

    for param_name in params:
        click.echo(f"[*] Probing parameter '{param_name}' at {url}", err=True)
        results = probe_param(url, param_name, payloads, method)
        for r in results:
            if r["detected"]:
                findings.append(
                    {
                        "url": url,
                        "param": param_name,
                        "payload": r["payload"].payload,
                        "confidence": r["confidence"],
                        "indicators": r["indicators"],
                        "response_code": r["response_code"],
                    }
                )

    if findings:
        click.echo(json.dumps({"vulnerable": True, "findings": findings}, indent=2))
        sys.exit(1)
    else:
        click.echo(json.dumps({"vulnerable": False, "findings": []}))


def main() -> None:
    cli()
