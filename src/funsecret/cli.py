from collections.abc import Iterator
from pathlib import Path
from typing import Annotated, Any, TypeAlias

import typer
from farlog import configure

from funsecret import (
    SecretManage,
    clear_secret_db,
    list_sectet,
    load_secret_db,
    read_secret,
    save_secret_db,
    write_secret,
)

app = typer.Typer(help="funsecret command line interface")
SecretTree: TypeAlias = dict[str, Any]
MYSQL_EXAMPLE_URL = "mysql+pymysql://username:password@127.0.0.1:3306/funsecret"
DEFAULT_DB_URL_CATEGORY = ("funsecret", "db", "url")


@app.callback()
def main() -> None:
    """初始化 funsecret 命令组。"""
    configure()


def _iter_secret_paths(
    tree: SecretTree, prefix: list[str] | None = None
) -> Iterator[list[str]]:
    prefix = prefix or []
    for key, value in tree.items():
        path = prefix + [key]
        if isinstance(value, dict):
            yield from _iter_secret_paths(value, path)
        else:
            yield path


@app.command()
def read(
    categories: Annotated[
        list[str],
        typer.Argument(
            metavar="CATE1 CATE2 [CATE3] [CATE4] [CATE5]",
            help="Secret category path",
        ),
    ],
) -> None:
    """按分类路径读取密钥。"""
    if len(categories) < 2 or len(categories) > 5:
        raise typer.BadParameter("read requires 2 to 5 category arguments")

    padded = categories + [""] * (5 - len(categories))
    value = read_secret(*padded)
    if value is None:
        raise typer.Exit(code=1)
    typer.echo(value)


@app.command()
def write(
    value: Annotated[str, typer.Argument(help="Secret value to store")],
    categories: Annotated[
        list[str],
        typer.Argument(
            metavar="CATE1 CATE2 [CATE3] [CATE4] [CATE5]",
            help="Secret category path",
        ),
    ],
) -> None:
    """按分类路径写入密钥。"""
    if len(categories) < 2 or len(categories) > 5:
        raise typer.BadParameter("write requires 2 to 5 category arguments")

    padded = categories + [""] * (5 - len(categories))
    write_secret(value, *padded)


@app.command(name="list")
def list_command() -> None:
    """列出所有密钥路径，不显示值。"""
    for path in _iter_secret_paths(list_sectet()):
        typer.echo(" ".join(path))


@app.command()
def info() -> None:
    """显示当前存储后端和密钥数量。"""
    manage = SecretManage()
    secret_paths = list(_iter_secret_paths(list_sectet()))
    engine_url = manage.engine.url.render_as_string(hide_password=True)

    typer.echo(f"backend: {manage.engine.url.get_backend_name()}")
    typer.echo(f"database_url: {engine_url}")
    if manage.engine.url.get_backend_name() == "sqlite" and manage.engine.url.database:
        typer.echo(f"database_file: {Path(manage.engine.url.database).expanduser()}")
    typer.echo(f"secret_count: {len(secret_paths)}")
    typer.echo(f"cipher_key_configured: {'yes' if bool(manage.cipher_key) else 'no'}")
    typer.echo(f"mysql_example_url: {MYSQL_EXAMPLE_URL}")


@app.command()
def clear(
    yes: Annotated[
        bool, typer.Option("--yes", help="Clear all secrets without confirmation")
    ] = False,
) -> None:
    """清空当前密钥数据库。"""
    if not yes:
        confirmed = typer.confirm(
            "This will delete all stored secrets. Continue?", default=False
        )
        if not confirmed:
            raise typer.Exit(code=1)
    clear_secret_db()
    typer.echo("cleared")


def _resolve_db_url(db_url: str | None) -> str:
    if db_url:
        return db_url
    stored = read_secret(*DEFAULT_DB_URL_CATEGORY)
    if not stored:
        category = " ".join(DEFAULT_DB_URL_CATEGORY)
        raise typer.BadParameter(
            "No database URL given and no default is stored. "
            f"Pass a URL, or store a default with: funsecret write <url> {category}"
        )
    return stored


@app.command()
def load(
    db_url: Annotated[
        str | None,
        typer.Argument(
            help="Database URL to load secrets from (defaults to the stored default URL if omitted)"
        ),
    ] = None,
    cipher_key: Annotated[
        str | None, typer.Option(help="Cipher key for the source database")
    ] = None,
) -> None:
    """从外部数据库加载密钥。"""
    load_secret_db(url=_resolve_db_url(db_url), cipher_key=cipher_key)


@app.command()
def save(
    db_url: Annotated[
        str | None,
        typer.Argument(
            help="Database URL to save secrets to (defaults to the stored default URL if omitted)"
        ),
    ] = None,
    cipher_key: Annotated[
        str | None, typer.Option(help="Cipher key for the target database")
    ] = None,
) -> None:
    """把密钥保存到外部数据库。"""
    save_secret_db(url=_resolve_db_url(db_url), cipher_key=cipher_key)


if __name__ == "__main__":
    app()
