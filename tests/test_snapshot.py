from pathlib import Path
from unittest.mock import Mock, patch

import pytest
from funsecret.snapshot import snapshot


def test_save_snapshot_exports_database() -> None:
    drive = Mock()

    def create_database(*, url: str) -> None:
        Path(url.removeprefix("sqlite:///")).touch()

    with (
        patch.object(snapshot, "save_secret_db", side_effect=create_database),
        patch.object(snapshot, "DriveSnapshot") as drive_snapshot,
    ):
        snapshot.save_snapshot("table-id", drive)

    drive_snapshot.assert_called_once_with(table_fid="table-id", drive=drive)
    _, kwargs = drive_snapshot.return_value.update.call_args
    assert kwargs == {"partition": "backup"}


def test_load_snapshot_imports_database() -> None:
    drive = Mock()

    def download(directory: str) -> None:
        Path(directory, snapshot.DATABASE_NAME).touch()

    with (
        patch.object(snapshot, "load_secret_db") as load_secret_db,
        patch.object(snapshot, "DriveSnapshot") as drive_snapshot,
    ):
        drive_snapshot.return_value.download.side_effect = download
        snapshot.load_snapshot("table-id", drive)

    drive_snapshot.assert_called_once_with(table_fid="table-id", drive=drive)
    load_secret_db.assert_called_once()
    assert load_secret_db.call_args.kwargs["url"].endswith("/funsecret.db")


def test_load_snapshot_requires_database_file() -> None:
    with (
        patch.object(snapshot, "DriveSnapshot"),
        pytest.raises(FileNotFoundError, match="funsecret.db"),
    ):
        snapshot.load_snapshot("table-id", Mock())
