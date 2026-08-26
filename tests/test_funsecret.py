import tempfile
import unittest
from pathlib import Path

from funsecret.secret.secret import _sqlite_database_path


class DatabasePathTest(unittest.TestCase):
    def test_existing_nltsecret_database_is_reused(self):
        with tempfile.TemporaryDirectory() as directory:
            legacy = Path(directory) / ".nltsecret.db"
            legacy.touch()
            self.assertEqual(Path(_sqlite_database_path(directory)), legacy)

    def test_funsecret_database_wins_when_both_exist(self):
        with tempfile.TemporaryDirectory() as directory:
            legacy = Path(directory) / ".nltsecret.db"
            current = Path(directory) / ".funsecret.db"
            legacy.touch()
            current.touch()
            self.assertEqual(Path(_sqlite_database_path(directory)), current)


if __name__ == "__main__":
    unittest.main()
