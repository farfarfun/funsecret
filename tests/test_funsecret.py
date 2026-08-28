import tempfile
import unittest
from pathlib import Path

from funsecret.secret.secret import SecretManage


class DatabasePathTest(unittest.TestCase):
    def test_uses_funsecret_database_file(self):
        with tempfile.TemporaryDirectory() as directory:
            manage = SecretManage(secret_dir=directory)
            expected = Path(directory) / ".funsecret.db"
            self.assertEqual(manage.engine.url.database, str(expected))


if __name__ == "__main__":
    unittest.main()
