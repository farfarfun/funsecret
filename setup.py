from multiprocessing import Process
from funpypi import setups, read_version


version = read_version()

# multi_package=2
setups(
    [
        {
            "name": "funsecret",
            "install_requires": ["funpypi", "sqlalchemy>2.0", "pandas", "cryptography", "farfundb"],
            "packages": ["funsecret"],
            "version": version,
        },
        {
            "name": "funsecret-snapshot",
            "packages": ["funsecret_snapshot"],
            "version": version,
            "install_requires": [
                # f"funsecret>={version}",
                "fundrive",
            ],
        },
    ]
)
