"""StarVault Desktop Application Entrypoint."""

import argparse
from pathlib import Path
import sys

# Ensure starvault package is discoverable
sys.path.insert(0, str(Path(__file__).parent.resolve()))

from starvault.config import APP_NAME, APP_VERSION, get_default_db_path
from starvault.ui.app import StarVaultApp


def main():
    parser = argparse.ArgumentParser(
        prog="StarVault",
        description=f"{APP_NAME} v{APP_VERSION} - Secure Credential & Key Vault for Homelabs and VPS",
    )
    parser.add_argument(
        "--db",
        type=str,
        default=None,
        help="Custom path to the SQLite vault file (e.g. --db ./my_vault.db)",
    )
    parser.add_argument(
        "--portable",
        action="store_true",
        help="Use portable database file './starvault.db' in the current working directory",
    )

    args = parser.parse_args()

    if args.db:
        db_path = Path(args.db).resolve()
    elif args.portable:
        db_path = Path("starvault.db").resolve()
    else:
        db_path = get_default_db_path()

    app = StarVaultApp(db_path=db_path)
    app.mainloop()


if __name__ == "__main__":
    main()
