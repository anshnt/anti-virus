"""Install the pinned official engine and verify/update its signature database."""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.antivirus import Antivirus
from app.core import DATA, Store, file_path
from app.windows import secure_data_folder


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, help='Already downloaded official ZIP; its pinned hash is still required.')
    parser.add_argument('--skip-update', action='store_true', help='Install only; scanning stays unavailable until definitions are installed.')
    args = parser.parse_args()
    DATA.mkdir(parents=True, exist_ok=True)
    file_path(str(DATA), directory=True)
    secure_data_folder(DATA)
    engine = Antivirus(Store(DATA))
    print(engine.install(args.archive), flush=True)
    if not args.skip_update:
        print(engine.update(), flush=True)


if __name__ == '__main__':
    main()
