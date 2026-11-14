#!/usr/bin/env bash
set -euo pipefail

SOURCE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="$HOME/.local/share/pigeon-security-toolkit"
BIN_DIR="$HOME/.local/bin"

if ! command -v python3 >/dev/null 2>&1; then
    echo "Error: Python 3 is required."
    exit 1
fi

if ! python3 -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)'; then
    echo "Error: Python 3.11 or later is required."
    exit 1
fi

for file in pst.py pigeon_portscan.py pigeon_history.py; do
    if [ ! -f "$SOURCE_DIR/$file" ]; then
        echo "Error: Missing $file"
        exit 1
    fi
done

mkdir -p "$APP_DIR" "$BIN_DIR"

cp "$SOURCE_DIR/pst.py" \
   "$SOURCE_DIR/pigeon_portscan.py" \
   "$SOURCE_DIR/pigeon_history.py" \
   "$APP_DIR/"

[ ! -f "$SOURCE_DIR/README.md" ] || cp "$SOURCE_DIR/README.md" "$APP_DIR/"
[ ! -f "$SOURCE_DIR/LICENSE" ] || cp "$SOURCE_DIR/LICENSE" "$APP_DIR/"

printf '%s\n' \
    '#!/usr/bin/env sh' \
    'APP_DIR="$HOME/.local/share/pigeon-security-toolkit"' \
    'exec python3 "$APP_DIR/pst.py" "$@"' > "$BIN_DIR/pst"

chmod 755 "$BIN_DIR/pst"

python3 -m py_compile \
    "$APP_DIR/pst.py" \
    "$APP_DIR/pigeon_portscan.py" \
    "$APP_DIR/pigeon_history.py"

echo "PST installed successfully."
echo "Application: $APP_DIR"
echo "Executable: $BIN_DIR/pst"
echo "Test with: $BIN_DIR/pst --version"

case ":$PATH:" in
    *":$BIN_DIR:"*) ;;
    *) echo "Add ~/.local/bin to your PATH to run pst directly." ;;
esac
