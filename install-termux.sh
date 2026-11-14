#!/data/data/com.termux/files/usr/bin/bash
set -eu

if [ -z "${PREFIX:-}" ] || [ ! -d "$PREFIX/bin" ]; then
    echo "Error: This installer must be run inside Termux."
    exit 1
fi

if ! command -v python >/dev/null 2>&1; then
    echo "Python is required. Install it with: pkg install python"
    exit 1
fi

SOURCE_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
APP_DIR="$HOME/.local/share/pigeon-security-toolkit"
BIN_DIR="$PREFIX/bin"

for file in pst.py pigeon_portscan.py pigeon_history.py; do
    if [ ! -f "$SOURCE_DIR/$file" ]; then
        echo "Error: Missing required file: $SOURCE_DIR/$file"
        exit 1
    fi
done

mkdir -p "$APP_DIR" "$BIN_DIR"
cp "$SOURCE_DIR/pst.py" "$SOURCE_DIR/pigeon_portscan.py" "$SOURCE_DIR/pigeon_history.py" "$APP_DIR/"

if [ -f "$SOURCE_DIR/README.md" ]; then
    cp "$SOURCE_DIR/README.md" "$APP_DIR/"
fi
if [ -f "$SOURCE_DIR/LICENSE" ]; then
    cp "$SOURCE_DIR/LICENSE" "$APP_DIR/"
fi

printf '%s\n' \
    '#!/data/data/com.termux/files/usr/bin/sh' \
    'APP_DIR="$HOME/.local/share/pigeon-security-toolkit"' \
    'exec python "$APP_DIR/pst.py" "$@"' > "$BIN_DIR/pst"

chmod 755 "$BIN_DIR/pst"
python -m py_compile "$APP_DIR/pst.py" "$APP_DIR/pigeon_portscan.py" "$APP_DIR/pigeon_history.py"

echo "PST installed successfully."
echo "Application files: $APP_DIR"
echo "Command: pst --version"
