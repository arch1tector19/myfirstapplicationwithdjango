#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(pwd)"
URL_SERVICE="$PROJECT_DIR/services/url_service.py"
VIEWS="$PROJECT_DIR/sbom/views.py"
TABLE="$PROJECT_DIR/sbom/templates/sbom/table.html"

for file in "$URL_SERVICE" "$VIEWS" "$TABLE"; do
    if [[ ! -f "$file" ]]; then
        echo "Файл не найден: $file" >&2
        exit 1
    fi
done

python3 - "$URL_SERVICE" "$VIEWS" "$TABLE" <<'PY'
from pathlib import Path
import re
import sys

url_path, views_path, table_path = map(Path, sys.argv[1:])

# 1. Восстанавливаем определение архивных ссылок без Django-прокси.
url = url_path.read_text(encoding="utf-8")

if "def is_archive_url(" not in url:
    addition = '''\n\nARCHIVE_EXTENSIONS = (\n    ".zip",\n    ".tar",\n    ".tar.gz",\n    ".tgz",\n    ".tar.bz2",\n    ".tbz2",\n    ".tar.xz",\n    ".txz",\n    ".7z",\n    ".rar",\n)\n\n\ndef is_archive_url(url: str) -> bool:\n    """Определяет, указывает ли URL на архив."""\n    if not url:\n        return False\n\n    path = urlparse(url).path.lower()\n    return path.endswith(ARCHIVE_EXTENSIONS)\n'''
    url = url.rstrip() + addition
    url_path.write_text(url + "\n", encoding="utf-8")

# 2. В views передаём в шаблон информацию, является ли ссылка архивом.
views = views_path.read_text(encoding="utf-8")

views = re.sub(
    r"from services\.url_service import(?:\s*\(.*?\)|\s+get_valid_url)",
    "from services.url_service import get_valid_url, is_archive_url",
    views,
    count=1,
    flags=re.DOTALL,
)

old = re.compile(
    r"(?P<indent>\s*)component\.external_reference_url = \(\s*"
    r"get_valid_url\(\s*"
    r"component\.external_references\s*"
    r"\)\s*"
    r"\)"
)

new = '''{indent}component.external_reference_url = (\n{indent}    get_valid_url(\n{indent}        component.external_references\n{indent}    )\n{indent})\n{indent}component.external_reference_is_archive = (\n{indent}    is_archive_url(\n{indent}        component.external_reference_url\n{indent}    )\n{indent})'''

if "external_reference_is_archive" not in views:
    views, count = old.subn(
        lambda m: new.format(indent=m.group("indent")),
        views,
        count=1,
    )
    if count != 1:
        raise SystemExit("Не удалось добавить external_reference_is_archive в sbom/views.py")

views_path.write_text(views, encoding="utf-8")

# 3. Возвращаем рабочую механику ссылок:
#    архив -> download, обычный URL -> новая вкладка.
table = table_path.read_text(encoding="utf-8")

pattern = re.compile(
    r"(?P<indent>\s*)\{% if component\.external_reference_url %\}.*?\{% endif %\}",
    re.DOTALL,
)

replacement = '''{indent}{% if component.external_reference_url %}\n\n{indent}    {% if component.external_reference_is_archive %}\n\n{indent}        <a\n{indent}            href="{{ component.external_reference_url }}"\n{indent}            download\n{indent}        >\n{indent}            {{ component.external_reference_url }}\n{indent}        </a>\n\n{indent}    {% else %}\n\n{indent}        <a\n{indent}            href="{{ component.external_reference_url }}"\n{indent}            target="_blank"\n{indent}            rel="noopener noreferrer"\n{indent}        >\n{indent}            {{ component.external_reference_url }}\n{indent}        </a>\n\n{indent}    {% endif %}\n\n{indent}{% else %}\n\n{indent}    {{ component.external_references }}\n\n{indent}{% endif %}'''

if "external_reference_is_archive" not in table:
    match = pattern.search(table)
    if not match:
        raise SystemExit("Не найден текущий блок externalReferences в table.html")
    table = pattern.sub(
        lambda m: replacement.replace("{indent}", m.group("indent")),
        table,
        count=1,
    )

table_path.write_text(table, encoding="utf-8")

print("Готово: восстановлена рабочая обработка archive externalReferences.")
print("Новых зависимостей и новых файлов проекта не требуется.")
PY

printf '\n--- проверка ---\n'
grep -n -A24 -B5 'external_reference_is_archive' "$VIEWS" "$TABLE" || true
grep -n -A20 -B5 'ARCHIVE_EXTENSIONS' "$URL_SERVICE"
