"""Ротация ключа шифрования секретов (data/secret.key) — закрывает пункт из
аудита: ключ раньше создавался один раз и не имел механизма смены (низкая
приоритетность для маленького внутреннего инструмента, нет требования
комплаенса на периодическую ротацию — но по прямому запросу владельца всё
равно реализовано).

Одноразовая ручная утилита в том же духе, что deploy/import_from_netopshub.py
— НЕ HTTP-эндпоинт: смена ключа шифрования всех секретов (SSH-пароли,
API-токены, bind-пароль LDAP и т.д.) требует реального доступа к серверу/
shell, не то, что должно быть доступно случайным вызовом API.

Что делает:
  1. Генерирует новый Fernet-ключ.
  2. Перешифровывает ВСЕ известные секреты в БД со старого ключа на новый
     (см. app.secrets_crypto.rotate_secrets — перечисление всех полей,
     MultiFernet-механизм, идемпотентность при повторном запуске).
  3. Только если перешифровка прошла без падения процесса — архивирует
     старый ключ (data/secret.key.rotated-<UTC-таймстамп>, НЕ удаляет: если
     что-то пойдёт не так, старый ключ ещё можно вернуть руками) и пишет
     новый ключ в data/secret.key с правами 0600.

ВАЖНО: уже запущенный процесс gridforge (веб/scheduler) держит ключ в
памяти (см. secrets_crypto._fernet, кэшируется на процесс) — после ротации
процесс нужно перезапустить (`systemctl restart gridforge` / `docker compose
restart gridforge`), иначе он продолжит шифровать новые секреты старым
ключом, а старый файл ключа к этому моменту уже архивирован под другим
именем.

Архивные data/secret.key.rotated-* НЕ удаляются этим скриптом автоматически
— их безопасно удалить руками после того, как ротация подтверждена рабочей
(приложение перезапущено, секреты читаются/применяются нормально).

    venv/bin/python3 deploy/rotate_secret_key.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cryptography.fernet import Fernet  # noqa: E402

from app import secrets_crypto  # noqa: E402
from app.db import get_session, init_db  # noqa: E402

KEY_PATH = secrets_crypto._KEY_PATH


def main() -> int:
    if not KEY_PATH.exists():
        print(
            f"{KEY_PATH} не существует — ротировать нечего (ключ создаётся "
            "автоматически при первом обращении приложения к секретам; "
            "запустите приложение хотя бы раз перед ротацией)."
        )
        return 1

    old_key = KEY_PATH.read_bytes()
    new_key = Fernet.generate_key()

    init_db()
    db = get_session()
    try:
        counts = secrets_crypto.rotate_secrets(db, new_key=new_key, old_key=old_key)
    finally:
        db.close()

    if counts["unreadable"]:
        print(
            f"ВНИМАНИЕ: {counts['unreadable']} полей не расшифровались ни старым, ни новым "
            "ключом (см. лог выше, rotate_secrets/ERROR) — вероятно, были повреждены/"
            "нечитаемы ещё ДО ротации. Ротация остальных полей всё равно применена и "
            "закоммичена; для этих конкретных полей нужна ручная проверка."
        )

    # Только теперь, когда все читаемые секреты в БД гарантированно уже
    # перешифрованы и закоммичены — меняем сам файл ключа. Порядок важен:
    # наоборот (сначала файл, потом перешифровка) означало бы, что при
    # падении процесса между этими шагами приложение стартует с новым
    # ключом, а данные в БД ещё под старым — и все секреты станут нечитаемы.
    archived_path = secrets_crypto.archive_and_replace_key(new_key)

    print(
        f"Готово: {counts['migrated']} полей перешифровано, {counts['already_current']} уже были "
        f"под новым ключом, {counts['plaintext_skipped']} legacy-plaintext не тронуто, "
        f"{counts['unreadable']} нечитаемых.\n"
        f"Старый ключ архивирован в {archived_path} (не удалён — удалить руками после "
        "проверки).\n"
        f"Новый ключ записан в {KEY_PATH} (0600).\n"
        "ВАЖНО: перезапустите gridforge (systemctl restart gridforge / docker compose "
        "restart gridforge), чтобы уже запущенный процесс подхватил новый ключ."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
