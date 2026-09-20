from app import secrets_crypto


def test_encrypt_decrypt_roundtrip():
    encrypted = secrets_crypto.encrypt_secret("my-password-123")
    assert encrypted.startswith(secrets_crypto.SECRET_MARKER)
    assert encrypted != "my-password-123"
    assert secrets_crypto.decrypt_secret(encrypted) == "my-password-123"


def test_decrypt_passthrough_for_legacy_plaintext():
    # Данные, заведённые до появления шифрования — без маркера enc:,
    # decrypt_secret не должен их трогать/ронять.
    assert secrets_crypto.decrypt_secret("plain-old-password") == "plain-old-password"


def test_decrypt_invalid_token_does_not_raise():
    # Ключ сменился или данные повреждены — decrypt_secret должен молча
    # вернуть исходную (нерасшифрованную) строку, не поднимать исключение,
    # чтобы ошибка проявилась естественно на уровне SSH/SNMP-подключения.
    fake = secrets_crypto.SECRET_MARKER + "not-a-real-fernet-token"
    result = secrets_crypto.decrypt_secret(fake)
    assert result == fake


def test_different_secrets_produce_different_ciphertext():
    a = secrets_crypto.encrypt_secret("secret-a")
    b = secrets_crypto.encrypt_secret("secret-b")
    assert a != b
