from app.backups_engine import diff_backups


def test_diff_shows_added_and_removed_lines():
    older = "line1\nline2\nline3"
    newer = "line1\nline2-changed\nline3"
    result = diff_backups(older, newer)
    assert "-line2" in result
    assert "+line2-changed" in result
    assert "line1" in result  # неизменённая строка — часть контекста


def test_diff_identical_texts_is_empty():
    text = "same\ntext\nhere"
    assert diff_backups(text, text) == ""


def test_diff_uses_readable_labels_not_ab():
    # unified diff по умолчанию помечает файлы "---"/"+++" — здесь
    # подписаны по-русски, не "a"/"b", как в чистом difflib.
    result = diff_backups("x", "y")
    assert "предыдущий" in result
    assert "текущий" in result


def test_diff_empty_to_nonempty():
    result = diff_backups("", "new content")
    assert "+new content" in result
