import os


def clear_screen():
    """Очищает экран консоли."""
    os.system("cls" if os.name == "nt" else "clear")


def show_banner():
    """Показывает красивую шапку программы."""

    clear_screen()

    print("=" * 40)
    print("         MeshMessenger")
    print("      Локальный мессенджер")
    print("=" * 40)
    print()


def show_help():
    """Показывает список команд."""

    print("Доступные команды:")
    print()
    print("/help   - показать список команд")
    print("/users  - показать пользователей")
    print("/clear  - очистить экран")
    print("/exit   - выйти из программы")
    print()