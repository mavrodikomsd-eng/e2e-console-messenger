import socket
import struct

# ─────────────────────────────────────────────
#  TCP-фрейминг с типами кадров
#
#  Кадр:
#    [1 байт: тип]
#    [4 байта: длина payload (BE)]
#    [payload]
#
#  Типы:
#    b'M' — сообщение:      name + b'\x00' + шифротекст
#    b'C' — команда:        шифротекст команды
#
#  E2E: сервер НЕ расшифровывает M-кадры,
#  а только пересылает их другим клиентам.
# ─────────────────────────────────────────────
TYPE_MESSAGE = b"M"   # сообщение
TYPE_COMMAND = b"C"   # команда

HEADER_SIZE = 5  # 1 (тип) + 4 (длина)
MAX_MESSAGE_SIZE = 1024 * 1024  # 1 МБ


def set_tcp_nodelay(sock: socket.socket) -> None:
    """Отключает алгоритм Нейгла — сообщения уходят сразу, без задержек."""
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except OSError:
        pass  # не критично


def send_frame(sock: socket.socket, frame_type: bytes, payload: bytes | str) -> None:
    """Отправляет кадр: [тип][4 байта длины][payload] одним пакетом."""
    if isinstance(payload, str):
        payload = payload.encode("utf-8")

    if len(payload) > MAX_MESSAGE_SIZE:
        raise ValueError(f"Сообщение слишком большое: {len(payload)} байт")

    frame = frame_type + struct.pack(">I", len(payload)) + payload
    sock.sendall(frame)


def recv_frame(sock: socket.socket) -> tuple[bytes, bytes] | None:
    """
    Читает один полный кадр: (тип, payload).
    Возвращает None при разрыве соединения.
    """
    header = _recv_exact(sock, HEADER_SIZE)
    if header is None:
        return None

    frame_type = header[:1]
    (length,) = struct.unpack(">I", header[1:])

    if length > MAX_MESSAGE_SIZE:
        raise ValueError(f"Недопустимая длина сообщения: {length}")

    payload = _recv_exact(sock, length)
    if payload is None:
        return None

    return frame_type, payload


# Обратная совместимость с предыдущей версией протокола
def send_message(sock: socket.socket, payload: bytes | str) -> None:
    """Отправляет сообщение с типом M (обратная совместимость)."""
    send_frame(sock, TYPE_MESSAGE, payload)


def recv_message(sock: socket.socket) -> bytes | None:
    """Читает кадр и возвращает payload (обратная совместимость)."""
    result = recv_frame(sock)
    if result is None:
        return None
    return result[1]


def _recv_exact(sock: socket.socket, n: int) -> bytes | None:
    """Читает ровно n байт. Возвращает None при разрыве соединения."""
    chunks = []
    remaining = n

    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            return None  # соединение закрыто
        chunks.append(chunk)
        remaining -= len(chunk)

    return b"".join(chunks)