//! Фрейминг протокола MeshMessenger: [тип 1 байт][длина u32 BE][payload].

use std::io::{Read, Write};
use std::net::TcpStream;

pub const TYPE_MESSAGE: u8 = b'M';
pub const TYPE_COMMAND: u8 = b'C';
pub const TYPE_FILE: u8 = b'F';
pub const TYPE_REGISTER: u8 = b'R';
pub const TYPE_VERSION: u8 = b'V';
pub const PROTOCOL_VERSION: &str = "2";
pub const MAX_FILE: usize = 400_000;
const MAX_FRAME: usize = 1 << 20;

pub fn send_frame(stream: &mut TcpStream, ftype: u8, payload: &[u8]) -> std::io::Result<()> {
    let mut frame = Vec::with_capacity(5 + payload.len());
    frame.push(ftype);
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(payload);
    stream.write_all(&frame)
}

/// None — сервер закрыл соединение.
pub fn recv_frame(stream: &mut TcpStream) -> std::io::Result<Option<(u8, Vec<u8>)>> {
    let mut header = [0u8; 5];
    match stream.read_exact(&mut header) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;
    if len > MAX_FRAME {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "frame too large"));
    }
    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload)?;
    Ok(Some((header[0], payload)))
}
