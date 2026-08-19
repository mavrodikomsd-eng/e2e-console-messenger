const std = @import("std");

pub fn main() !void {
    // --- X25519: derive public + shared secret (deterministic seeds for test) ---
    var my_secret: [32]u8 = undefined;
    @memset(&my_secret, 0x11);
    const my_pub = try std.crypto.dh.X25519.recoverPublicKey(my_secret);

    var peer_secret: [32]u8 = undefined;
    @memset(&peer_secret, 0x22);
    const peer_pub = try std.crypto.dh.X25519.recoverPublicKey(peer_secret);

    const shared1 = try std.crypto.dh.X25519.scalarmult(my_secret, peer_pub);
    const shared2 = try std.crypto.dh.X25519.scalarmult(peer_secret, my_pub);
    std.debug.print("x25519 peer pub ok, shares equal: {}\n", .{std.mem.eql(u8, &shared1, &shared2)});

    // --- sha256 key-derivation hash ---
    var key: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&shared1, &key, .{});

    // --- AES-256-GCM encrypt + decrypt ---
    const key2: [32]u8 = key;
    var nonce: [12]u8 = undefined;
    @memset(&nonce, 0xAB);
    const msg = "zig mesh probe";
    var cipher: [64]u8 = undefined;
    var tag: [16]u8 = undefined;
    std.crypto.aead.aes_gcm.Aes256Gcm.encrypt(cipher[0..msg.len], &tag, msg, "aad", nonce, key2);
    var plain: [64]u8 = undefined;
    try std.crypto.aead.aes_gcm.Aes256Gcm.decrypt(plain[0..msg.len], cipher[0..msg.len], tag, "aad", nonce, key2);
    const ok = std.mem.eql(u8, plain[0..msg.len], msg);
    std.debug.print("aes-gcm roundtrip ok: {}\n", .{ok});
    std.debug.print("probe done\n", .{});
}