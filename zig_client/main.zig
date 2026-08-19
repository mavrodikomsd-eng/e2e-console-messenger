const std = @import("std");

const TYPE_MESSAGE: u8 = 'M';
const TYPE_COMMAND: u8 = 'C';
const TYPE_FILE: u8 = 'F';
const TYPE_REGISTER: u8 = 'R';
const TYPE_VERSION: u8 = 'V';
const PROTOCOL_VERSION: []const u8 = "1";
const MAX_FRAME: usize = 1 << 20;

const print_mu = std.Thread.Mutex{};

fn pprint(comptime fmt: []const u8, args: anytype) void {
    print_mu.lock();
    defer print_mu.unlock();
    std.debug.print("\r", .{});
    std.debug.print(fmt, args);
    std.debug.print(" \r\n>>> ", .{});
}

// ---- frame: [1 type][4 len BE][payload] ----
fn build_frame(alloc: std.mem.Allocator, ftype: u8, payload: []const u8) ![]u8 {
    const frame = try alloc.alloc(u8, 5 + payload.len);
    frame[0] = ftype;
    std.mem.writeInt(u32, frame[1..5][0..4], @intCast(payload.len), .big);
    @memcpy(frame[5..], payload);
    return frame;
}

const Frame = struct { ftype: u8, payload: []u8 };

fn read_frame(reader: std.io.AnyReader, alloc: std.mem.Allocator) !?Frame {
    var header: [5]u8 = undefined;
    const n = try reader.readAll(&header) catch |e| switch (e) {
        error.EndOfStream => return null,
        else => return e,
    };
    if (n == 0) return null;
    const len: usize = std.mem.readInt(u32, header[1..5], .big);
    if (len > MAX_FRAME) return error.FrameTooLarge;
    const payload = try alloc.alloc(u8, len);
    errdefer alloc.free(payload);
    const got = try reader.readAll(payload);
    if (got < len) return error.Truncated;
    return Frame{ .ftype = header[0], .payload = payload };
}

pub fn main() !void {
    const alloc = std.heap.page_allocator;
    _ = alloc;
    std.debug.print("libmesh-zig client stub\n", .{});
}