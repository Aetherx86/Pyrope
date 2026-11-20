const std = @import("std");

/// WireGuard REJECT_AFTER_MESSAGES: counters at or above this are never valid.
pub const REJECT_AFTER_MESSAGES: u64 = std.math.maxInt(u64) - (1 << 13);

const BLOCK_BITS_LOG: u6 = 6;
const BLOCK_BITS: u64 = 1 << BLOCK_BITS_LOG; // 64-bit words
const RING_BLOCKS: u64 = 1 << 7; // 128 words = 8192 bits
const BLOCK_MASK: u64 = RING_BLOCKS - 1;
const BIT_MASK: u64 = BLOCK_BITS - 1;

/// Number of counters behind the highest accepted one that are still tracked.
/// One ring word is kept as slack so the window can slide without
/// discarding bits that are still inside it (RFC 6479 Section 2).
pub const WINDOW_SIZE: u64 = (RING_BLOCKS - 1) * BLOCK_BITS; // 8128

/// Sliding-window anti-replay filter as described in RFC 6479 and used by
/// WireGuard. Call `validate` only after a packet has been authenticated,
/// otherwise a forged counter could advance the window.
pub const ReplayFilter = struct {
    last: u64 = 0,
    ring: [RING_BLOCKS]u64 = @splat(0),

    pub fn reset(self: *ReplayFilter) void {
        self.* = .{};
    }

    /// Returns true when `counter` has not been seen before and is inside the
    /// window, and records it. Returns false for replays, counters too far
    /// behind the window and counters >= `limit`.
    pub fn validate(self: *ReplayFilter, counter: u64, limit: u64) bool {
        if (counter >= limit) return false;
        var index_block = counter >> BLOCK_BITS_LOG;
        if (counter > self.last) {
            // Slide forward, clearing the words that are being reused.
            const current = self.last >> BLOCK_BITS_LOG;
            const diff = @min(index_block - current, RING_BLOCKS);
            var i: u64 = current + 1;
            while (i <= current + diff) : (i += 1) {
                self.ring[i & BLOCK_MASK] = 0;
            }
            self.last = counter;
        } else if (self.last - counter > WINDOW_SIZE) {
            return false;
        }
        index_block &= BLOCK_MASK;
        const bit = @as(u64, 1) << @as(u6, @intCast(counter & BIT_MASK));
        const old = self.ring[index_block];
        self.ring[index_block] = old | bit;
        return old & bit == 0;
    }
};

test "replay filter: WireGuard reference sequence" {
    var f = ReplayFilter{};
    const T_LIM = WINDOW_SIZE + 1;
    const R = REJECT_AFTER_MESSAGES;
    const Case = struct { n: u64, ok: bool };
    const cases = [_]Case{
        .{ .n = 0, .ok = true },                        .{ .n = 1, .ok = true },
        .{ .n = 1, .ok = false },                       .{ .n = 9, .ok = true },
        .{ .n = 8, .ok = true },                        .{ .n = 7, .ok = true },
        .{ .n = 7, .ok = false },                       .{ .n = T_LIM, .ok = true },
        .{ .n = T_LIM - 1, .ok = true },                .{ .n = T_LIM - 1, .ok = false },
        .{ .n = T_LIM - 2, .ok = true },                .{ .n = 2, .ok = true },
        .{ .n = 2, .ok = false },                       .{ .n = T_LIM + 16, .ok = true },
        .{ .n = 3, .ok = false },                       .{ .n = T_LIM + 16, .ok = false },
        .{ .n = T_LIM * 4, .ok = true },                .{ .n = T_LIM * 4 - (T_LIM - 1), .ok = true },
        .{ .n = 10, .ok = false },                      .{ .n = T_LIM * 4 - T_LIM, .ok = false },
        .{ .n = T_LIM * 4 - (T_LIM + 1), .ok = false }, .{ .n = T_LIM * 4 - (T_LIM - 2), .ok = true },
        .{ .n = T_LIM * 4 + 1 - T_LIM, .ok = false },   .{ .n = 0, .ok = false },
        .{ .n = R, .ok = false },                       .{ .n = R - 1, .ok = true },
        .{ .n = R, .ok = false },                       .{ .n = R - 1, .ok = false },
        .{ .n = R - 2, .ok = true },                    .{ .n = R + 1, .ok = false },
        .{ .n = R + 2, .ok = false },                   .{ .n = R - 2, .ok = false },
        .{ .n = R - 3, .ok = true },                    .{ .n = 0, .ok = false },
    };
    for (cases, 0..) |c, i| {
        if (f.validate(c.n, R) != c.ok) {
            std.debug.print("case {d}: counter {d} expected {}\n", .{ i, c.n, c.ok });
            return error.TestUnexpectedResult;
        }
    }
}

test "replay filter: every in-window counter accepted exactly once, any order" {
    var f = ReplayFilter{};
    var prng = std.Random.DefaultPrng.init(6479);
    var order: [WINDOW_SIZE + 1]u64 = undefined;
    for (&order, 0..) |*o, i| o.* = i;
    prng.random().shuffle(u64, &order);
    // Accept the top of the window first so every other counter is in range.
    try std.testing.expect(f.validate(WINDOW_SIZE, REJECT_AFTER_MESSAGES));
    for (order) |n| {
        try std.testing.expectEqual(n != WINDOW_SIZE, f.validate(n, REJECT_AFTER_MESSAGES));
    }
    for (order) |n| try std.testing.expect(!f.validate(n, REJECT_AFTER_MESSAGES));
}

test "replay filter: differential against a naive set-based model" {
    const gpa = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x6479);
    const rnd = prng.random();
    for (0..20) |round| {
        var f = ReplayFilter{};
        var seen = std.AutoHashMap(u64, void).init(gpa);
        defer seen.deinit();
        var max: ?u64 = null;
        const limit: u64 = if (round % 4 == 0) 50_000 else REJECT_AFTER_MESSAGES;
        var base: u64 = if (round % 5 == 0) REJECT_AFTER_MESSAGES - 40_000 else 0;
        for (0..6000) |_| {
            // Mostly forward motion with jitter, sometimes big jumps or far-back replays.
            const r = rnd.uintLessThan(u32, 100);
            var n: u64 = undefined;
            if (r < 70) {
                base +|= rnd.uintLessThan(u64, 4);
                n = base -| rnd.uintLessThan(u64, 300);
            } else if (r < 80) {
                base +|= rnd.uintLessThan(u64, 20_000);
                n = base;
            } else if (r < 95) {
                n = base -| rnd.uintLessThan(u64, WINDOW_SIZE + 200);
            } else {
                n = rnd.int(u64);
            }
            const expected = blk: {
                if (n >= limit) break :blk false;
                if (seen.contains(n)) break :blk false;
                if (max) |mx| if (n < mx and mx - n > WINDOW_SIZE) break :blk false;
                break :blk true;
            };
            if (expected) {
                try seen.put(n, {});
                max = if (max) |mx| @max(mx, n) else n;
            }
            try std.testing.expectEqual(expected, f.validate(n, limit));
        }
    }
}
