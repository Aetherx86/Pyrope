const std = @import("std");
pub const chacha = @import("chacha20.zig");
pub const poly = @import("poly1305.zig");
pub const aead = @import("aead.zig");
pub const curve = @import("curve25519.zig");

pub const MessageType = enum(u32) {
    handshake_initiation = 1,
    handshake_response = 2,
    cookie_reply = 3,
    data = 4,
};

pub const TRANSPORT_HEADER_SIZE: usize = 16; // 4B type + 4B receiver_idx + 8B counter
pub const TRANSPORT_TAG_SIZE: usize = 16;
pub const TRANSPORT_OVERHEAD: usize = TRANSPORT_HEADER_SIZE + TRANSPORT_TAG_SIZE; // 32 bytes

pub const TransportPacketHeader = extern struct {
    msg_type: u32,
    receiver_index: u32,
    counter: u64,
};

pub const WireGuardTunnel = struct {
    pub fn buildNonce(counter: u64) [12]u8 {
        var nonce: [12]u8 = undefined;
        // WireGuard AEAD nonce: 4 bytes of 0x00 followed by 64-bit counter little-endian
        @memset(nonce[0..4], 0);
        std.mem.writeInt(u64, nonce[4..12], counter, .little);
        return nonce;
    }

    pub fn encapsulateData(
        key: *const [32]u8,
        receiver_index: u32,
        counter: u64,
        payload: []const u8,
        out_packet: []u8,
    ) !usize {
        const total_len = TRANSPORT_HEADER_SIZE + payload.len + TRANSPORT_TAG_SIZE;
        if (out_packet.len < total_len) return error.BufferTooSmall;

        // Write header
        std.mem.writeInt(u32, out_packet[0..4], @intFromEnum(MessageType.data), .little);
        std.mem.writeInt(u32, out_packet[4..8], receiver_index, .little);
        std.mem.writeInt(u64, out_packet[8..16], counter, .little);

        const nonce = buildNonce(counter);
        const ct_slice = out_packet[TRANSPORT_HEADER_SIZE .. TRANSPORT_HEADER_SIZE + payload.len];
        const tag_slice: *[16]u8 = @ptrCast(out_packet[TRANSPORT_HEADER_SIZE + payload.len .. total_len][0..16]);

        aead.ChaCha20Poly1305.encrypt(
            key,
            &nonce,
            "", // WireGuard data packet uses empty AAD
            payload,
            ct_slice,
            tag_slice,
        );

        return total_len;
    }

    pub fn decapsulateData(
        key: *const [32]u8,
        expected_receiver_index: u32,
        in_packet: []const u8,
        out_payload: []u8,
    ) !struct { counter: u64, payload_len: usize } {
        if (in_packet.len < TRANSPORT_OVERHEAD) return error.PacketTooShort;

        const msg_type = std.mem.readInt(u32, in_packet[0..4], .little);
        if (msg_type != @intFromEnum(MessageType.data)) return error.InvalidMessageType;

        const rx_idx = std.mem.readInt(u32, in_packet[4..8], .little);
        if (rx_idx != expected_receiver_index) return error.ReceiverIndexMismatch;

        const counter = std.mem.readInt(u64, in_packet[8..16], .little);
        const ct_len = in_packet.len - TRANSPORT_OVERHEAD;

        if (out_payload.len < ct_len) return error.BufferTooSmall;

        const nonce = buildNonce(counter);
        const ct_slice = in_packet[TRANSPORT_HEADER_SIZE .. TRANSPORT_HEADER_SIZE + ct_len];
        const tag_slice: *const [16]u8 = @ptrCast(in_packet[TRANSPORT_HEADER_SIZE + ct_len .. in_packet.len][0..16]);

        try aead.ChaCha20Poly1305.decrypt(
            key,
            &nonce,
            "",
            ct_slice,
            tag_slice,
            out_payload[0..ct_len],
        );

        return .{
            .counter = counter,
            .payload_len = ct_len,
        };
    }
};

test "WireGuard Transport Packet Encapsulation and Decapsulation" {
    const tunnel_key = [32]u8{
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    };
    const rx_index: u32 = 0x4A3B2C1D;
    const packet_counter: u64 = 42;
    const raw_ip_payload = "IPv4: GET /api/v1/telemetry HTTP/1.1\r\nHost: node-12.matrix.internal\r\n\r\n";

    var wire_packet: [256]u8 = undefined;
    const wire_len = try WireGuardTunnel.encapsulateData(
        &tunnel_key,
        rx_index,
        packet_counter,
        raw_ip_payload,
        &wire_packet,
    );

    try std.testing.expectEqual(TRANSPORT_HEADER_SIZE + raw_ip_payload.len + TRANSPORT_TAG_SIZE, wire_len);

    // Verify header fields
    try std.testing.expectEqual(@as(u32, 4), std.mem.readInt(u32, wire_packet[0..4], .little));
    try std.testing.expectEqual(rx_index, std.mem.readInt(u32, wire_packet[4..8], .little));
    try std.testing.expectEqual(packet_counter, std.mem.readInt(u64, wire_packet[8..16], .little));

    // Decapsulate
    var recovered: [256]u8 = undefined;
    const res = try WireGuardTunnel.decapsulateData(
        &tunnel_key,
        rx_index,
        wire_packet[0..wire_len],
        &recovered,
    );

    try std.testing.expectEqual(packet_counter, res.counter);
    try std.testing.expectEqual(raw_ip_payload.len, res.payload_len);
    try std.testing.expectEqualStrings(raw_ip_payload, recovered[0..res.payload_len]);

    // Receiver index mismatch rejection
    const bad_rx = WireGuardTunnel.decapsulateData(
        &tunnel_key,
        0x99999999,
        wire_packet[0..wire_len],
        &recovered,
    );
    try std.testing.expectError(error.ReceiverIndexMismatch, bad_rx);

    // Corrupted payload tampering rejection
    var tampered_packet = wire_packet;
    tampered_packet[TRANSPORT_HEADER_SIZE + 2] ^= 0x40;
    const bad_auth = WireGuardTunnel.decapsulateData(
        &tunnel_key,
        rx_index,
        tampered_packet[0..wire_len],
        &recovered,
    );
    try std.testing.expectError(error.AuthenticationFailed, bad_auth);
}
