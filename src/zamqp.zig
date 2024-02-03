const std = @import("std");
const mem = std.mem;
const meta = std.meta;
const c = std.c;

pub const c_api = struct {
    pub extern fn amqp_version_number() u32;
    pub extern fn amqp_version() [*:0]const u8;
    pub extern fn amqp_error_string2(err: status_t) [*:0]const u8;
    pub extern fn amqp_cstring_bytes(cstr: [*:0]const u8) bytes_t;
    pub extern fn amqp_parse_url(url: [*:0]u8, parsed: *ConnectionInfo) status_t;

    // Connection
    pub const connection_state_t = opaque {};

    pub extern fn amqp_new_connection() ?*connection_state_t;
    pub extern fn amqp_connection_close(state: *connection_state_t, code: c_int) RpcReply;
    pub extern fn amqp_destroy_connection(state: *connection_state_t) status_t;
    pub extern fn amqp_login(state: *connection_state_t, vhost: [*:0]const u8, channel_max: c_int, frame_max: c_int, heartbeat: c_int, sasl_method: sasl_method_t, ...) RpcReply;
    pub extern fn amqp_maybe_release_buffers(state: *connection_state_t) void;
    pub extern fn amqp_get_rpc_reply(state: *connection_state_t) RpcReply;
    pub extern fn amqp_simple_wait_frame_noblock(state: *connection_state_t, decoded_frame: *Frame, tv: ?*c.timeval) status_t;
    pub extern fn amqp_consume_message(state: *connection_state_t, envelope: *Envelope, timeout: ?*c.timeval, flags_t: c_int) RpcReply;

    // Socket
    pub const socket_t = opaque {};

    pub extern fn amqp_socket_open_noblock(self: *socket_t, host: [*:0]const u8, port: c_int, timeout: ?*c.timeval) status_t;

    pub extern fn amqp_tcp_socket_new(state: *connection_state_t) ?*socket_t;
    pub extern fn amqp_tcp_socket_set_sockfd(self: *socket_t, sockfd: c_int) void;

    pub extern fn amqp_ssl_socket_new(state: *connection_state_t) ?*socket_t;
    pub extern fn amqp_ssl_socket_set_cacert(self: *socket_t, cacert: [*:0]const u8) status_t;
    pub extern fn amqp_ssl_socket_set_key(self: *socket_t, cert: [*:0]const u8, key: [*:0]const u8) status_t;
    pub extern fn amqp_ssl_socket_set_key_buffer(self: *socket_t, cert: [*:0]const u8, key: ?*const anyopaque, n: usize) status_t;
    pub extern fn amqp_ssl_socket_set_verify_peer(self: *socket_t, verify: boolean_t) void;
    pub extern fn amqp_ssl_socket_set_verify_hostname(self: *socket_t, verify: boolean_t) void;
    pub extern fn amqp_ssl_socket_set_ssl_versions(self: *socket_t, min: c_api.tls_version_t, max: c_api.tls_version_t) status_t;

    // Channel

    pub extern fn amqp_channel_open(state: *connection_state_t, channel: channel_t) ?*channel_open_ok_t;
    pub extern fn amqp_basic_get(state: *connection_state_t, channel: channel_t, queue: bytes_t, no_ack: boolean_t) RpcReply;
    pub extern fn amqp_read_message(state: *connection_state_t, channel: channel_t, message: *Message, flags: c_int) RpcReply;
    pub extern fn amqp_basic_publish(
        state: *connection_state_t,
        channel: channel_t,
        exchange: bytes_t,
        routing_key: bytes_t,
        mandatory: boolean_t,
        immediate: boolean_t,
        properties: *const BasicProperties,
        body: bytes_t,
    ) status_t;
    pub extern fn amqp_basic_consume(
        state: *connection_state_t,
        channel: channel_t,
        queue: bytes_t,
        consumer_tag: bytes_t,
        no_local: boolean_t,
        no_ack: boolean_t,
        exclusive: boolean_t,
        arguments: table_t,
    ) ?*basic_consume_ok_t;
    pub extern fn amqp_exchange_declare(
        state: *connection_state_t,
        channel: channel_t,
        exchange: bytes_t,
        type_: bytes_t,
        passive: boolean_t,
        durable: boolean_t,
        auto_delete: boolean_t,
        internal: boolean_t,
        arguments: table_t,
    ) ?*exchange_declare_ok_t;
    pub extern fn amqp_queue_declare(
        state: *connection_state_t,
        channel: channel_t,
        queue: bytes_t,
        passive: boolean_t,
        durable: boolean_t,
        exclusive: boolean_t,
        auto_delete: boolean_t,
        arguments: table_t,
    ) ?*queue_declare_ok_t;
    pub extern fn amqp_queue_bind(
        state: *connection_state_t,
        channel: channel_t,
        queue: bytes_t,
        exchange: bytes_t,
        routing_key: bytes_t,
        arguments: table_t,
    ) ?*queue_bind_ok_t;
    pub extern fn amqp_basic_ack(state: *connection_state_t, channel: channel_t, delivery_tag: u64, multiple: boolean_t) status_t;
    pub extern fn amqp_basic_reject(state: *connection_state_t, channel: channel_t, delivery_tag: u64, requeue: boolean_t) status_t;
    pub extern fn amqp_basic_qos(state: *connection_state_t, channel: channel_t, prefetch_size: u32, prefetch_count: u16, global: boolean_t) ?*basic_qos_ok_t;
    pub extern fn amqp_channel_close(state: *connection_state_t, channel: channel_t, code: c_int) RpcReply;
    pub extern fn amqp_maybe_release_buffers_on_channel(state: *connection_state_t, channel: channel_t) void;

    pub extern fn amqp_destroy_message(message: *Message) void;

    pub extern fn amqp_destroy_envelope(envelope: *Envelope) void;

    pub extern const amqp_empty_bytes: bytes_t;
    pub extern const amqp_empty_table: table_t;
    pub extern const amqp_empty_array: array_t;

    pub const sasl_method_t = enum(c_int) {
        UNDEFINED = -1,
        PLAIN = 0,
        EXTERNAL = 1,
        _,
    };

    pub const basic_qos_ok_t = extern struct {
        dummy: u8,
    };
    pub const exchange_declare_ok_t = extern struct {
        dummy: u8,
    };
    pub const queue_bind_ok_t = extern struct {
        dummy: u8,
    };
};

const log = std.log.scoped(.zamqp);

pub const boolean_t = c_int;
pub const flags_t = u32;
pub const channel_t = u16;

pub const bytes_t = extern struct {
    len: usize,
    bytes: ?[*]const u8,

    pub fn init(buf: []const u8) bytes_t {
        if (buf.len == 0) return empty();
        return .{ .len = buf.len, .bytes = buf.ptr };
    }

    pub fn slice(self: bytes_t) ?[]const u8 {
        return (self.bytes orelse return null)[0..self.len];
    }

    pub const initZ = c_api.amqp_cstring_bytes;

    pub fn empty() bytes_t {
        return .{ .len = 0, .bytes = null };
    }
};

pub const array_t = extern struct {
    num_entries: c_int,
    entries: ?*opaque {},

    pub fn empty() array_t {
        return .{ .num_entries = 0, .entries = null };
    }
};

pub const table_t = extern struct {
    num_entries: c_int,
    entries: ?[*]table_entry_t,

    pub fn empty() table_t {
        return .{ .num_entries = 0, .entries = null };
    }

    pub fn init(allocator: std.mem.Allocator, s: anytype) !table_t {
        const t = @TypeOf(s);
        const ti = @typeInfo(t);
        if (ti != .Struct) {
            return error.ArgumentNoStruct;
        }

        const fields = std.meta.fields(t);
        var entries = try allocator.alloc(table_entry_t, fields.len);

        inline for (fields, 0..) |f, i| {
            entries[i] = try table_entry_t.init(f.name, @field(s, f.name));
        }

        return table_t{
            .num_entries = @intCast(entries.len),
            .entries = entries.ptr,
        };
    }

    pub fn deinit(self: *table_t, allocator: std.mem.Allocator) void {
        const entries = self.entries;
        const num_entries = self.num_entries;
        self.entries = null;
        self.num_entries = 0;

        if (entries) |e| {
            allocator.free(e[0..@intCast(num_entries)]);
        }
    }
};

test "table_t init" {
    const allocator = std.testing.allocator;

    const value = .{
        .b = true,
        .int8 = @as(i8, -8),
        .uint8 = @as(u8, 8),
        .int16 = @as(i16, -16),
        .uint16 = @as(u16, 16),
        .int32 = @as(i32, -32),
        .uint32 = @as(u32, 32),
        .int64 = @as(i64, -64),
        .uint64 = @as(u64, 64),
        .s1 = "hello world",
    };

    var e = try table_t.init(allocator, value);
    defer e.deinit(allocator);
}

pub const table_entry_kind = enum(u8) {
    AMQP_FIELD_KIND_BOOLEAN = 't',
    AMQP_FIELD_KIND_I8 = 'b',
    AMQP_FIELD_KIND_U8 = 'B',
    AMQP_FIELD_KIND_I16 = 's',
    AMQP_FIELD_KIND_U16 = 'u',
    AMQP_FIELD_KIND_I32 = 'I',
    AMQP_FIELD_KIND_U32 = 'i',
    AMQP_FIELD_KIND_I64 = 'l',
    AMQP_FIELD_KIND_U64 = 'L',
    //AMQP_FIELD_KIND_F32 = 'f',
    //AMQP_FIELD_KIND_F64 = 'd',
    //AMQP_FIELD_KIND_DECIMAL = 'D',
    AMQP_FIELD_KIND_UTF8 = 'S',
    //AMQP_FIELD_KIND_ARRAY = 'A',
    //AMQP_FIELD_KIND_TIMESTAMP = 'T',
    //AMQP_FIELD_KIND_TABLE = 'F',
    AMQP_FIELD_KIND_VOID = 'V',
    AMQP_FIELD_KIND_BYTES = 'x',
};

pub const table_entry_value_t = extern union {
    AMQP_FIELD_KIND_BOOLEAN: boolean_t,
    AMQP_FIELD_KIND_I8: i8,
    AMQP_FIELD_KIND_U8: u8,
    AMQP_FIELD_KIND_I16: i16,
    AMQP_FIELD_KIND_U16: u16,
    AMQP_FIELD_KIND_I32: i32,
    AMQP_FIELD_KIND_U32: u32,
    AMQP_FIELD_KIND_I64: i64,
    AMQP_FIELD_KIND_U64: u64,
    //AMQP_FIELD_KIND_F32: f32,
    //AMQP_FIELD_KIND_F64: f64,
    //AMQP_FIELD_KIND_DECIMAL = 'D',
    AMQP_FIELD_KIND_UTF8: bytes_t,
    //AMQP_FIELD_KIND_ARRAY = 'A',
    //AMQP_FIELD_KIND_TIMESTAMP = 'T',
    //AMQP_FIELD_KIND_TABLE = 'F',
    AMQP_FIELD_KIND_VOID: void,
    AMQP_FIELD_KIND_BYTES: bytes_t,
};

pub const table_entry_t = extern struct {
    key: bytes_t,
    kind: table_entry_kind = .AMQP_FIELD_KIND_VOID,
    value: table_entry_value_t = undefined,

    pub fn init(key: []const u8, comptime s: anytype) !table_entry_t {
        var e = table_entry_t{
            .key = bytes_t.init(key),
        };

        try e.set(s);

        return e;
    }

    fn set(self: *table_entry_t, s: anytype) !void {
        const t = @TypeOf(s);
        const ti = @typeInfo(t);

        switch (t) {
            bool => {
                self.kind = .AMQP_FIELD_KIND_BOOLEAN;
                self.value.AMQP_FIELD_KIND_BOOLEAN = @intFromBool(s);
            },
            i8 => {
                self.kind = .AMQP_FIELD_KIND_I8;
                self.value.AMQP_FIELD_KIND_I8 = s;
            },
            u8 => {
                self.kind = .AMQP_FIELD_KIND_U8;
                self.value.AMQP_FIELD_KIND_U8 = s;
            },
            i16 => {
                self.kind = .AMQP_FIELD_KIND_I16;
                self.value.AMQP_FIELD_KIND_I16 = s;
            },
            u16 => {
                self.kind = .AMQP_FIELD_KIND_U16;
                self.value.AMQP_FIELD_KIND_U16 = s;
            },
            i32 => {
                self.kind = .AMQP_FIELD_KIND_I32;
                self.value.AMQP_FIELD_KIND_I32 = s;
            },
            u32 => {
                self.kind = .AMQP_FIELD_KIND_U32;
                self.value.AMQP_FIELD_KIND_U32 = s;
            },
            i64 => {
                self.kind = .AMQP_FIELD_KIND_I64;
                self.value.AMQP_FIELD_KIND_I64 = s;
            },
            u64 => {
                self.kind = .AMQP_FIELD_KIND_U64;
                self.value.AMQP_FIELD_KIND_U64 = s;
            },
            else => {
                switch (ti) {
                    .Optional => |_| {
                        if (s) |v| {
                            try self.set(v);
                        } else {
                            return error.NullOptional;
                        }
                    },
                    .Pointer => |p| {
                        const pti = @typeInfo(p.child);

                        switch (pti) {
                            .Array => |a| {
                                switch (a.child) {
                                    u8 => {
                                        self.kind = .AMQP_FIELD_KIND_UTF8;
                                        self.value.AMQP_FIELD_KIND_UTF8 = bytes_t.init(s);
                                    },
                                    else => {
                                        //std.log.err("Unsupported table_entry_t array type: {}", .{ti});

                                        return error.UnsupportedType;
                                    },
                                }
                            },
                            else => {
                                //std.log.err("Unsupported table_entry_t pointer type: {}", .{ti});

                                return error.UnsupportedType;
                            },
                        }
                    },
                    else => {
                        //std.log.err("Unsupported table_entry_t type: {}", .{ti});

                        return error.UnsupportedType;
                    },
                }
            },
        }
    }
};

test "table_entry_t init bool" {
    const key = "hello";
    const value = true;

    const e = try table_entry_t.init(key, value);

    try std.testing.expectEqual(@as(?[*]const u8, key), e.key.bytes);
    try std.testing.expectEqual(table_entry_kind.AMQP_FIELD_KIND_BOOLEAN, e.kind);
    try std.testing.expectEqual(@as(boolean_t, 1), e.value.AMQP_FIELD_KIND_BOOLEAN);
}

test "table_entry_t init i8" {
    const key = "hello";
    const value = @as(i8, 126);

    const e = try table_entry_t.init(key, value);

    try std.testing.expectEqual(@as(?[*]const u8, key), e.key.bytes);
    try std.testing.expectEqual(table_entry_kind.AMQP_FIELD_KIND_I8, e.kind);
    try std.testing.expectEqual(value, e.value.AMQP_FIELD_KIND_I8);
}

test "table_entry_t init u8" {
    const key = "hello";
    const value = @as(u8, 126);

    const e = try table_entry_t.init(key, value);

    try std.testing.expectEqual(@as(?[*]const u8, key), e.key.bytes);
    try std.testing.expectEqual(table_entry_kind.AMQP_FIELD_KIND_U8, e.kind);
    try std.testing.expectEqual(value, e.value.AMQP_FIELD_KIND_U8);
}

test "table_entry_t init i16" {
    const key = "hello";
    const value = @as(i16, 126);

    const e = try table_entry_t.init(key, value);

    try std.testing.expectEqual(@as(?[*]const u8, key), e.key.bytes);
    try std.testing.expectEqual(table_entry_kind.AMQP_FIELD_KIND_I16, e.kind);
    try std.testing.expectEqual(value, e.value.AMQP_FIELD_KIND_I16);
}

test "table_entry_t init u16" {
    const key = "hello";
    const value = @as(u16, 126);

    const e = try table_entry_t.init(key, value);

    try std.testing.expectEqual(@as(?[*]const u8, key), e.key.bytes);
    try std.testing.expectEqual(table_entry_kind.AMQP_FIELD_KIND_U16, e.kind);
    try std.testing.expectEqual(value, e.value.AMQP_FIELD_KIND_U16);
}

test "table_entry_t init i32" {
    const key = "hello";
    const value = @as(i32, 126);

    const e = try table_entry_t.init(key, value);

    try std.testing.expectEqual(@as(?[*]const u8, key), e.key.bytes);
    try std.testing.expectEqual(table_entry_kind.AMQP_FIELD_KIND_I32, e.kind);
    try std.testing.expectEqual(value, e.value.AMQP_FIELD_KIND_I32);
}

test "table_entry_t init u32" {
    const key = "hello";
    const value = @as(u32, 126);

    const e = try table_entry_t.init(key, value);

    try std.testing.expectEqual(@as(?[*]const u8, key), e.key.bytes);
    try std.testing.expectEqual(table_entry_kind.AMQP_FIELD_KIND_U32, e.kind);
    try std.testing.expectEqual(value, e.value.AMQP_FIELD_KIND_U32);
}

test "table_entry_t init i64" {
    const key = "hello";
    const value = @as(i64, 126);

    const e = try table_entry_t.init(key, value);

    try std.testing.expectEqual(@as(?[*]const u8, key), e.key.bytes);
    try std.testing.expectEqual(table_entry_kind.AMQP_FIELD_KIND_I64, e.kind);
    try std.testing.expectEqual(value, e.value.AMQP_FIELD_KIND_I64);
}

test "table_entry_t init u64" {
    const key = "hello";
    const value = @as(u64, 126);

    const e = try table_entry_t.init(key, value);

    try std.testing.expectEqual(@as(?[*]const u8, key), e.key.bytes);
    try std.testing.expectEqual(table_entry_kind.AMQP_FIELD_KIND_U64, e.kind);
    try std.testing.expectEqual(value, e.value.AMQP_FIELD_KIND_U64);
}

test "table_entry_t init optional" {
    const key = "hello";
    const value = @as(?i8, 126);

    const e = try table_entry_t.init(key, value);

    try std.testing.expectEqual(@as(?[*]const u8, key), e.key.bytes);
    try std.testing.expectEqual(table_entry_kind.AMQP_FIELD_KIND_I8, e.kind);
    try std.testing.expectEqual(value, e.value.AMQP_FIELD_KIND_I8);
}

test "table_entry_t init optional null" {
    const key = "hello";
    const value = @as(?i8, null);

    if (table_entry_t.init(key, value)) |_| {
        return error.Unexpected;
    } else |err| {
        try std.testing.expectEqual(error.NullOptional, err);
    }
}

test "table_entry_t init string" {
    const key = "hello";
    const value = "world";

    const e = try table_entry_t.init(key, value);

    try std.testing.expectEqual(@as(?[*]const u8, key), e.key.bytes);
    try std.testing.expectEqual(table_entry_kind.AMQP_FIELD_KIND_UTF8, e.kind);
    try std.testing.expectEqual(@as(?[*]const u8, value), e.value.AMQP_FIELD_KIND_UTF8.bytes);
}

// test "table_entry_t init stringZ" {
//     const key = "hello";
//     const value = @as([*:0]const u8, "world");
//
//     const e = try table_entry_t.init(key, value);
//
//     try std.testing.expectEqual(@as(?[*]const u8, key), e.key.bytes);
//     try std.testing.expectEqual(table_entry_kind.AMQP_FIELD_KIND_UTF8, e.kind);
//     try std.testing.expectEqual(@as(?[*]const u8, value), e.value.AMQP_FIELD_KIND_UTF8.bytes);
// }

test "table_entry_t init unsupported type" {
    const t = struct {};
    const key = "hello";
    const value = t{};

    if (table_entry_t.init(key, value)) |_| {
        return error.Unexpected;
    } else |err| {
        try std.testing.expectEqual(error.UnsupportedType, err);
    }
}

pub const method_t = extern struct {
    id: method_number_t,
    decoded: ?*anyopaque,
};

pub const DEFAULT_FRAME_SIZE: c_int = 131072;
pub const DEFAULT_MAX_CHANNELS: c_int = 2047;
// pub const DEFAULT_HEARTBEAT: c_int = 0;
// pub const DEFAULT_VHOST = "/";

pub const version_number = c_api.amqp_version_number;
pub const version = c_api.amqp_version;

pub const ConnectionInfo = extern struct {
    user: [*:0]u8,
    password: [*:0]u8,
    host: [*:0]u8,
    vhost: [*:0]u8,
    port: c_int,
    ssl: boolean_t,
};

pub fn parse_url(url: [*:0]u8) error{ BadUrl, Unexpected }!ConnectionInfo {
    var result: ConnectionInfo = undefined;
    return switch (c_api.amqp_parse_url(url, &result)) {
        .OK => result,
        .BAD_URL => error.BadUrl,
        else => |code| unexpected(code),
    };
}

pub const Connection = struct {
    handle: *c_api.connection_state_t,

    pub fn new() error{OutOfMemory}!Connection {
        return Connection{ .handle = c_api.amqp_new_connection() orelse return error.OutOfMemory };
    }

    pub fn close(self: Connection, code: ReplyCode) !void {
        return c_api.amqp_connection_close(self.handle, @intFromEnum(code)).ok();
    }

    pub fn destroy(self: *Connection) !void {
        const status = c_api.amqp_destroy_connection(self.handle);
        self.handle = undefined;
        return status.ok();
    }

    pub fn maybe_release_buffers(self: Connection) void {
        c_api.amqp_maybe_release_buffers(self.handle);
    }

    /// Not every function updates this. See docs of `c_api.amqp_get_rpc_reply`.
    pub fn last_rpc_reply(self: Connection) RpcReply {
        return c_api.amqp_get_rpc_reply(self.handle);
    }

    pub fn login(
        self: Connection,
        vhost: [*:0]const u8,
        sasl_auth: SaslAuth,
        extra: struct {
            heartbeat: c_int,
            channel_max: c_int = DEFAULT_MAX_CHANNELS,
            frame_max: c_int = DEFAULT_FRAME_SIZE,
        },
    ) !void {
        return switch (sasl_auth) {
            .plain => |plain| c_api.amqp_login(self.handle, vhost, extra.channel_max, extra.frame_max, extra.heartbeat, .PLAIN, plain.username, plain.password),
            .external => |external| c_api.amqp_login(self.handle, vhost, extra.channel_max, extra.frame_max, extra.heartbeat, .EXTERNAL, external.identity),
        }.ok();
    }

    pub fn simple_wait_frame(self: Connection, timeout: ?*c.timeval) !Frame {
        var f: Frame = undefined;
        try c_api.amqp_simple_wait_frame_noblock(self.handle, &f, timeout).ok();
        return f;
    }

    pub fn consume_message(self: Connection, timeout: ?*c.timeval, flags: c_int) !Envelope {
        var e: Envelope = undefined;
        try c_api.amqp_consume_message(self.handle, &e, timeout, flags).ok();
        return e;
    }

    pub fn channel(self: Connection, number: channel_t) Channel {
        return .{ .connection = self, .number = number };
    }

    pub const SaslAuth = union(enum) {
        plain: struct {
            username: [*:0]const u8,
            password: [*:0]const u8,
        },
        external: struct {
            identity: [*:0]const u8,
        },
    };
};

test "rabbitmq localhost connection" {
    const allocator = std.testing.allocator;

    var conn = try Connection.new();
    defer {
        conn.destroy() catch unreachable;
    }

    var socket = try TcpSocket.new(conn);
    try socket.open("localhost", 5672, null);
    defer {
        conn.close(.REPLY_SUCCESS) catch unreachable;
    }

    const auth = Connection.SaslAuth{ .plain = .{
        .username = "guest",
        .password = "guest",
    } };

    try conn.login("/", auth, .{ .heartbeat = 30 });

    var channel = conn.channel(1);
    _ = try channel.open();
    defer {
        channel.close(.REPLY_SUCCESS) catch unreachable;
    }

    var queueArguments = try table_t.init(allocator, .{
        .@"x-max-priority" = @as(u8, 2),
        .@"x-queue-type" = "classic",
    });
    defer queueArguments.deinit(allocator);

    _ = try channel.queue_declare(bytes_t.init("zamqp-unittest"), .{ .auto_delete = true, .exclusive = true, .arguments = queueArguments });
}

pub const Channel = struct {
    connection: Connection,
    number: channel_t,

    pub fn open(self: Channel) !*channel_open_ok_t {
        return c_api.amqp_channel_open(self.connection.handle, self.number) orelse self.connection.last_rpc_reply().err();
    }

    pub fn close(self: Channel, code: ReplyCode) !void {
        return c_api.amqp_channel_close(self.connection.handle, self.number, @intFromEnum(code)).ok();
    }

    pub fn exchange_declare(
        self: Channel,
        exchange: bytes_t,
        type_: bytes_t,
        extra: struct {
            passive: bool = false,
            durable: bool = false,
            auto_delete: bool = false,
            internal: bool = false,
            arguments: table_t = table_t.empty(),
        },
    ) !void {
        _ = c_api.amqp_exchange_declare(
            self.connection.handle,
            self.number,
            exchange,
            type_,
            @intFromBool(extra.passive),
            @intFromBool(extra.durable),
            @intFromBool(extra.auto_delete),
            @intFromBool(extra.internal),
            extra.arguments,
        ) orelse return self.connection.last_rpc_reply().err();
    }

    pub fn queue_declare(
        self: Channel,
        queue: bytes_t,
        extra: struct {
            passive: bool = false,
            durable: bool = false,
            exclusive: bool = false,
            auto_delete: bool = false,
            arguments: table_t = table_t.empty(),
        },
    ) !*queue_declare_ok_t {
        return c_api.amqp_queue_declare(
            self.connection.handle,
            self.number,
            queue,
            @intFromBool(extra.passive),
            @intFromBool(extra.durable),
            @intFromBool(extra.exclusive),
            @intFromBool(extra.auto_delete),
            extra.arguments,
        ) orelse self.connection.last_rpc_reply().err();
    }

    pub fn queue_bind(self: Channel, queue: bytes_t, exchange: bytes_t, routing_key: bytes_t, arguments: table_t) !void {
        _ = c_api.amqp_queue_bind(self.connection.handle, self.number, queue, exchange, routing_key, arguments) orelse return self.connection.last_rpc_reply().err();
    }

    pub fn basic_get(
        self: Channel,
        queue: bytes_t,
        extra: struct {
            no_ack: bool = false,
        },
    ) !void {
        return c_api.amqp_basic_get(
            self.connection.handle,
            self.number,
            queue,
            @intFromBool(extra.no_ack),
        ).ok();
    }

    pub fn basic_publish(
        self: Channel,
        exchange: bytes_t,
        routing_key: bytes_t,
        body: bytes_t,
        properties: BasicProperties,
        extra: struct {
            mandatory: bool = false,
            immediate: bool = false,
        },
    ) !void {
        return c_api.amqp_basic_publish(
            self.connection.handle,
            self.number,
            exchange,
            routing_key,
            @intFromBool(extra.mandatory),
            @intFromBool(extra.immediate),
            &properties,
            body,
        ).ok();
    }

    pub fn basic_consume(
        self: Channel,
        queue: bytes_t,
        extra: struct {
            consumer_tag: bytes_t = bytes_t.empty(),
            no_local: bool = false,
            no_ack: bool = false,
            exclusive: bool = false,
            arguments: table_t = table_t.empty(),
        },
    ) !*basic_consume_ok_t {
        return c_api.amqp_basic_consume(
            self.connection.handle,
            self.number,
            queue,
            extra.consumer_tag,
            @intFromBool(extra.no_local),
            @intFromBool(extra.no_ack),
            @intFromBool(extra.exclusive),
            extra.arguments,
        ) orelse self.connection.last_rpc_reply().err();
    }

    pub fn basic_ack(self: Channel, delivery_tag: u64, multiple: bool) !void {
        return c_api.amqp_basic_ack(self.connection.handle, self.number, delivery_tag, @intFromBool(multiple)).ok();
    }

    pub fn basic_reject(self: Channel, delivery_tag: u64, requeue: bool) !void {
        return c_api.amqp_basic_reject(self.connection.handle, self.number, delivery_tag, @intFromBool(requeue)).ok();
    }

    pub fn basic_qos(self: Channel, prefetch_size: u32, prefetch_count: u16, global: bool) !void {
        _ = c_api.amqp_basic_qos(
            self.connection.handle,
            self.number,
            prefetch_size,
            prefetch_count,
            @intFromBool(global),
        ) orelse return self.connection.last_rpc_reply().err();
    }

    pub fn read_message(self: Channel, flags: c_int) !Message {
        var msg: Message = undefined;
        try c_api.amqp_read_message(self.connection.handle, self.number, &msg, flags).ok();
        return msg;
    }

    pub fn maybe_release_buffers(self: Channel) void {
        c_api.amqp_maybe_release_buffers_on_channel(self.connection.handle, self.number);
    }
};

pub const TcpSocket = struct {
    handle: *c_api.socket_t,

    pub fn new(connection: Connection) error{OutOfMemory}!TcpSocket {
        return TcpSocket{ .handle = c_api.amqp_tcp_socket_new(connection.handle) orelse return error.OutOfMemory };
    }

    pub fn set_sockfd(self: TcpSocket, sockfd: c_int) void {
        c_api.amqp_tcp_socket_set_sockfd(self.handle, sockfd);
    }

    pub fn open(self: TcpSocket, host: [*:0]const u8, port: c_int, timeout: ?*c.timeval) !void {
        return c_api.amqp_socket_open_noblock(self.handle, host, port, timeout).ok();
    }
};

pub const SslSocket = struct {
    handle: *c_api.socket_t,

    pub fn new(connection: Connection) error{OutOfMemory}!SslSocket {
        return SslSocket{ .handle = c_api.amqp_ssl_socket_new(connection.handle) orelse return error.OutOfMemory };
    }

    pub fn open(self: SslSocket, host: [*:0]const u8, port: c_int, timeout: ?*c.timeval) !void {
        return c_api.amqp_socket_open_noblock(self.handle, host, port, timeout).ok();
    }

    pub fn set_cacert(self: SslSocket, cacert_path: [*:0]const u8) !void {
        return c_api.amqp_ssl_socket_set_cacert(self.handle, cacert_path).ok();
    }

    pub fn set_key(self: SslSocket, cert_path: [*:0]const u8, key_path: [*:0]const u8) !void {
        return c_api.amqp_ssl_socket_set_key(self.handle, cert_path, key_path).ok();
    }

    pub fn set_key_buffer(self: SslSocket, cert_path: [*:0]const u8, key: []const u8) !void {
        return c_api.amqp_ssl_socket_set_key_buffer(self.handle, cert_path, key.ptr, key.len).ok();
    }

    pub fn set_verify_peer(self: SslSocket, verify: bool) void {
        c_api.amqp_ssl_socket_set_verify_peer(self.handle, @intFromBool(verify));
    }

    pub fn set_verify_hostname(self: SslSocket, verify: bool) void {
        c_api.amqp_ssl_socket_set_verify_hostname(self.handle, @intFromBool(verify));
    }

    pub fn set_ssl_versions(self: SslSocket, min: TlsVersion, max: TlsVersion) error{ Unsupported, InvalidParameter, Unexpected }!void {
        return switch (c_api.amqp_ssl_socket_set_ssl_versions(self.handle, min, max)) {
            .OK => {},
            .UNSUPPORTED => error.Unsupported,
            .INVALID_PARAMETER => error.InvalidParameter,
            else => |code| unexpected(code),
        };
    }

    const TlsVersion = enum(c_api.c_int) {
        v1 = 1,
        v1_1 = 2,
        v1_2 = 3,
        vLATEST = 65535,
        _,
    };
};

pub const RpcReply = extern struct {
    reply_type: response_type_t,
    reply: method_t,
    library_error: status_t,

    pub fn ok(self: RpcReply) Error!void {
        return switch (self.reply_type) {
            .NORMAL => {},
            .NONE => error.SocketError,
            .LIBRARY_EXCEPTION => self.library_error.ok(),
            .SERVER_EXCEPTION => switch (self.reply.id) {
                .CONNECTION_CLOSE => error.ConnectionClosed,
                .CHANNEL_CLOSE => error.ChannelClosed,
                else => error.UnexpectedReply,
            },
            _ => {
                log.err("unexpected librabbitmq response type, value {}", .{self.reply_type});
                return error.Unexpected;
            },
        };
    }

    pub fn err(self: RpcReply) Error {
        if (self.ok()) |_| {
            log.err("expected librabbitmq error, got success instead", .{});
            return error.Unexpected;
        } else |e| return e;
    }

    pub const response_type_t = enum(c_int) {
        NONE = 0,
        NORMAL = 1,
        LIBRARY_EXCEPTION = 2,
        SERVER_EXCEPTION = 3,
        _,
    };
};

/// Do not use fields directly to avoid bugs.
pub const BasicProperties = extern struct {
    _flags: flags_t,
    _content_type: bytes_t,
    _content_encoding: bytes_t,
    _headers: table_t,
    _delivery_mode: u8,
    _priority: u8,
    _correlation_id: bytes_t,
    _reply_to: bytes_t,
    _expiration: bytes_t,
    _message_id: bytes_t,
    _timestamp: u64,
    _type_: bytes_t,
    _user_id: bytes_t,
    _app_id: bytes_t,
    _cluster_id: bytes_t,

    pub fn init(fields: anytype) BasicProperties {
        var props: BasicProperties = undefined;
        props._flags = 0;

        inline for (meta.fields(@TypeOf(fields))) |f| {
            @field(props, "_" ++ f.name) = @field(fields, f.name);
            props._flags |= @intFromEnum(@field(Flag, f.name));
        }

        return props;
    }

    pub fn get(self: BasicProperties, comptime flag: Flag) ?flag.Type() {
        if (self._flags & @intFromEnum(flag) == 0) return null;
        return @field(self, "_" ++ @tagName(flag));
    }

    pub fn set(self: *BasicProperties, comptime flag: Flag, value: ?flag.Type()) void {
        if (value) |val| {
            self._flags |= @intFromEnum(flag);
            @field(self, "_" ++ @tagName(flag)) = val;
        } else {
            self._flags &= ~@intFromEnum(flag);
            @field(self, "_" ++ @tagName(flag)) = undefined;
        }
    }

    pub const Flag = enum(flags_t) {
        content_type = 1 << 15,
        content_encoding = 1 << 14,
        headers = 1 << 13,
        delivery_mode = 1 << 12,
        priority = 1 << 11,
        correlation_id = 1 << 10,
        reply_to = 1 << 9,
        expiration = 1 << 8,
        message_id = 1 << 7,
        timestamp = 1 << 6,
        type_ = 1 << 5,
        user_id = 1 << 4,
        app_id = 1 << 3,
        cluster_id = 1 << 2,
        _,

        pub fn Type(comptime flag: Flag) type {
            const needle = "_" ++ @tagName(flag);
            inline for (comptime meta.fields(BasicProperties)) |field| {
                if (comptime mem.eql(u8, field.name, needle)) return field.type;
            }
            unreachable;
        }
    };
};

pub const pool_blocklist_t = extern struct {
    num_blocks: c_int,
    blocklist: [*]?*anyopaque,
};

pub const pool_t = extern struct {
    pagesize: usize,
    pages: pool_blocklist_t,
    large_blocks: pool_blocklist_t,
    next_page: c_int,
    alloc_block: [*]u8,
    alloc_used: usize,
};

pub const Message = extern struct {
    properties: BasicProperties,
    body: bytes_t,
    pool: pool_t,

    pub fn destroy(self: *Message) void {
        c_api.amqp_destroy_message(self);
    }
};

pub const Envelope = extern struct {
    channel: channel_t,
    consumer_tag: bytes_t,
    delivery_tag: u64,
    redelivered: boolean_t,
    exchange: bytes_t,
    routing_key: bytes_t,
    message: Message,

    pub fn destroy(self: *Envelope) void {
        c_api.amqp_destroy_envelope(self);
    }
};

pub const Frame = extern struct {
    frame_type: Type,
    channel: channel_t,
    payload: extern union {
        /// frame_type == .METHOD
        method: method_t,
        /// frame_type == .HEADER
        properties: extern struct {
            class_id: u16,
            body_size: u64,
            decoded: ?*anyopaque,
            raw: bytes_t,
        },
        /// frame_type == BODY
        body_fragment: bytes_t,
        /// used during initial handshake
        protocol_header: extern struct {
            transport_high: u8,
            transport_low: u8,
            protocol_version_major: u8,
            protocol_version_minor: u8,
        },
    },

    pub const Type = enum(c_api.u8) {
        METHOD = 1,
        HEADER = 2,
        BODY = 3,
        HEARTBEAT = 8,
        _,
    };
};

pub const Error = LibraryError || ServerError;

pub const ServerError = error{
    ConnectionClosed,
    ChannelClosed,
    UnexpectedReply,
};

pub const LibraryError = error{
    OutOfMemory,
    BadAmqpData,
    UnknownClass,
    UnknownMethod,
    HostnameResolutionFailed,
    IncompatibleAmqpVersion,
    ConnectionClosed,
    BadUrl,
    SocketError,
    InvalidParameter,
    TableTooBig,
    WrongMethod,
    Timeout,
    TimerFailure,
    HeartbeatTimeout,
    UnexpectedState,
    SocketClosed,
    SocketInUse,
    BrokerUnsupportedSaslMethod,
    Unsupported,
    TcpError,
    TcpSocketlibInitError,
    SslError,
    SslHostnameVerifyFailed,
    SslPeerVerifyFailed,
    SslConnectionFailed,
    Unexpected,
};

fn unexpected(status: status_t) error{Unexpected} {
    log.err("unexpected librabbitmq error, code {}, message {s}", .{ status, status.string() });
    return error.Unexpected;
}

pub const status_t = enum(c_int) {
    OK = 0,
    NO_MEMORY = -1,
    BAD_AMQP_DATA = -2,
    UNKNOWN_CLASS = -3,
    UNKNOWN_METHOD = -4,
    HOSTNAME_RESOLUTION_FAILED = -5,
    INCOMPATIBLE_AMQP_VERSION = -6,
    CONNECTION_CLOSED = -7,
    BAD_URL = -8,
    SOCKET_ERROR = -9,
    INVALID_PARAMETER = -10,
    TABLE_TOO_BIG = -11,
    WRONG_METHOD = -12,
    TIMEOUT = -13,
    TIMER_FAILURE = -14,
    HEARTBEAT_TIMEOUT = -15,
    UNEXPECTED_STATE = -16,
    SOCKET_CLOSED = -17,
    SOCKET_INUSE = -18,
    BROKER_UNSUPPORTED_SASL_METHOD = -19,
    UNSUPPORTED = -20,
    TCP_ERROR = -256,
    TCP_SOCKETLIB_INIT_ERROR = -257,
    SSL_ERROR = -512,
    SSL_HOSTNAME_VERIFY_FAILED = -513,
    SSL_PEER_VERIFY_FAILED = -514,
    SSL_CONNECTION_FAILED = -515,
    _,

    pub fn ok(status: status_t) LibraryError!void {
        return switch (status) {
            .OK => {},
            .NO_MEMORY => error.OutOfMemory,
            .BAD_AMQP_DATA => error.BadAmqpData,
            .UNKNOWN_CLASS => error.UnknownClass,
            .UNKNOWN_METHOD => error.UnknownMethod,
            .HOSTNAME_RESOLUTION_FAILED => error.HostnameResolutionFailed,
            .INCOMPATIBLE_AMQP_VERSION => error.IncompatibleAmqpVersion,
            .CONNECTION_CLOSED => error.ConnectionClosed,
            .BAD_URL => error.BadUrl,
            .SOCKET_ERROR => error.SocketError,
            .INVALID_PARAMETER => error.InvalidParameter,
            .TABLE_TOO_BIG => error.TableTooBig,
            .WRONG_METHOD => error.WrongMethod,
            .TIMEOUT => error.Timeout,
            .TIMER_FAILURE => error.TimerFailure,
            .HEARTBEAT_TIMEOUT => error.HeartbeatTimeout,
            .UNEXPECTED_STATE => error.UnexpectedState,
            .SOCKET_CLOSED => error.SocketClosed,
            .SOCKET_INUSE => error.SocketInUse,
            .BROKER_UNSUPPORTED_SASL_METHOD => error.BrokerUnsupportedSaslMethod,
            .UNSUPPORTED => error.Unsupported,
            .TCP_ERROR => error.TcpError,
            .TCP_SOCKETLIB_INIT_ERROR => error.TcpSocketlibInitError,
            .SSL_ERROR => error.SslError,
            .SSL_HOSTNAME_VERIFY_FAILED => error.SslHostnameVerifyFailed,
            .SSL_PEER_VERIFY_FAILED => error.SslPeerVerifyFailed,
            .SSL_CONNECTION_FAILED => error.SslConnectionFailed,
            _ => unexpected(status),
        };
    }

    pub const string = c_api.amqp_error_string2;
};

pub const ReplyCode = enum(u16) {
    REPLY_SUCCESS = 200,
    CONTENT_TOO_LARGE = 311,
    NO_ROUTE = 312,
    NO_CONSUMERS = 313,
    ACCESS_REFUSED = 403,
    NOT_FOUND = 404,
    RESOURCE_LOCKED = 405,
    PRECONDITION_FAILED = 406,
    CONNECTION_FORCED = 320,
    INVALID_PATH = 402,
    FRAME_ERROR = 501,
    SYNTAX_ERROR = 502,
    COMMAND_INVALID = 503,
    CHANNEL_ERROR = 504,
    UNEXPECTED_FRAME = 505,
    RESOURCE_ERROR = 506,
    NOT_ALLOWED = 530,
    NOT_IMPLEMENTED = 540,
    INTERNAL_ERROR = 541,
};

pub const method_number_t = enum(u32) {
    CONNECTION_START = 0x000A000A,
    CONNECTION_START_OK = 0x000A000B,
    CONNECTION_SECURE = 0x000A0014,
    CONNECTION_SECURE_OK = 0x000A0015,
    CONNECTION_TUNE = 0x000A001E,
    CONNECTION_TUNE_OK = 0x000A001F,
    CONNECTION_OPEN = 0x000A0028,
    CONNECTION_OPEN_OK = 0x000A0029,
    CONNECTION_CLOSE = 0x000A0032,
    CONNECTION_CLOSE_OK = 0x000A0033,
    CONNECTION_BLOCKED = 0x000A003C,
    CONNECTION_UNBLOCKED = 0x000A003D,
    CHANNEL_OPEN = 0x0014000A,
    CHANNEL_OPEN_OK = 0x0014000B,
    CHANNEL_FLOW = 0x00140014,
    CHANNEL_FLOW_OK = 0x00140015,
    CHANNEL_CLOSE = 0x00140028,
    CHANNEL_CLOSE_OK = 0x00140029,
    ACCESS_REQUEST = 0x001E000A,
    ACCESS_REQUEST_OK = 0x001E000B,
    EXCHANGE_DECLARE = 0x0028000A,
    EXCHANGE_DECLARE_OK = 0x0028000B,
    EXCHANGE_DELETE = 0x00280014,
    EXCHANGE_DELETE_OK = 0x00280015,
    EXCHANGE_BIND = 0x0028001E,
    EXCHANGE_BIND_OK = 0x0028001F,
    EXCHANGE_UNBIND = 0x00280028,
    EXCHANGE_UNBIND_OK = 0x00280033,
    QUEUE_DECLARE = 0x0032000A,
    QUEUE_DECLARE_OK = 0x0032000B,
    QUEUE_BIND = 0x00320014,
    QUEUE_BIND_OK = 0x00320015,
    QUEUE_PURGE = 0x0032001E,
    QUEUE_PURGE_OK = 0x0032001F,
    QUEUE_DELETE = 0x00320028,
    QUEUE_DELETE_OK = 0x00320029,
    QUEUE_UNBIND = 0x00320032,
    QUEUE_UNBIND_OK = 0x00320033,
    BASIC_QOS = 0x003C000A,
    BASIC_QOS_OK = 0x003C000B,
    BASIC_CONSUME = 0x003C0014,
    BASIC_CONSUME_OK = 0x003C0015,
    BASIC_CANCEL = 0x003C001E,
    BASIC_CANCEL_OK = 0x003C001F,
    BASIC_PUBLISH = 0x003C0028,
    BASIC_RETURN = 0x003C0032,
    BASIC_DELIVER = 0x003C003C,
    BASIC_GET = 0x003C0046,
    BASIC_GET_OK = 0x003C0047,
    BASIC_GET_EMPTY = 0x003C0048,
    BASIC_ACK = 0x003C0050,
    BASIC_REJECT = 0x003C005A,
    BASIC_RECOVER_ASYNC = 0x003C0064,
    BASIC_RECOVER = 0x003C006E,
    BASIC_RECOVER_OK = 0x003C006F,
    BASIC_NACK = 0x003C0078,
    TX_SELECT = 0x005A000A,
    TX_SELECT_OK = 0x005A000B,
    TX_COMMIT = 0x005A0014,
    TX_COMMIT_OK = 0x005A0015,
    TX_ROLLBACK = 0x005A001E,
    TX_ROLLBACK_OK = 0x005A001F,
    CONFIRM_SELECT = 0x0055000A,
    CONFIRM_SELECT_OK = 0x0055000B,
    _,
};

// Messages

pub const channel_open_ok_t = extern struct {
    channel_id: bytes_t,
};

pub const queue_declare_ok_t = extern struct {
    queue: bytes_t,
    message_count: u32,
    consumer_count: u32,
};

pub const basic_consume_ok_t = extern struct {
    consumer_tag: bytes_t,
};

pub const connection_close_t = extern struct {
    reply_code: ReplyCode,
    reply_text: bytes_t,
    class_id: u16,
    method_id: u16,
};

pub const channel_close_t = extern struct {
    reply_code: ReplyCode,
    reply_text: bytes_t,
    class_id: u16,
    method_id: u16,
};
