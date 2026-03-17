const std = @import("std");
const Type = std.builtin.Type;
const Operation = @import("operation.zig").Operation;
const Status = @import("operation.zig").Status;
const ValueType = @import("operation.zig").ValueType;
const Attribute = @import("operation.zig").Attribute;
const StatsTag = @import("operation.zig").StatsTag;
const DocType = @import("operation.zig").DocType;
const ArrayList = std.ArrayList;
const Allocator = std.mem.Allocator;
const Buffer = @import("utils").Buffer;

pub const Packet = struct {
    checksum: u64,
    packet_length: u32,
    packet_id: u32,
    timestamp: i64,
    // auth_token: [32]u8,
    op: Operation,

    pub fn calcMsgSize(pck: *const Packet) usize {
        var size: usize = 0;
        size += @sizeOf(u64); // checksum
        size += @sizeOf(u32); // packet_length
        size += @sizeOf(u32); // packet_id
        size += @sizeOf(i64); // timestamp
        // size += 32; // auth_token
        size += 1; // op tag (u8)
        // Add operation-specific size
        switch (pck.op) {
            .Create => |data| {
                size += 1; // doc_type (u8)
                size += 4 + @as(u32, @intCast(data.ns.len)); // ns string
                size += 4 + @as(u32, @intCast(data.payload.len)); // payload string
                size += 1; // auto_create (u8)
                size += 1; // has_metadata (u8)
                if (data.metadata) |meta| {
                    size += 4 + @as(u32, @intCast(meta.len)); // metadata string
                }
            },
            .Read => |data| {
                size += 4 + @as(u32, @intCast(data.store_ns.len)); // store_ns string
                size += 16; // id (u128)
            },
            .Update => |data| {
                size += 4 + @as(u32, @intCast(data.store_ns.len)); // store_ns string
                size += 16; // id (u128)
                size += 4 + @as(u32, @intCast(data.payload.len)); // payload string
            },
            .Delete => |data| {
                size += 4 + @as(u32, @intCast(data.store_ns.len)); // store_ns string
                size += 1; // has_id (u8)
                if (data.id) |_| {
                    size += 16; // id (u128)
                }
                size += 1; // has_query_json (u8)
                if (data.query_json) |qj| {
                    size += 4 + @as(u32, @intCast(qj.len)); // query_json string
                }
            },
            .List => |data| {
                size += 1; // doc_type (u8)
                size += 1; // has_ns (u8)
                if (data.ns) |ns| {
                    size += 4 + @as(u32, @intCast(ns.len)); // ns string
                }
                size += 1; // has_limit (u8)
                if (data.limit) |_| {
                    size += 4; // limit (u32)
                }
                size += 1; // has_offset (u8)
                if (data.offset) |_| {
                    size += 4; // offset (u32)
                }
            },
            .Drop => |data| {
                size += 1; // doc_type (u8)
                size += 4 + @as(u32, @intCast(data.name.len)); // name string
            },
            .Insert => |data| {
                size += 4 + @as(u32, @intCast(data.store_ns.len)); // store_ns string
                size += 4 + @as(u32, @intCast(data.payload.len)); // payload string
                size += 1; // auto_create (u8)
            },
            .BatchInsert => |data| {
                size += 4 + @as(u32, @intCast(data.store_ns.len)); // store_ns string
                size += 4; // count (u32)
                for (data.values) |value| {
                    size += 4 + @as(u32, @intCast(value.len)); // value string
                }
            },
            .Range => |data| {
                size += 4 + @as(u32, @intCast(data.store_ns.len)); // store_ns string
                size += data.start_key.calcAttributeSize(); // start_key attribute
                size += data.end_key.calcAttributeSize(); // end_key attribute
            },
            .Query => |data| {
                size += 4 + @as(u32, @intCast(data.store_ns.len)); // store_ns string
                size += 4 + @as(u32, @intCast(data.query_json.len)); // query_json string
            },
            .Aggregate => |data| {
                size += 4 + @as(u32, @intCast(data.store_ns.len)); // store_ns string
                size += 4 + @as(u32, @intCast(data.aggregate_json.len)); // aggregate_json string
            },
            .Scan => |data| {
                size += 4 + @as(u32, @intCast(data.store_ns.len)); // store_ns string
                size += 1; // has_start_key (u8)
                if (data.start_key) |_| {
                    size += 16; // start_key (u128)
                }
                size += 4; // limit (u32)
                size += 4; // skip (u32)
            },
            .Authenticate => |data| {
                size += 4 + @as(u32, @intCast(data.uid.len)); // uid string
                size += 4 + @as(u32, @intCast(data.key.len)); // key string
            },
            .ShipWal => |data| {
                size += 1; // op_kind (u8)
                size += 4 + @as(u32, @intCast(data.store_ns.len)); // store_ns string
                size += 8; // lsn (u64)
                size += 16; // doc_id (u128)
                size += 8; // timestamp (i64)
                size += 4 + @as(u32, @intCast(data.data.len)); // data bytes
            },
            .Logout => {},
            .RegenerateKey => |data| {
                size += 4 + @as(u32, @intCast(data.uid.len)); // uid string
            },
            .Restore => |data| {
                size += 4 + @as(u32, @intCast(data.backup_path.len)); // backup_path string
                size += 4 + @as(u32, @intCast(data.target_path.len)); // target_path string
            },
            .Backup => |data| {
                size += 4 + @as(u32, @intCast(data.path.len)); // path string
            },
            .Reply => |data| {
                size += 1; // status (u8)
                size += 1; // has_data (u8)
                if (data.data) |d| {
                    size += 4 + @as(u32, @intCast(d.len)); // data string
                }
            },
            .BatchReply => |data| {
                size += 1; // status (u8)
                size += 4; // count (u32)
                for (data.results) |result| {
                    size += 4 + @as(u32, @intCast(result.len)); // result string
                }
            },
            .Flush => {},
            .Shutdown => {},
            .Vlogs => {},
            .Stats => {
                size += 1; // stat tag (u8)
            },
            .Collect => |data| {
                size += 4 + @as(u32, @intCast(data.vlogs.len)); // u32 count + u8 per vlog
            },
            .SetMode => {
                size += 1; // online (u8 bool)
            },
            .UpdateUser => |data| {
                size += 4 + @as(u32, @intCast(data.uid.len)); // uid string
                size += 1; // role (u8)
            },
            .GetConfig => {},
            .SetConfig => |data| {
                size += 4 + @as(u32, @intCast(data.data.len)); // data string
            },
            .Export => |data| {
                size += 4 + @as(u32, @intCast(data.store_ns.len));
                size += 4 + @as(u32, @intCast(data.format.len));
                size += 4 + @as(u32, @intCast(data.file_path.len));
            },
            .Import => |data| {
                size += 4 + @as(u32, @intCast(data.payload.len));
            },
        }
        return size;
    }

    pub fn serialize(self: Packet, buf: *Buffer) ![]u8 {
        const w = buf.writer();
        try w.writeInt(u64, self.checksum, .little);
        try w.writeInt(u32, self.packet_length, .little);
        try w.writeInt(u32, self.packet_id, .little);
        try w.writeInt(i64, self.timestamp, .little);
        try Packet.serializeOperation(w, self.op);
        return buf.slice();
    }

    pub fn deserialize(allocator: Allocator, data: []const u8) !Packet {
        var offset: usize = 0;
        const checksum = try Packet.readBytes(data, &offset, u64);
        const packet_length = try Packet.readBytes(data, &offset, u32);
        const packet_id = try Packet.readBytes(data, &offset, u32);
        const timestamp = try Packet.readBytes(data, &offset, i64);
        // const auth_token = try Packet.readBytes(data, &offset, [32]u8);
        const op = try Packet.deserializeOperation(allocator, data, &offset);
        return Packet{
            .checksum = checksum,
            .packet_length = packet_length,
            .packet_id = packet_id,
            .timestamp = timestamp,
            // .auth_token = auth_token,
            .op = op,
        };
    }

    pub fn free(allocator: Allocator, pck: Packet) void {
        switch (pck.op) {
            // Most operations use string slices from packet data - no explicit free needed
            .Create, .Drop, .List => {},
            .Insert, .Read, .Update, .Delete => {},
            .Range, .Query, .Aggregate, .Scan => {},
            .Authenticate, .ShipWal, .Logout => {},
            .RegenerateKey, .UpdateUser, .GetConfig, .SetConfig => {},
            .Restore, .Backup => {},
            .Export, .Import => {},
            .Reply, .Flush, .Shutdown => {},
            .Stats, .Vlogs, .SetMode => {},
            .Collect => |data| {
                allocator.free(data.vlogs);
            },
            // BatchInsert and BatchReply have arrays that need freeing
            .BatchInsert => |data| {
                allocator.free(data.values);
            },
            .BatchReply => |data| {
                for (data.results) |result| {
                    allocator.free(result);
                }
                allocator.free(data.results);
            },
        }
    }

    fn serializeAttribute(w: Buffer.Writer, attr: Attribute) !void {
        const tag = @intFromEnum(attr);
        try w.writeInt(u8, tag, .little);
        switch (attr) {
            .I8 => |data| {
                try w.writeString(data.name);
                try w.writeInt(i8, data.value, .little);
            },
            .I16 => |data| {
                try w.writeString(data.name);
                try w.writeInt(i16, data.value, .little);
            },
            .I32 => |data| {
                try w.writeString(data.name);
                try w.writeInt(i32, data.value, .little);
            },
            .I64 => |data| {
                try w.writeString(data.name);
                try w.writeInt(i64, data.value, .little);
            },
            .I128 => |data| {
                try w.writeString(data.name);
                try w.writeInt(i128, data.value, .little);
            },
            .U8 => |data| {
                try w.writeString(data.name);
                try w.writeInt(u8, data.value, .little);
            },
            .U16 => |data| {
                try w.writeString(data.name);
                try w.writeInt(u16, data.value, .little);
            },
            .U32 => |data| {
                try w.writeString(data.name);
                try w.writeInt(u32, data.value, .little);
            },
            .U64 => |data| {
                try w.writeString(data.name);
                try w.writeInt(u64, data.value, .little);
            },
            .U128 => |data| {
                try w.writeString(data.name);
                try w.writeInt(u128, data.value, .little);
            },
            .F32 => |data| {
                try w.writeString(data.name);
                try w.writeInt(i32, @bitCast(data.value), .little);
            },
            .F64 => |data| {
                try w.writeString(data.name);
                try w.writeInt(i64, @bitCast(data.value), .little);
            },
            .F128 => |data| {
                try w.writeString(data.name);
                try w.writeInt(i128, @bitCast(data.value), .little);
            },
            .Pointer => |data| {
                try w.writeString(data.name);
                try w.writeString(data.value);
            },
        }
    }

    fn serializeOperation(w: Buffer.Writer, op: Operation) !void {
        const tag = @intFromEnum(op);
        try w.writeInt(u8, tag, .little);
        switch (op) {
            // ========== SCHEMA/METADATA OPERATIONS ==========
            .Create => |data| {
                try w.writeInt(u8, @intFromEnum(data.doc_type), .little);
                try w.writeString(data.ns);
                try w.writeString(data.payload);
                try w.writeInt(u8, if (data.auto_create) 1 else 0, .little);
                if (data.metadata) |meta| {
                    try w.writeInt(u8, 1, .little);
                    try w.writeString(meta);
                } else {
                    try w.writeInt(u8, 0, .little);
                }
            },
            .Drop => |data| {
                try w.writeInt(u8, @intFromEnum(data.doc_type), .little);
                try w.writeString(data.name);
            },
            .List => |data| {
                try w.writeInt(u8, @intFromEnum(data.doc_type), .little);
                if (data.ns) |ns| {
                    try w.writeInt(u8, 1, .little);
                    try w.writeString(ns);
                } else {
                    try w.writeInt(u8, 0, .little);
                }
                if (data.limit) |lim| {
                    try w.writeInt(u8, 1, .little);
                    try w.writeInt(u32, lim, .little);
                } else {
                    try w.writeInt(u8, 0, .little);
                }
                if (data.offset) |off| {
                    try w.writeInt(u8, 1, .little);
                    try w.writeInt(u32, off, .little);
                } else {
                    try w.writeInt(u8, 0, .little);
                }
            },
            // ========== DOCUMENT DATA OPERATIONS ==========
            .Insert => |data| {
                try w.writeString(data.store_ns);
                try w.writeString(data.payload);
                try w.writeInt(u8, if (data.auto_create) 1 else 0, .little);
            },
            .BatchInsert => |data| {
                try w.writeString(data.store_ns);
                const count = @as(u32, @intCast(data.values.len));
                try w.writeInt(u32, count, .little);
                for (data.values) |value| {
                    try w.writeString(value);
                }
            },
            .Read => |data| {
                try w.writeString(data.store_ns);
                try w.writeInt(u128, data.id, .little);
            },
            .Update => |data| {
                try w.writeString(data.store_ns);
                try w.writeInt(u128, data.id, .little);
                try w.writeString(data.payload);
            },
            .Delete => |data| {
                try w.writeString(data.store_ns);
                if (data.id) |id| {
                    try w.writeInt(u8, 1, .little);
                    try w.writeInt(u128, id, .little);
                } else {
                    try w.writeInt(u8, 0, .little);
                }
                if (data.query_json) |qj| {
                    try w.writeInt(u8, 1, .little);
                    try w.writeString(qj);
                } else {
                    try w.writeInt(u8, 0, .little);
                }
            },
            // ========== QUERY OPERATIONS ==========
            .Range => |data| {
                try w.writeString(data.store_ns);
                try serializeAttribute(w, data.start_key);
                try serializeAttribute(w, data.end_key);
            },
            .Query => |data| {
                try w.writeString(data.store_ns);
                try w.writeString(data.query_json);
            },
            .Aggregate => |data| {
                try w.writeString(data.store_ns);
                try w.writeString(data.aggregate_json);
            },
            .Scan => |data| {
                try w.writeString(data.store_ns);
                if (data.start_key) |key| {
                    try w.writeInt(u8, 1, .little);
                    try w.writeInt(u128, key, .little);
                } else {
                    try w.writeInt(u8, 0, .little);
                }
                try w.writeInt(u32, data.limit, .little);
                try w.writeInt(u32, data.skip, .little);
            },
            // ========== AUTHENTICATION OPERATIONS ==========
            .Authenticate => |data| {
                try w.writeString(data.uid);
                try w.writeString(data.key);
            },
            // ========== REPLICATION OPERATIONS ==========
            .ShipWal => |data| {
                try w.writeInt(u8, data.op_kind, .little);
                try w.writeString(data.store_ns);
                try w.writeInt(u64, data.lsn, .little);
                try w.writeInt(u128, data.doc_id, .little);
                try w.writeInt(i64, data.timestamp, .little);
                try w.writeString(data.data);
            },
            .Logout => {},
            // ========== USER MANAGEMENT OPERATIONS ==========
            .RegenerateKey => |data| {
                try w.writeString(data.uid);
            },
            // ========== BACKUP OPERATIONS ==========
            .Restore => |data| {
                try w.writeString(data.backup_path);
                try w.writeString(data.target_path);
            },
            .Backup => |data| {
                try w.writeString(data.path);
            },
            // ========== SERVER CONTROL OPERATIONS ==========
            .Reply => |data| {
                const status_byte = @intFromEnum(data.status);
                try w.writeInt(u8, status_byte, .little);
                if (data.data) |d| {
                    try w.writeInt(u8, 1, .little);
                    try w.writeString(d);
                } else {
                    try w.writeInt(u8, 0, .little);
                }
            },
            .BatchReply => |data| {
                const status_byte = @intFromEnum(data.status);
                try w.writeInt(u8, status_byte, .little);
                const count = @as(u32, @intCast(data.results.len));
                try w.writeInt(u32, count, .little);
                for (data.results) |result| {
                    try w.writeString(result);
                }
            },
            .Flush => {},
            .Shutdown => {},
            .Vlogs => {},
            // ========== ADMIN OPERATIONS ==========
            .Stats => |data| {
                try w.writeInt(u8, @intFromEnum(data.stat), .little);
            },
            .Collect => |data| {
                try w.writeInt(u32, @intCast(data.vlogs.len), .little);
                try w.writeAll(data.vlogs);
            },
            .SetMode => |data| {
                try w.writeInt(u8, if (data.online) 1 else 0, .little);
            },
            .UpdateUser => |data| {
                try w.writeString(data.uid);
                try w.writeInt(u8, data.role, .little);
            },
            .GetConfig => {},
            .SetConfig => |data| {
                try w.writeString(data.data);
            },
            .Export => |data| {
                try w.writeString(data.store_ns);
                try w.writeString(data.format);
                try w.writeString(data.file_path);
            },
            .Import => |data| {
                try w.writeString(data.payload);
            },
        }
    }

    fn readBytes(data: []const u8, offset: *usize, comptime T: type) !T {
        if (offset.* + @sizeOf(T) > data.len) {
            return SerializationError.InvalidData;
        }
        const result = std.mem.bytesToValue(T, data[offset.* .. offset.* + @sizeOf(T)]);
        offset.* += @sizeOf(T);
        return result;
    }

    fn readString(allocator: Allocator, data: []const u8, offset: *usize) ![]const u8 {
        const len = try Packet.readBytes(data, offset, u32);
        if (offset.* + len > data.len) {
            return SerializationError.InvalidData;
        }
        _ = allocator;
        const result = data[offset.* .. offset.* + len][0..];
        offset.* += len;
        return result;
    }

    fn deserializeAttribute(allocator: Allocator, data: []const u8, offset: *usize) !Attribute {
        const tag = try Packet.readBytes(data, offset, u8);
        return switch (tag) {
            0 => {
                const name = try Packet.readString(allocator, data, offset);
                const value = try Packet.readBytes(data, offset, i8);
                return Attribute{ .I8 = .{ .name = name, .value = value } };
            },
            1 => {
                const name = try Packet.readString(allocator, data, offset);
                const value = try Packet.readBytes(data, offset, i16);
                return Attribute{ .I16 = .{ .name = name, .value = value } };
            },
            2 => {
                const name = try Packet.readString(allocator, data, offset);
                const value = try Packet.readBytes(data, offset, i32);
                return Attribute{ .I32 = .{ .name = name, .value = value } };
            },
            3 => {
                const name = try Packet.readString(allocator, data, offset);
                const value = try Packet.readBytes(data, offset, i64);
                return Attribute{ .I64 = .{ .name = name, .value = value } };
            },
            4 => {
                const name = try Packet.readString(allocator, data, offset);
                const value = try Packet.readBytes(data, offset, i128);
                return Attribute{ .I128 = .{ .name = name, .value = value } };
            },
            5 => {
                const name = try Packet.readString(allocator, data, offset);
                const value = try Packet.readBytes(data, offset, u8);
                return Attribute{ .U8 = .{ .name = name, .value = value } };
            },
            6 => {
                const name = try Packet.readString(allocator, data, offset);
                const value = try Packet.readBytes(data, offset, u16);
                return Attribute{ .U16 = .{ .name = name, .value = value } };
            },
            7 => {
                const name = try Packet.readString(allocator, data, offset);
                const value = try Packet.readBytes(data, offset, u32);
                return Attribute{ .U32 = .{ .name = name, .value = value } };
            },
            8 => {
                const name = try Packet.readString(allocator, data, offset);
                const value = try Packet.readBytes(data, offset, u64);
                return Attribute{ .U64 = .{ .name = name, .value = value } };
            },
            9 => {
                const name = try Packet.readString(allocator, data, offset);
                const value = try Packet.readBytes(data, offset, u128);
                return Attribute{ .U128 = .{ .name = name, .value = value } };
            },
            10 => {
                const name = try Packet.readString(allocator, data, offset);
                const value = try Packet.readBytes(data, offset, f32);
                return Attribute{ .F32 = .{ .name = name, .value = value } };
            },
            11 => {
                const name = try Packet.readString(allocator, data, offset);
                const value = try Packet.readBytes(data, offset, f64);
                return Attribute{ .F64 = .{ .name = name, .value = value } };
            },
            12 => {
                const name = try Packet.readString(allocator, data, offset);
                const value = try Packet.readBytes(data, offset, f128);
                return Attribute{ .F128 = .{ .name = name, .value = value } };
            },
            13 => {
                const name = try Packet.readString(allocator, data, offset);
                const value = try Packet.readString(allocator, data, offset);
                return Attribute{ .Pointer = .{ .name = name, .value = value } };
            },
            else => SerializationError.InvalidData,
        };
    }

    fn deserializeOperation(allocator: Allocator, data: []const u8, offset: *usize) !Operation {
        const tag = try Packet.readBytes(data, offset, u8);
        return switch (tag) {
            // Tag 100: Create
            100 => {
                const doc_type_byte = try Packet.readBytes(data, offset, u8);
                const doc_type = @as(DocType, @enumFromInt(doc_type_byte));
                const ns = try Packet.readString(allocator, data, offset);
                const payload = try Packet.readString(allocator, data, offset);
                const auto_create = (try Packet.readBytes(data, offset, u8)) == 1;

                const has_metadata = try Packet.readBytes(data, offset, u8);
                const metadata = if (has_metadata == 1)
                    try Packet.readString(allocator, data, offset)
                else
                    null;

                return Operation{ .Create = .{
                    .doc_type = doc_type,
                    .ns = ns,
                    .payload = payload,
                    .auto_create = auto_create,
                    .metadata = metadata,
                } };
            },
            // Tag 101: Drop
            101 => {
                const doc_type_byte = try Packet.readBytes(data, offset, u8);
                const doc_type = @as(DocType, @enumFromInt(doc_type_byte));
                const name = try Packet.readString(allocator, data, offset);

                return Operation{ .Drop = .{
                    .doc_type = doc_type,
                    .name = name,
                } };
            },
            // Tag 102: List
            102 => {
                const doc_type_byte = try Packet.readBytes(data, offset, u8);
                const doc_type = @as(DocType, @enumFromInt(doc_type_byte));

                const has_ns = try Packet.readBytes(data, offset, u8);
                const ns = if (has_ns == 1)
                    try Packet.readString(allocator, data, offset)
                else
                    null;

                const has_limit = try Packet.readBytes(data, offset, u8);
                const limit = if (has_limit == 1)
                    try Packet.readBytes(data, offset, u32)
                else
                    null;

                const has_offset = try Packet.readBytes(data, offset, u8);
                const offset_val = if (has_offset == 1)
                    try Packet.readBytes(data, offset, u32)
                else
                    null;

                return Operation{ .List = .{
                    .doc_type = doc_type,
                    .ns = ns,
                    .limit = limit,
                    .offset = offset_val,
                } };
            },
            // Tag 103: Insert
            103 => {
                const store_ns = try Packet.readString(allocator, data, offset);
                const payload = try Packet.readString(allocator, data, offset);
                const auto_create = (try Packet.readBytes(data, offset, u8)) == 1;

                return Operation{ .Insert = .{
                    .store_ns = store_ns,
                    .payload = payload,
                    .auto_create = auto_create,
                } };
            },
            // Tag 104: BatchInsert
            104 => {
                const store_ns = try Packet.readString(allocator, data, offset);
                const count = try Packet.readBytes(data, offset, u32);
                const values = try allocator.alloc([]const u8, count);
                for (values) |*value| {
                    value.* = try Packet.readString(allocator, data, offset);
                }

                return Operation{ .BatchInsert = .{
                    .store_ns = store_ns,
                    .values = values,
                } };
            },
            // Tag 105: Read
            105 => {
                const store_ns = try Packet.readString(allocator, data, offset);
                const id = try Packet.readBytes(data, offset, u128);

                return Operation{ .Read = .{
                    .store_ns = store_ns,
                    .id = id,
                } };
            },
            // Tag 106: Update
            106 => {
                const store_ns = try Packet.readString(allocator, data, offset);
                const id = try Packet.readBytes(data, offset, u128);
                const payload = try Packet.readString(allocator, data, offset);

                return Operation{ .Update = .{
                    .store_ns = store_ns,
                    .id = id,
                    .payload = payload,
                } };
            },
            // Tag 107: Delete
            107 => {
                const store_ns = try Packet.readString(allocator, data, offset);

                const has_id = try Packet.readBytes(data, offset, u8);
                const id = if (has_id == 1)
                    try Packet.readBytes(data, offset, u128)
                else
                    null;

                const has_query_json = try Packet.readBytes(data, offset, u8);
                const query_json = if (has_query_json == 1)
                    try Packet.readString(allocator, data, offset)
                else
                    null;

                return Operation{ .Delete = .{
                    .store_ns = store_ns,
                    .id = id,
                    .query_json = query_json,
                } };
            },
            // Tag 108: Range
            108 => {
                const store_ns = try Packet.readString(allocator, data, offset);
                const start_key = try Packet.deserializeAttribute(allocator, data, offset);
                const end_key = try Packet.deserializeAttribute(allocator, data, offset);

                return Operation{ .Range = .{
                    .store_ns = store_ns,
                    .start_key = start_key,
                    .end_key = end_key,
                } };
            },
            // Tag 109: Query
            109 => {
                const store_ns = try Packet.readString(allocator, data, offset);
                const query_json = try Packet.readString(allocator, data, offset);

                return Operation{ .Query = .{
                    .store_ns = store_ns,
                    .query_json = query_json,
                } };
            },
            // Tag 110: Aggregate
            110 => {
                const store_ns = try Packet.readString(allocator, data, offset);
                const aggregate_json = try Packet.readString(allocator, data, offset);

                return Operation{ .Aggregate = .{
                    .store_ns = store_ns,
                    .aggregate_json = aggregate_json,
                } };
            },
            // Tag 111: Authenticate
            111 => {
                const uid = try Packet.readString(allocator, data, offset);
                const key = try Packet.readString(allocator, data, offset);

                return Operation{ .Authenticate = .{
                    .uid = uid,
                    .key = key,
                } };
            },

            // Tag 112: ShipWal (server-to-server replication)
            112 => {
                const op_kind = try Packet.readBytes(data, offset, u8);
                const store_ns = try Packet.readString(allocator, data, offset);
                const lsn = try Packet.readBytes(data, offset, u64);

                const doc_id = try Packet.readBytes(data, offset, u128);
                const timestamp = try Packet.readBytes(data, offset, i64);
                const wal_data = try Packet.readString(allocator, data, offset);

                return Operation{ .ShipWal = .{
                    .op_kind = op_kind,
                    .store_ns = store_ns,
                    .lsn = lsn,
                    .doc_id = doc_id,
                    .timestamp = timestamp,
                    .data = wal_data,
                } };
            },
            // Tag 113: Logout
            113 => Operation.Logout,
            // Tag 114: RegenerateKey
            114 => {
                const uid = try Packet.readString(allocator, data, offset);

                return Operation{ .RegenerateKey = .{
                    .uid = uid,
                } };
            },
            // Tag 115: Restore
            115 => {
                const backup_path = try Packet.readString(allocator, data, offset);
                const target_path = try Packet.readString(allocator, data, offset);

                return Operation{ .Restore = .{
                    .backup_path = backup_path,
                    .target_path = target_path,
                } };
            },
            // Tag 116: Backup
            116 => {
                const path = try Packet.readString(allocator, data, offset);
                return Operation{ .Backup = .{
                    .path = path,
                } };
            },
            // Tag 117: Reply
            117 => {
                const status_byte = try Packet.readBytes(data, offset, u8);
                const status = @as(Status, @enumFromInt(status_byte));
                const has_data = try Packet.readBytes(data, offset, u8);
                const reply_data = if (has_data == 1) try Packet.readString(allocator, data, offset) else null;

                return Operation{ .Reply = .{
                    .status = status,
                    .data = reply_data,
                } };
            },
            // Tag 118: BatchReply
            118 => {
                const status_byte = try Packet.readBytes(data, offset, u8);
                const status = @as(Status, @enumFromInt(status_byte));
                const count = try Packet.readBytes(data, offset, u32);
                const results = try allocator.alloc([]const u8, count);
                for (results) |*result| {
                    result.* = try Packet.readString(allocator, data, offset);
                }

                return Operation{ .BatchReply = .{
                    .status = status,
                    .results = results,
                } };
            },
            // Tag 119: Flush
            119 => Operation.Flush,
            // Tag 120: Shutdown
            120 => Operation.Shutdown,
            // Tag 121: Scan
            121 => {
                const store_ns = try Packet.readString(allocator, data, offset);

                const has_start_key = try Packet.readBytes(data, offset, u8);
                const start_key = if (has_start_key == 1)
                    try Packet.readBytes(data, offset, u128)
                else
                    null;

                const limit = try Packet.readBytes(data, offset, u32);
                const skip = try Packet.readBytes(data, offset, u32);

                return Operation{ .Scan = .{
                    .store_ns = store_ns,
                    .start_key = start_key,
                    .limit = limit,
                    .skip = skip,
                } };
            },
            // Tag 122: Stats
            122 => {
                const stat_byte = try Packet.readBytes(data, offset, u8);
                const stat = @as(StatsTag, @enumFromInt(stat_byte));
                return Operation{ .Stats = .{ .stat = stat } };
            },
            // Tag 123: Collect
            123 => {
                const count = try Packet.readBytes(data, offset, u32);
                const vlogs = try allocator.alloc(u8, count);
                for (vlogs) |*v| {
                    v.* = try Packet.readBytes(data, offset, u8);
                }
                return Operation{ .Collect = .{ .vlogs = vlogs } };
            },
            124 => return Operation.Vlogs,
            125 => {
                const online = (try Packet.readBytes(data, offset, u8)) == 1;
                return Operation{ .SetMode = .{ .online = online } };
            },
            // Tag 126: UpdateUser
            126 => {
                const uid = try Packet.readString(allocator, data, offset);
                const role = try Packet.readBytes(data, offset, u8);
                return Operation{ .UpdateUser = .{ .uid = uid, .role = role } };
            },
            // Tag 127: GetConfig
            127 => Operation.GetConfig,
            // Tag 128: SetConfig
            128 => {
                const config_data = try Packet.readString(allocator, data, offset);
                return Operation{ .SetConfig = .{ .data = config_data } };
            },
            // Tag 129: Export
            129 => {
                const store_ns = try Packet.readString(allocator, data, offset);
                const format = try Packet.readString(allocator, data, offset);
                const file_path = try Packet.readString(allocator, data, offset);
                return Operation{ .Export = .{ .store_ns = store_ns, .format = format, .file_path = file_path } };
            },
            // Tag 130: Import
            130 => {
                const payload = try Packet.readString(allocator, data, offset);
                return Operation{ .Import = .{ .payload = payload } };
            },
            else => SerializationError.InvalidData,
        };
    }

    fn freeAttribute(allocator: Allocator, attr: Attribute) void {
        switch (attr) {
            .Pointer => |data| {
                allocator.free(data.name);
                allocator.free(data.value);
            },
            .I8 => |data| {
                allocator.free(data.name);
            },
            .I16 => |data| {
                allocator.free(data.name);
            },
            .I32 => |data| {
                allocator.free(data.name);
            },
            .I64 => |data| {
                allocator.free(data.name);
            },
            .I128 => |data| {
                allocator.free(data.name);
            },
            .U8 => |data| {
                allocator.free(data.name);
            },
            .U16 => |data| {
                allocator.free(data.name);
            },
            .U32 => |data| {
                allocator.free(data.name);
            },
            .U64 => |data| {
                allocator.free(data.name);
            },
            .U128 => |data| {
                allocator.free(data.name);
            },
            .F32 => |data| {
                allocator.free(data.name);
            },
            .F64 => |data| {
                allocator.free(data.name);
            },
            .F128 => |data| {
                allocator.free(data.name);
            },
        }
    }
};


pub const SerializationError = error{
    BufferTooSmall,
    InvalidData,
    OutOfMemory,
};

const testing = std.testing;
const expect = testing.expect;
const expectEqual = testing.expectEqual;
const expectEqualStrings = testing.expectEqualStrings;

test "serialize and deserialize basic message with Flush op" {
    const allocator = testing.allocator;
    const original = Packet{
        .checksum = 12345,
        .packet_length = 100,
        .packet_id = 1,
        .timestamp = 1234567890,
        .op = Operation.Flush,
    };
    var buf = try Buffer.init(allocator, original.calcMsgSize());
    defer buf.deinit();
    const serialized = try original.serialize(&buf);
    const deserialized = try Packet.deserialize(allocator, serialized);
    defer Packet.free(allocator, deserialized);
    try expectEqual(original.checksum, deserialized.checksum);
    try expectEqual(original.packet_length, deserialized.packet_length);
    try expectEqual(original.packet_id, deserialized.packet_id);
    try expectEqual(original.timestamp, deserialized.timestamp);
    try expectEqual(@intFromEnum(original.op), @intFromEnum(deserialized.op));
}

test "serialize and deserialize Reply operation with data" {
    const allocator = testing.allocator;
    const original = Packet{
        .checksum = 22222,
        .packet_length = 75,
        .packet_id = 4,
        .timestamp = 2222222222,
        .op = Operation{ .Reply = .{ .status = Status.ok, .data = "response data" } },
    };
    var buf = try Buffer.init(allocator, original.calcMsgSize());
    defer buf.deinit();
    const serialized = try original.serialize(&buf);
    const deserialized = try Packet.deserialize(allocator, serialized);
    defer Packet.free(allocator, deserialized);
    try expectEqual(original.op.Reply.status, deserialized.op.Reply.status);
    try expect(deserialized.op.Reply.data != null);
    try expectEqualStrings(original.op.Reply.data.?, deserialized.op.Reply.data.?);
}

test "serialize and deserialize Reply operation without data" {
    const allocator = testing.allocator;
    const original = Packet{
        .checksum = 33333,
        .packet_length = 50,
        .packet_id = 5,
        .timestamp = 3333333333,
        .op = Operation{ .Reply = .{ .status = Status.not_found, .data = null } },
    };
    var buf = try Buffer.init(allocator, original.calcMsgSize());
    defer buf.deinit();
    const serialized = try original.serialize(&buf);
    const deserialized = try Packet.deserialize(allocator, serialized);
    defer Packet.free(allocator, deserialized);
    try expectEqual(original.op.Reply.status, deserialized.op.Reply.status);
    try expect(deserialized.op.Reply.data == null);
}

test "serialize and deserialize all status types" {
    const allocator = testing.allocator;
    const statuses = [_]Status{ .ok, .err, .not_found, .invalid_request, .server_error };
    for (statuses) |status| {
        const original = Packet{
            .checksum = 77777,
            .packet_length = 25,
            .packet_id = 9,
            .timestamp = 7777777777,
            .op = Operation{ .Reply = .{ .status = status, .data = null } },
        };
        var buf = try Buffer.init(allocator, original.calcMsgSize());
        defer buf.deinit();
        const serialized = try original.serialize(&buf);
        const deserialized = try Packet.deserialize(allocator, serialized);
        defer Packet.free(allocator, deserialized);
        try expectEqual(original.op.Reply.status, deserialized.op.Reply.status);
    }
}

test "error handling for invalid data" {
    const allocator = testing.allocator;
    const empty_data = [_]u8{};
    try testing.expectError(SerializationError.InvalidData, Packet.deserialize(allocator, &empty_data));
    const partial_data = [_]u8{ 1, 2, 3, 4 };
    try testing.expectError(SerializationError.InvalidData, Packet.deserialize(allocator, &partial_data));
    // Header is 56 bytes; op_tag at offset 56; 255 is an invalid op tag.
    var invalid_op_data = [_]u8{0} ** 57;
    invalid_op_data[56] = 255;
    try testing.expectError(SerializationError.InvalidData, Packet.deserialize(allocator, &invalid_op_data));
}

test "attribute name matches index field for all attribute types" {
    // const allocator = testing.allocator;
    const index_field = "field_name";
    const attrs = [_]Attribute{
        Attribute{ .I8 = .{ .name = "field_name", .value = -1 } },
        Attribute{ .I16 = .{ .name = "field_name", .value = -2 } },
        Attribute{ .I32 = .{ .name = "field_name", .value = -3 } },
        Attribute{ .I64 = .{ .name = "field_name", .value = -4 } },
        Attribute{ .I128 = .{ .name = "field_name", .value = -5 } },
        Attribute{ .U8 = .{ .name = "field_name", .value = 1 } },
        Attribute{ .U16 = .{ .name = "field_name", .value = 2 } },
        Attribute{ .U32 = .{ .name = "field_name", .value = 3 } },
        Attribute{ .U64 = .{ .name = "field_name", .value = 4 } },
        Attribute{ .U128 = .{ .name = "field_name", .value = 5 } },
        Attribute{ .F32 = .{ .name = "field_name", .value = 1.23 } },
        Attribute{ .F64 = .{ .name = "field_name", .value = 4.56 } },
        Attribute{ .F128 = .{ .name = "field_name", .value = 7.89 } },
        Attribute{ .Pointer = .{ .name = "field_name", .value = "pointer_value" } },
    };
    var all_match = true;
    for (attrs) |attr| {
        var match = false;
        switch (attr) {
            .I8 => |data| {
                match = std.mem.eql(u8, data.name, index_field);
            },
            .I16 => |data| {
                match = std.mem.eql(u8, data.name, index_field);
            },
            .I32 => |data| {
                match = std.mem.eql(u8, data.name, index_field);
            },
            .I64 => |data| {
                match = std.mem.eql(u8, data.name, index_field);
            },
            .I128 => |data| {
                match = std.mem.eql(u8, data.name, index_field);
            },
            .U8 => |data| {
                match = std.mem.eql(u8, data.name, index_field);
            },
            .U16 => |data| {
                match = std.mem.eql(u8, data.name, index_field);
            },
            .U32 => |data| {
                match = std.mem.eql(u8, data.name, index_field);
            },
            .U64 => |data| {
                match = std.mem.eql(u8, data.name, index_field);
            },
            .U128 => |data| {
                match = std.mem.eql(u8, data.name, index_field);
            },
            .F32 => |data| {
                match = std.mem.eql(u8, data.name, index_field);
            },
            .F64 => |data| {
                match = std.mem.eql(u8, data.name, index_field);
            },
            .F128 => |data| {
                match = std.mem.eql(u8, data.name, index_field);
            },
            .Pointer => |data| {
                match = std.mem.eql(u8, data.name, index_field);
            },
        }
        if (!match) {
            all_match = false;
            break;
        }
    }
    try expect(all_match);
}

test "attribute name does not match index field for all attribute types" {
    // const allocator = testing.allocator;
    const index_field = "field_name";
    const attrs = [_]Attribute{
        Attribute{ .I8 = .{ .name = "other", .value = -1 } },
        Attribute{ .I16 = .{ .name = "other", .value = -2 } },
        Attribute{ .I32 = .{ .name = "other", .value = -3 } },
        Attribute{ .I64 = .{ .name = "other", .value = -4 } },
        Attribute{ .I128 = .{ .name = "other", .value = -5 } },
        Attribute{ .U8 = .{ .name = "other", .value = 1 } },
        Attribute{ .U16 = .{ .name = "other", .value = 2 } },
        Attribute{ .U32 = .{ .name = "other", .value = 3 } },
        Attribute{ .U64 = .{ .name = "other", .value = 4 } },
        Attribute{ .U128 = .{ .name = "other", .value = 5 } },
        Attribute{ .F32 = .{ .name = "other", .value = 1.23 } },
        Attribute{ .F64 = .{ .name = "other", .value = 4.56 } },
        Attribute{ .F128 = .{ .name = "other", .value = 7.89 } },
        Attribute{ .Pointer = .{ .name = "other", .value = "pointer_value" } },
    };
    var any_match = false;
    for (attrs) |attr| {
        switch (attr) {
            .I8 => |data| {
                if (std.mem.eql(u8, data.name, index_field)) any_match = true;
            },
            .I16 => |data| {
                if (std.mem.eql(u8, data.name, index_field)) any_match = true;
            },
            .I32 => |data| {
                if (std.mem.eql(u8, data.name, index_field)) any_match = true;
            },
            .I64 => |data| {
                if (std.mem.eql(u8, data.name, index_field)) any_match = true;
            },
            .I128 => |data| {
                if (std.mem.eql(u8, data.name, index_field)) any_match = true;
            },
            .U8 => |data| {
                if (std.mem.eql(u8, data.name, index_field)) any_match = true;
            },
            .U16 => |data| {
                if (std.mem.eql(u8, data.name, index_field)) any_match = true;
            },
            .U32 => |data| {
                if (std.mem.eql(u8, data.name, index_field)) any_match = true;
            },
            .U64 => |data| {
                if (std.mem.eql(u8, data.name, index_field)) any_match = true;
            },
            .U128 => |data| {
                if (std.mem.eql(u8, data.name, index_field)) any_match = true;
            },
            .F32 => |data| {
                if (std.mem.eql(u8, data.name, index_field)) any_match = true;
            },
            .F64 => |data| {
                if (std.mem.eql(u8, data.name, index_field)) any_match = true;
            },
            .F128 => |data| {
                if (std.mem.eql(u8, data.name, index_field)) any_match = true;
            },
            .Pointer => |data| {
                if (std.mem.eql(u8, data.name, index_field)) any_match = true;
            },
        }
    }
    try expect(!any_match);
}

// ========== Round-trip tests for each OpTag ==========

fn roundTrip(original: Packet) !void {
    const allocator = testing.allocator;
    var buf = try Buffer.init(allocator, original.calcMsgSize());
    defer buf.deinit();
    const serialized = try original.serialize(&buf);
    const deserialized = try Packet.deserialize(allocator, serialized);
    defer Packet.free(allocator, deserialized);
    try expectEqual(original.checksum, deserialized.checksum);
    try expectEqual(original.packet_id, deserialized.packet_id);
    try expectEqual(original.timestamp, deserialized.timestamp);
    try expectEqual(@intFromEnum(original.op), @intFromEnum(deserialized.op));
}

test "round-trip Create with metadata" {
    const pkt = Packet{
        .checksum = 1,
        .packet_length = 0,
        .packet_id = 10,
        .timestamp = 1000,
        .op = Operation{ .Create = .{
            .doc_type = DocType.Store,
            .ns = "myspace.orders",
            .payload = "{\"desc\":\"order store\"}",
            .auto_create = true,
            .metadata = "some meta",
        } },
    };
    try roundTrip(pkt);
    // Also verify fields
    const allocator = testing.allocator;
    var buf = try Buffer.init(allocator, pkt.calcMsgSize());
    defer buf.deinit();
    const serialized = try pkt.serialize(&buf);
    const d = try Packet.deserialize(allocator, serialized);
    defer Packet.free(allocator, d);
    try expectEqualStrings("myspace.orders", d.op.Create.ns);
    try expectEqualStrings("{\"desc\":\"order store\"}", d.op.Create.payload);
    try expect(d.op.Create.auto_create);
    try expectEqualStrings("some meta", d.op.Create.metadata.?);
    try expectEqual(DocType.Store, d.op.Create.doc_type);
}

test "round-trip Create without metadata" {
    const pkt = Packet{
        .checksum = 2,
        .packet_length = 0,
        .packet_id = 11,
        .timestamp = 2000,
        .op = Operation{ .Create = .{
            .doc_type = DocType.Space,
            .ns = "myspace",
            .payload = "{}",
            .auto_create = false,
            .metadata = null,
        } },
    };
    try roundTrip(pkt);
    const allocator = testing.allocator;
    var buf = try Buffer.init(allocator, pkt.calcMsgSize());
    defer buf.deinit();
    const serialized = try pkt.serialize(&buf);
    const d = try Packet.deserialize(allocator, serialized);
    defer Packet.free(allocator, d);
    try expect(d.op.Create.metadata == null);
    try expect(!d.op.Create.auto_create);
}

test "round-trip Drop" {
    try roundTrip(Packet{
        .checksum = 3,
        .packet_length = 0,
        .packet_id = 12,
        .timestamp = 3000,
        .op = Operation{ .Drop = .{ .doc_type = DocType.Index, .name = "myspace.orders.idx" } },
    });
}

test "round-trip List with all optional fields" {
    const pkt = Packet{
        .checksum = 4,
        .packet_length = 0,
        .packet_id = 13,
        .timestamp = 4000,
        .op = Operation{ .List = .{ .doc_type = DocType.Store, .ns = "myspace", .limit = 50, .offset = 10 } },
    };
    try roundTrip(pkt);
    const allocator = testing.allocator;
    var buf = try Buffer.init(allocator, pkt.calcMsgSize());
    defer buf.deinit();
    const serialized = try pkt.serialize(&buf);
    const d = try Packet.deserialize(allocator, serialized);
    defer Packet.free(allocator, d);
    try expectEqual(@as(u32, 50), d.op.List.limit.?);
    try expectEqual(@as(u32, 10), d.op.List.offset.?);
    try expectEqualStrings("myspace", d.op.List.ns.?);
}

test "round-trip List with no optional fields" {
    const pkt = Packet{
        .checksum = 5,
        .packet_length = 0,
        .packet_id = 14,
        .timestamp = 5000,
        .op = Operation{ .List = .{ .doc_type = DocType.Space, .ns = null, .limit = null, .offset = null } },
    };
    try roundTrip(pkt);
    const allocator = testing.allocator;
    var buf = try Buffer.init(allocator, pkt.calcMsgSize());
    defer buf.deinit();
    const serialized = try pkt.serialize(&buf);
    const d = try Packet.deserialize(allocator, serialized);
    defer Packet.free(allocator, d);
    try expect(d.op.List.ns == null);
    try expect(d.op.List.limit == null);
    try expect(d.op.List.offset == null);
}

test "round-trip Insert" {
    const pkt = Packet{
        .checksum = 6,
        .packet_length = 0,
        .packet_id = 15,
        .timestamp = 6000,
        .op = Operation{ .Insert = .{ .store_ns = "app.users", .payload = "\x10\x00\x00\x00", .auto_create = true } },
    };
    try roundTrip(pkt);
    const allocator = testing.allocator;
    var buf = try Buffer.init(allocator, pkt.calcMsgSize());
    defer buf.deinit();
    const serialized = try pkt.serialize(&buf);
    const d = try Packet.deserialize(allocator, serialized);
    defer Packet.free(allocator, d);
    try expectEqualStrings("app.users", d.op.Insert.store_ns);
    try expect(d.op.Insert.auto_create);
}

test "round-trip BatchInsert" {
    const allocator = testing.allocator;
    const values = try allocator.alloc([]const u8, 3);
    defer allocator.free(values);
    values[0] = "doc1";
    values[1] = "doc2";
    values[2] = "doc3";
    const pkt = Packet{
        .checksum = 7,
        .packet_length = 0,
        .packet_id = 16,
        .timestamp = 7000,
        .op = Operation{ .BatchInsert = .{ .store_ns = "app.orders", .values = values } },
    };
    var buf = try Buffer.init(allocator, pkt.calcMsgSize());
    defer buf.deinit();
    const serialized = try pkt.serialize(&buf);
    const d = try Packet.deserialize(allocator, serialized);
    defer Packet.free(allocator, d);
    try expectEqual(@as(usize, 3), d.op.BatchInsert.values.len);
    try expectEqualStrings("doc1", d.op.BatchInsert.values[0]);
    try expectEqualStrings("doc2", d.op.BatchInsert.values[1]);
    try expectEqualStrings("doc3", d.op.BatchInsert.values[2]);
}

test "round-trip Read" {
    const pkt = Packet{
        .checksum = 8,
        .packet_length = 0,
        .packet_id = 17,
        .timestamp = 8000,
        .op = Operation{ .Read = .{ .store_ns = "app.users", .id = 0xDEADBEEF_CAFEBABE_12345678_9ABCDEF0 } },
    };
    try roundTrip(pkt);
    const allocator = testing.allocator;
    var buf = try Buffer.init(allocator, pkt.calcMsgSize());
    defer buf.deinit();
    const serialized = try pkt.serialize(&buf);
    const d = try Packet.deserialize(allocator, serialized);
    defer Packet.free(allocator, d);
    try expectEqual(@as(u128, 0xDEADBEEF_CAFEBABE_12345678_9ABCDEF0), d.op.Read.id);
}

test "round-trip Update" {
    const pkt = Packet{
        .checksum = 9,
        .packet_length = 0,
        .packet_id = 18,
        .timestamp = 9000,
        .op = Operation{ .Update = .{ .store_ns = "app.users", .id = 42, .payload = "updated_data" } },
    };
    try roundTrip(pkt);
    const allocator = testing.allocator;
    var buf = try Buffer.init(allocator, pkt.calcMsgSize());
    defer buf.deinit();
    const serialized = try pkt.serialize(&buf);
    const d = try Packet.deserialize(allocator, serialized);
    defer Packet.free(allocator, d);
    try expectEqual(@as(u128, 42), d.op.Update.id);
    try expectEqualStrings("updated_data", d.op.Update.payload);
}

test "round-trip Delete with id" {
    const pkt = Packet{
        .checksum = 10,
        .packet_length = 0,
        .packet_id = 19,
        .timestamp = 10000,
        .op = Operation{ .Delete = .{ .store_ns = "app.users", .id = 99, .query_json = null } },
    };
    try roundTrip(pkt);
    const allocator = testing.allocator;
    var buf = try Buffer.init(allocator, pkt.calcMsgSize());
    defer buf.deinit();
    const serialized = try pkt.serialize(&buf);
    const d = try Packet.deserialize(allocator, serialized);
    defer Packet.free(allocator, d);
    try expectEqual(@as(u128, 99), d.op.Delete.id.?);
    try expect(d.op.Delete.query_json == null);
}

test "round-trip Delete with query_json" {
    const pkt = Packet{
        .checksum = 11,
        .packet_length = 0,
        .packet_id = 20,
        .timestamp = 11000,
        .op = Operation{ .Delete = .{ .store_ns = "app.orders", .id = null, .query_json = "{\"status\":\"cancelled\"}" } },
    };
    try roundTrip(pkt);
    const allocator = testing.allocator;
    var buf = try Buffer.init(allocator, pkt.calcMsgSize());
    defer buf.deinit();
    const serialized = try pkt.serialize(&buf);
    const d = try Packet.deserialize(allocator, serialized);
    defer Packet.free(allocator, d);
    try expect(d.op.Delete.id == null);
    try expectEqualStrings("{\"status\":\"cancelled\"}", d.op.Delete.query_json.?);
}

test "round-trip Range with I64 attributes" {
    const pkt = Packet{
        .checksum = 12,
        .packet_length = 0,
        .packet_id = 21,
        .timestamp = 12000,
        .op = Operation{ .Range = .{
            .store_ns = "app.events",
            .start_key = Attribute{ .I64 = .{ .name = "timestamp", .value = 1000 } },
            .end_key = Attribute{ .I64 = .{ .name = "timestamp", .value = 9999 } },
        } },
    };
    try roundTrip(pkt);
    const allocator = testing.allocator;
    var buf = try Buffer.init(allocator, pkt.calcMsgSize());
    defer buf.deinit();
    const serialized = try pkt.serialize(&buf);
    const d = try Packet.deserialize(allocator, serialized);
    defer Packet.free(allocator, d);
    try expectEqual(@as(i64, 1000), d.op.Range.start_key.I64.value);
    try expectEqual(@as(i64, 9999), d.op.Range.end_key.I64.value);
}

test "round-trip Query" {
    const pkt = Packet{
        .checksum = 13,
        .packet_length = 0,
        .packet_id = 22,
        .timestamp = 13000,
        .op = Operation{ .Query = .{ .store_ns = "app.users", .query_json = "{\"age\":{\"$gt\":18}}" } },
    };
    try roundTrip(pkt);
    const allocator = testing.allocator;
    var buf = try Buffer.init(allocator, pkt.calcMsgSize());
    defer buf.deinit();
    const serialized = try pkt.serialize(&buf);
    const d = try Packet.deserialize(allocator, serialized);
    defer Packet.free(allocator, d);
    try expectEqualStrings("{\"age\":{\"$gt\":18}}", d.op.Query.query_json);
}

test "round-trip Aggregate" {
    const pkt = Packet{
        .checksum = 14,
        .packet_length = 0,
        .packet_id = 23,
        .timestamp = 14000,
        .op = Operation{ .Aggregate = .{ .store_ns = "app.sales", .aggregate_json = "[{\"$sum\":\"amount\"}]" } },
    };
    try roundTrip(pkt);
    const allocator = testing.allocator;
    var buf = try Buffer.init(allocator, pkt.calcMsgSize());
    defer buf.deinit();
    const serialized = try pkt.serialize(&buf);
    const d = try Packet.deserialize(allocator, serialized);
    defer Packet.free(allocator, d);
    try expectEqualStrings("[{\"$sum\":\"amount\"}]", d.op.Aggregate.aggregate_json);
}

test "round-trip Scan with start_key" {
    const pkt = Packet{
        .checksum = 15,
        .packet_length = 0,
        .packet_id = 24,
        .timestamp = 15000,
        .op = Operation{ .Scan = .{ .store_ns = "app.logs", .start_key = 500, .limit = 100, .skip = 10 } },
    };
    try roundTrip(pkt);
    const allocator = testing.allocator;
    var buf = try Buffer.init(allocator, pkt.calcMsgSize());
    defer buf.deinit();
    const serialized = try pkt.serialize(&buf);
    const d = try Packet.deserialize(allocator, serialized);
    defer Packet.free(allocator, d);
    try expectEqual(@as(u128, 500), d.op.Scan.start_key.?);
    try expectEqual(@as(u32, 100), d.op.Scan.limit);
    try expectEqual(@as(u32, 10), d.op.Scan.skip);
}

test "round-trip Scan without start_key" {
    const pkt = Packet{
        .checksum = 16,
        .packet_length = 0,
        .packet_id = 25,
        .timestamp = 16000,
        .op = Operation{ .Scan = .{ .store_ns = "app.logs", .start_key = null, .limit = 50, .skip = 0 } },
    };
    try roundTrip(pkt);
    const allocator = testing.allocator;
    var buf = try Buffer.init(allocator, pkt.calcMsgSize());
    defer buf.deinit();
    const serialized = try pkt.serialize(&buf);
    const d = try Packet.deserialize(allocator, serialized);
    defer Packet.free(allocator, d);
    try expect(d.op.Scan.start_key == null);
}

test "round-trip Authenticate" {
    const pkt = Packet{
        .checksum = 17,
        .packet_length = 0,
        .packet_id = 26,
        .timestamp = 17000,
        .op = Operation{ .Authenticate = .{ .uid = "admin", .key = "secret_key_123" } },
    };
    try roundTrip(pkt);
    const allocator = testing.allocator;
    var buf = try Buffer.init(allocator, pkt.calcMsgSize());
    defer buf.deinit();
    const serialized = try pkt.serialize(&buf);
    const d = try Packet.deserialize(allocator, serialized);
    defer Packet.free(allocator, d);
    try expectEqualStrings("admin", d.op.Authenticate.uid);
    try expectEqualStrings("secret_key_123", d.op.Authenticate.key);
}

test "round-trip ShipWal" {
    const pkt = Packet{
        .checksum = 18,
        .packet_length = 0,
        .packet_id = 27,
        .timestamp = 18000,
        .op = Operation{ .ShipWal = .{
            .op_kind = 0,
            .store_ns = "app.users",
            .lsn = 12345,
            .doc_id = 67890,
            .timestamp = 18000,
            .data = "wal_payload_data",
        } },
    };
    try roundTrip(pkt);
    const allocator = testing.allocator;
    var buf = try Buffer.init(allocator, pkt.calcMsgSize());
    defer buf.deinit();
    const serialized = try pkt.serialize(&buf);
    const d = try Packet.deserialize(allocator, serialized);
    defer Packet.free(allocator, d);
    try expectEqual(@as(u8, 0), d.op.ShipWal.op_kind);
    try expectEqual(@as(u64, 12345), d.op.ShipWal.lsn);
    try expectEqual(@as(u128, 67890), d.op.ShipWal.doc_id);
    try expectEqualStrings("wal_payload_data", d.op.ShipWal.data);
}

test "round-trip Logout" {
    try roundTrip(Packet{
        .checksum = 19,
        .packet_length = 0,
        .packet_id = 28,
        .timestamp = 19000,
        .op = Operation.Logout,
    });
}

test "round-trip RegenerateKey" {
    const pkt = Packet{
        .checksum = 20,
        .packet_length = 0,
        .packet_id = 29,
        .timestamp = 20000,
        .op = Operation{ .RegenerateKey = .{ .uid = "user42" } },
    };
    try roundTrip(pkt);
    const allocator = testing.allocator;
    var buf = try Buffer.init(allocator, pkt.calcMsgSize());
    defer buf.deinit();
    const serialized = try pkt.serialize(&buf);
    const d = try Packet.deserialize(allocator, serialized);
    defer Packet.free(allocator, d);
    try expectEqualStrings("user42", d.op.RegenerateKey.uid);
}

test "round-trip Restore" {
    const pkt = Packet{
        .checksum = 21,
        .packet_length = 0,
        .packet_id = 30,
        .timestamp = 21000,
        .op = Operation{ .Restore = .{ .backup_path = "/backups/snap1", .target_path = "/data/restored" } },
    };
    try roundTrip(pkt);
    const allocator = testing.allocator;
    var buf = try Buffer.init(allocator, pkt.calcMsgSize());
    defer buf.deinit();
    const serialized = try pkt.serialize(&buf);
    const d = try Packet.deserialize(allocator, serialized);
    defer Packet.free(allocator, d);
    try expectEqualStrings("/backups/snap1", d.op.Restore.backup_path);
    try expectEqualStrings("/data/restored", d.op.Restore.target_path);
}

test "round-trip Backup" {
    const pkt = Packet{
        .checksum = 22,
        .packet_length = 0,
        .packet_id = 31,
        .timestamp = 22000,
        .op = Operation{ .Backup = .{ .path = "/backups/daily" } },
    };
    try roundTrip(pkt);
    const allocator = testing.allocator;
    var buf = try Buffer.init(allocator, pkt.calcMsgSize());
    defer buf.deinit();
    const serialized = try pkt.serialize(&buf);
    const d = try Packet.deserialize(allocator, serialized);
    defer Packet.free(allocator, d);
    try expectEqualStrings("/backups/daily", d.op.Backup.path);
}

test "round-trip BatchReply" {
    const allocator = testing.allocator;
    const results = try allocator.alloc([]const u8, 2);
    defer allocator.free(results);
    results[0] = "key_abc";
    results[1] = "key_def";
    const pkt = Packet{
        .checksum = 23,
        .packet_length = 0,
        .packet_id = 32,
        .timestamp = 23000,
        .op = Operation{ .BatchReply = .{ .status = Status.ok, .results = results } },
    };
    var buf = try Buffer.init(allocator, pkt.calcMsgSize());
    defer buf.deinit();
    const serialized = try pkt.serialize(&buf);
    const d = try Packet.deserialize(allocator, serialized);
    // readString returns slices into serialized buffer, not allocated copies,
    // so only free the results array itself (allocated by deserialize)
    defer allocator.free(d.op.BatchReply.results);
    try expectEqual(Status.ok, d.op.BatchReply.status);
    try expectEqual(@as(usize, 2), d.op.BatchReply.results.len);
    try expectEqualStrings("key_abc", d.op.BatchReply.results[0]);
    try expectEqualStrings("key_def", d.op.BatchReply.results[1]);
}

test "round-trip Shutdown" {
    try roundTrip(Packet{
        .checksum = 24,
        .packet_length = 0,
        .packet_id = 33,
        .timestamp = 24000,
        .op = Operation.Shutdown,
    });
}

test "round-trip Vlogs" {
    try roundTrip(Packet{
        .checksum = 25,
        .packet_length = 0,
        .packet_id = 34,
        .timestamp = 25000,
        .op = Operation.Vlogs,
    });
}

test "round-trip Stats" {
    const tags = [_]StatsTag{ .WalStats, .DbStats, .IndexStats, .VLogStats, .GcStats, .AllStats };
    const allocator = testing.allocator;
    for (tags) |tag| {
        const pkt = Packet{
            .checksum = 26,
            .packet_length = 0,
            .packet_id = 35,
            .timestamp = 26000,
            .op = Operation{ .Stats = .{ .stat = tag } },
        };
        var buf = try Buffer.init(allocator, pkt.calcMsgSize());
        defer buf.deinit();
        const serialized = try pkt.serialize(&buf);
        const d = try Packet.deserialize(allocator, serialized);
        defer Packet.free(allocator, d);
        try expectEqual(tag, d.op.Stats.stat);
    }
}

test "round-trip Collect" {
    const allocator = testing.allocator;
    const vlogs = try allocator.alloc(u8, 3);
    vlogs[0] = 1;
    vlogs[1] = 2;
    vlogs[2] = 5;
    const pkt = Packet{
        .checksum = 27,
        .packet_length = 0,
        .packet_id = 36,
        .timestamp = 27000,
        .op = Operation{ .Collect = .{ .vlogs = vlogs } },
    };
    var buf = try Buffer.init(allocator, pkt.calcMsgSize());
    defer buf.deinit();
    const serialized = try pkt.serialize(&buf);
    const d = try Packet.deserialize(allocator, serialized);
    defer Packet.free(allocator, d);
    try expectEqual(@as(usize, 3), d.op.Collect.vlogs.len);
    try expectEqual(@as(u8, 1), d.op.Collect.vlogs[0]);
    try expectEqual(@as(u8, 2), d.op.Collect.vlogs[1]);
    try expectEqual(@as(u8, 5), d.op.Collect.vlogs[2]);
    allocator.free(vlogs);
}

test "round-trip SetMode" {
    const allocator = testing.allocator;
    for ([_]bool{ true, false }) |online| {
        const pkt = Packet{
            .checksum = 28,
            .packet_length = 0,
            .packet_id = 37,
            .timestamp = 28000,
            .op = Operation{ .SetMode = .{ .online = online } },
        };
        var buf = try Buffer.init(allocator, pkt.calcMsgSize());
        defer buf.deinit();
        const serialized = try pkt.serialize(&buf);
        const d = try Packet.deserialize(allocator, serialized);
        defer Packet.free(allocator, d);
        try expectEqual(online, d.op.SetMode.online);
    }
}

// ========== Attribute round-trip through Range op ==========

test "round-trip all attribute types via Range" {
    const allocator = testing.allocator;

    const test_cases = .{
        .{ Attribute{ .I8 = .{ .name = "f", .value = -42 } }, Attribute{ .I8 = .{ .name = "f", .value = 42 } } },
        .{ Attribute{ .I16 = .{ .name = "f", .value = -1000 } }, Attribute{ .I16 = .{ .name = "f", .value = 1000 } } },
        .{ Attribute{ .I32 = .{ .name = "f", .value = -100000 } }, Attribute{ .I32 = .{ .name = "f", .value = 100000 } } },
        .{ Attribute{ .U8 = .{ .name = "f", .value = 0 } }, Attribute{ .U8 = .{ .name = "f", .value = 255 } } },
        .{ Attribute{ .U16 = .{ .name = "f", .value = 0 } }, Attribute{ .U16 = .{ .name = "f", .value = 65535 } } },
        .{ Attribute{ .U32 = .{ .name = "f", .value = 0 } }, Attribute{ .U32 = .{ .name = "f", .value = 4294967295 } } },
        .{ Attribute{ .U64 = .{ .name = "f", .value = 0 } }, Attribute{ .U64 = .{ .name = "f", .value = std.math.maxInt(u64) } } },
        .{ Attribute{ .U128 = .{ .name = "f", .value = 0 } }, Attribute{ .U128 = .{ .name = "f", .value = std.math.maxInt(u128) } } },
        .{ Attribute{ .I128 = .{ .name = "f", .value = std.math.minInt(i128) } }, Attribute{ .I128 = .{ .name = "f", .value = std.math.maxInt(i128) } } },
        .{ Attribute{ .Pointer = .{ .name = "f", .value = "hello" } }, Attribute{ .Pointer = .{ .name = "f", .value = "world" } } },
    };

    inline for (test_cases) |tc| {
        const pkt = Packet{
            .checksum = 0,
            .packet_length = 0,
            .packet_id = 0,
            .timestamp = 0,
            .op = Operation{ .Range = .{ .store_ns = "a.b", .start_key = tc[0], .end_key = tc[1] } },
        };
        var buf = try Buffer.init(allocator, pkt.calcMsgSize());
        defer buf.deinit();
        const serialized = try pkt.serialize(&buf);
        const d = try Packet.deserialize(allocator, serialized);
        defer Packet.free(allocator, d);
        try expectEqual(@intFromEnum(tc[0]), @intFromEnum(d.op.Range.start_key));
        try expectEqual(@intFromEnum(tc[1]), @intFromEnum(d.op.Range.end_key));
    }
}

// ========== Truncated buffer / corrupt data tests ==========

test "deserialize truncated header" {
    const allocator = testing.allocator;
    // Header needs 24 bytes (8+4+4+8). Give only 20.
    var short = [_]u8{0} ** 20;
    try testing.expectError(SerializationError.InvalidData, Packet.deserialize(allocator, &short));
}

test "deserialize truncated operation data" {
    const allocator = testing.allocator;
    // Valid header (24 bytes) + valid op tag for Insert (103) but no payload after
    const pkt = Packet{
        .checksum = 0,
        .packet_length = 0,
        .packet_id = 0,
        .timestamp = 0,
        .op = Operation{ .Insert = .{ .store_ns = "a.b", .payload = "data", .auto_create = false } },
    };
    var buf = try Buffer.init(allocator, pkt.calcMsgSize());
    defer buf.deinit();
    const serialized = try pkt.serialize(&buf);
    // Truncate: give only header + op tag (25 bytes), missing the rest
    try testing.expectError(SerializationError.InvalidData, Packet.deserialize(allocator, serialized[0..25]));
}

test "deserialize corrupt string length" {
    const allocator = testing.allocator;
    // Serialize a valid Insert packet then corrupt the store_ns length field
    const pkt = Packet{
        .checksum = 0,
        .packet_length = 0,
        .packet_id = 0,
        .timestamp = 0,
        .op = Operation{ .Insert = .{ .store_ns = "a.b", .payload = "x", .auto_create = false } },
    };
    var buf = try Buffer.init(allocator, pkt.calcMsgSize());
    defer buf.deinit();
    const serialized = try pkt.serialize(&buf);
    // The string length is at offset 25 (after 24-byte header + 1-byte op tag), as a u32 LE
    // Set it to a huge value to simulate corrupt length
    var corrupt = try allocator.alloc(u8, serialized.len);
    defer allocator.free(corrupt);
    @memcpy(corrupt, serialized);
    corrupt[25] = 0xFF;
    corrupt[26] = 0xFF;
    corrupt[27] = 0xFF;
    corrupt[28] = 0x7F; // 0x7FFFFFFF = ~2GB
    try testing.expectError(SerializationError.InvalidData, Packet.deserialize(allocator, corrupt));
}

test "round-trip GetConfig" {
    try roundTrip(Packet{
        .checksum = 29,
        .packet_length = 0,
        .packet_id = 38,
        .timestamp = 29000,
        .op = Operation.GetConfig,
    });
}

test "round-trip SetConfig" {
    const yaml_data = "server:\n  port: 8080\n  host: localhost\n";
    const pkt = Packet{
        .checksum = 30,
        .packet_length = 0,
        .packet_id = 39,
        .timestamp = 30000,
        .op = Operation{ .SetConfig = .{ .data = yaml_data } },
    };
    try roundTrip(pkt);
    const allocator = testing.allocator;
    var buf = try Buffer.init(allocator, pkt.calcMsgSize());
    defer buf.deinit();
    const serialized = try pkt.serialize(&buf);
    const d = try Packet.deserialize(allocator, serialized);
    defer Packet.free(allocator, d);
    try expectEqualStrings(yaml_data, d.op.SetConfig.data);
}
