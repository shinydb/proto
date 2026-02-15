const std = @import("std");
const Type = std.builtin.Type;
const Operation = @import("operation.zig").Operation;
const Status = @import("operation.zig").Status;
const ValueType = @import("operation.zig").ValueType;
const Attribute = @import("operation.zig").Attribute;
const DocType = @import("operation.zig").DocType;
const ArrayList = std.ArrayList;
const Allocator = std.mem.Allocator;

pub const Packet = struct {
    checksum: u64,
    packet_length: u32,
    packet_id: u32,
    session_id: u32,
    correlation_id: u64,
    timestamp: i64,
    op: Operation,

    fn calcMsgSize(pck: *const Packet) usize {
        var size: usize = 0;
        size += @sizeOf(u64); // checksum
        size += @sizeOf(u32); // packet_length
        size += @sizeOf(u32); // packet_id
        size += @sizeOf(u32); // session_id
        size += @sizeOf(u64); // correlation_id
        size += @sizeOf(i64); // timestamp
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
                size += 4 + @as(u32, @intCast(data.username.len)); // username string
                size += 4 + @as(u32, @intCast(data.password.len)); // password string
            },
            .AuthenticateApiKey => |data| {
                size += 4 + @as(u32, @intCast(data.api_key.len)); // api_key string
            },
            .Logout => {},
            .ResetPassword => |data| {
                size += 4 + @as(u32, @intCast(data.username.len)); // username string
                size += 4 + @as(u32, @intCast(data.old_password.len)); // old_password string
                size += 4 + @as(u32, @intCast(data.new_password.len)); // new_password string
            },
            .Restore => |data| {
                size += 4 + @as(u32, @intCast(data.backup_path.len)); // backup_path string
                size += 4 + @as(u32, @intCast(data.target_path.len)); // target_path string
            },
            .CleanBackups => |data| {
                size += 4 + @as(u32, @intCast(data.backup_dir.len)); // backup_dir string
                size += 4; // keep_count (u32)
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
        }
        return size;
    }

    pub fn serialize(self: Packet, writer: *BufferWriter) ![]u8 {
        writer.writeInt(u64, self.checksum);
        writer.writeInt(u32, self.packet_length);
        writer.writeInt(u32, self.packet_id);
        writer.writeInt(u32, self.session_id);
        writer.writeInt(u64, self.correlation_id);
        writer.writeInt(i64, self.timestamp);
        try Packet.serializeOperation(writer, self.op);
        return writer.buffer[0..writer.pos];
    }

    pub fn deserialize(allocator: Allocator, data: []const u8) !Packet {
        var offset: usize = 0;
        const checksum = try Packet.readBytes(data, &offset, u64);
        const packet_length = try Packet.readBytes(data, &offset, u32);
        const packet_id = try Packet.readBytes(data, &offset, u32);
        const session_id = try Packet.readBytes(data, &offset, u32);
        const correlation_id = try Packet.readBytes(data, &offset, u64);
        const timestamp = try Packet.readBytes(data, &offset, i64);
        const op = try Packet.deserializeOperation(allocator, data, &offset);
        return Packet{
            .checksum = checksum,
            .packet_length = packet_length,
            .packet_id = packet_id,
            .session_id = session_id,
            .correlation_id = correlation_id,
            .timestamp = timestamp,
            .op = op,
        };
    }

    pub fn free(allocator: Allocator, pck: Packet) void {
        switch (pck.op) {
            // Most operations use string slices from packet data - no explicit free needed
            .Create, .Drop, .List => {},
            .Insert, .Read, .Update, .Delete => {},
            .Range, .Query, .Aggregate, .Scan => {},
            .Authenticate, .AuthenticateApiKey, .Logout => {},
            .ResetPassword => {},
            .Restore, .CleanBackups => {},
            .Reply, .Flush, .Shutdown => {},
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

    fn serializeAttribute(writer: *BufferWriter, attr: Attribute) !void {
        const tag = @intFromEnum(attr);
        writer.writeInt(u8, tag);
        switch (attr) {
            .I8 => |data| {
                writer.writeString(data.name);
                writer.writeInt(i8, data.value);
            },
            .I16 => |data| {
                writer.writeString(data.name);
                writer.writeInt(i16, data.value);
            },
            .I32 => |data| {
                writer.writeString(data.name);
                writer.writeInt(i32, data.value);
            },
            .I64 => |data| {
                writer.writeString(data.name);
                writer.writeInt(i64, data.value);
            },
            .I128 => |data| {
                writer.writeString(data.name);
                writer.writeInt(i128, data.value);
            },
            .U8 => |data| {
                writer.writeString(data.name);
                writer.writeInt(u8, data.value);
            },
            .U16 => |data| {
                writer.writeString(data.name);
                writer.writeInt(u16, data.value);
            },
            .U32 => |data| {
                writer.writeString(data.name);
                writer.writeInt(u32, data.value);
            },
            .U64 => |data| {
                writer.writeString(data.name);
                writer.writeInt(u64, data.value);
            },
            .U128 => |data| {
                writer.writeString(data.name);
                writer.writeInt(u128, data.value);
            },
            .F32 => |data| {
                writer.writeString(data.name);
                writer.writeInt(i32, @bitCast(data.value));
            },
            .F64 => |data| {
                writer.writeString(data.name);
                writer.writeInt(i64, @bitCast(data.value));
            },
            .F128 => |data| {
                writer.writeString(data.name);
                writer.writeInt(i128, @bitCast(data.value));
            },
            .Pointer => |data| {
                writer.writeString(data.name);
                writer.writeString(data.value);
            },
        }
    }

    fn serializeOperation(writer: *BufferWriter, op: Operation) !void {
        const tag = @intFromEnum(op);
        writer.writeInt(u8, tag);
        switch (op) {
            // ========== SCHEMA/METADATA OPERATIONS ==========
            .Create => |data| {
                writer.writeInt(u8, @intFromEnum(data.doc_type));
                writer.writeString(data.ns);
                writer.writeString(data.payload);
                writer.writeInt(u8, if (data.auto_create) 1 else 0);
                if (data.metadata) |meta| {
                    writer.writeInt(u8, 1);
                    writer.writeString(meta);
                } else {
                    writer.writeInt(u8, 0);
                }
            },
            .Drop => |data| {
                writer.writeInt(u8, @intFromEnum(data.doc_type));
                writer.writeString(data.name);
            },
            .List => |data| {
                writer.writeInt(u8, @intFromEnum(data.doc_type));
                if (data.ns) |ns| {
                    writer.writeInt(u8, 1);
                    writer.writeString(ns);
                } else {
                    writer.writeInt(u8, 0);
                }
                if (data.limit) |lim| {
                    writer.writeInt(u8, 1);
                    writer.writeInt(u32, lim);
                } else {
                    writer.writeInt(u8, 0);
                }
                if (data.offset) |off| {
                    writer.writeInt(u8, 1);
                    writer.writeInt(u32, off);
                } else {
                    writer.writeInt(u8, 0);
                }
            },
            // ========== DOCUMENT DATA OPERATIONS ==========
            .Insert => |data| {
                writer.writeString(data.store_ns);
                writer.writeString(data.payload);
                writer.writeInt(u8, if (data.auto_create) 1 else 0);
            },
            .BatchInsert => |data| {
                writer.writeString(data.store_ns);
                const count = @as(u32, @intCast(data.values.len));
                writer.writeInt(u32, count);
                for (data.values) |value| {
                    writer.writeString(value);
                }
            },
            .Read => |data| {
                writer.writeString(data.store_ns);
                writer.writeInt(u128, data.id);
            },
            .Update => |data| {
                writer.writeString(data.store_ns);
                writer.writeInt(u128, data.id);
                writer.writeString(data.payload);
            },
            .Delete => |data| {
                writer.writeString(data.store_ns);
                if (data.id) |id| {
                    writer.writeInt(u8, 1);
                    writer.writeInt(u128, id);
                } else {
                    writer.writeInt(u8, 0);
                }
                if (data.query_json) |qj| {
                    writer.writeInt(u8, 1);
                    writer.writeString(qj);
                } else {
                    writer.writeInt(u8, 0);
                }
            },
            // ========== QUERY OPERATIONS ==========
            .Range => |data| {
                writer.writeString(data.store_ns);
                try serializeAttribute(writer, data.start_key);
                try serializeAttribute(writer, data.end_key);
            },
            .Query => |data| {
                writer.writeString(data.store_ns);
                writer.writeString(data.query_json);
            },
            .Aggregate => |data| {
                writer.writeString(data.store_ns);
                writer.writeString(data.aggregate_json);
            },
            .Scan => |data| {
                writer.writeString(data.store_ns);
                if (data.start_key) |key| {
                    writer.writeInt(u8, 1);
                    writer.writeInt(u128, key);
                } else {
                    writer.writeInt(u8, 0);
                }
                writer.writeInt(u32, data.limit);
                writer.writeInt(u32, data.skip);
            },
            // ========== AUTHENTICATION OPERATIONS ==========
            .Authenticate => |data| {
                writer.writeString(data.username);
                writer.writeString(data.password);
            },
            .AuthenticateApiKey => |data| {
                writer.writeString(data.api_key);
            },
            .Logout => {},
            // ========== USER MANAGEMENT OPERATIONS ==========
            .ResetPassword => |data| {
                writer.writeString(data.username);
                writer.writeString(data.old_password);
                writer.writeString(data.new_password);
            },
            // ========== BACKUP OPERATIONS ==========
            .Restore => |data| {
                writer.writeString(data.backup_path);
                writer.writeString(data.target_path);
            },
            .CleanBackups => |data| {
                writer.writeString(data.backup_dir);
                writer.writeInt(u32, data.keep_count);
            },
            // ========== SERVER CONTROL OPERATIONS ==========
            .Reply => |data| {
                const status_byte = @intFromEnum(data.status);
                writer.writeInt(u8, status_byte);
                if (data.data) |d| {
                    writer.writeInt(u8, 1);
                    writer.writeString(d);
                } else {
                    writer.writeInt(u8, 0);
                }
            },
            .BatchReply => |data| {
                const status_byte = @intFromEnum(data.status);
                writer.writeInt(u8, status_byte);
                const count = @as(u32, @intCast(data.results.len));
                writer.writeInt(u32, count);
                for (data.results) |result| {
                    writer.writeString(result);
                }
            },
            .Flush => {},
            .Shutdown => {},
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
                const username = try Packet.readString(allocator, data, offset);
                const password = try Packet.readString(allocator, data, offset);

                return Operation{ .Authenticate = .{
                    .username = username,
                    .password = password,
                } };
            },
            // Tag 112: AuthenticateApiKey
            112 => {
                const api_key = try Packet.readString(allocator, data, offset);

                return Operation{ .AuthenticateApiKey = .{
                    .api_key = api_key,
                } };
            },
            // Tag 113: Logout
            113 => Operation.Logout,
            // Tag 114: ResetPassword
            114 => {
                const username = try Packet.readString(allocator, data, offset);
                const old_password = try Packet.readString(allocator, data, offset);
                const new_password = try Packet.readString(allocator, data, offset);

                return Operation{ .ResetPassword = .{
                    .username = username,
                    .old_password = old_password,
                    .new_password = new_password,
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
            // Tag 116: CleanBackups
            116 => {
                const backup_dir = try Packet.readString(allocator, data, offset);
                const keep_count = try Packet.readBytes(data, offset, u32);

                return Operation{ .CleanBackups = .{
                    .backup_dir = backup_dir,
                    .keep_count = keep_count,
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

pub fn generateCorrelationId(session_id: u32) u64 {
    const posix = std.posix;
    const ts = posix.clock_gettime(posix.CLOCK.REALTIME) catch {
        return @as(u64, session_id);
    };
    const seconds: i64 = @intCast(ts.sec);
    const nanos: i64 = @intCast(ts.nsec);
    const ms_timestamp: u32 = @intCast((seconds * 1000 + @divTrunc(nanos, 1_000_000)) & 0xFFFFFFFF);
    return (@as(u64, ms_timestamp) << 32) | @as(u64, session_id);
}

pub fn extractTimestamp(correlation_id: u64) i64 {
    return correlation_id >> 32;
}

pub fn extractSessionId(correlation_id: u64) u32 {
    return @intCast(@as(u64, @bitCast(correlation_id)) & 0xFFFFFFFF);
}

pub const BufferWriter = struct {
    buffer: []u8,
    pos: usize = 0,

    pub fn init(allocator: Allocator) !BufferWriter {
        return BufferWriter{
            .buffer = try allocator.alloc(u8, 1048576),
        };
    }

    pub fn deinit(self: *BufferWriter, allocator: Allocator) void {
        allocator.free(self.buffer);
    }

    pub fn reset(self: *BufferWriter) void {
        // @memset(self.buffer, 0);
        self.pos = 0;
    }

    inline fn writeBytes(self: *BufferWriter, data: []const u8) void {
        @memcpy(self.buffer[self.pos .. self.pos + data.len], data);
        self.pos += data.len;
    }

    inline fn writeInt(self: *BufferWriter, comptime T: type, value: T) void {
        const bytes = std.mem.asBytes(&value);
        @memcpy(self.buffer[self.pos .. self.pos + bytes.len], bytes);
        self.pos += bytes.len;
    }

    inline fn writeString(self: *BufferWriter, str: []const u8) void {
        self.writeInt(u32, @intCast(str.len));
        @memcpy(self.buffer[self.pos .. self.pos + str.len], str);
        self.pos += str.len;
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

test "correlation id" {
    const session_id = 42;
    const correlation_id = generateCorrelationId(session_id);
    std.debug.print("\nCor ID: {}\n", .{correlation_id});
    const extractedsessid = extractSessionId(correlation_id);
    std.debug.print("\nExtracted Session ID: {}\n", .{extractedsessid});
    // try expectEqual(correlation_id, 178956970);
}

test "serialize and deserialize basic message with Flush op" {
    const allocator = testing.allocator;
    const original = Packet{
        .checksum = 12345,
        .packet_length = 100,
        .packet_id = 1,
        .session_id = 42,
        .correlation_id = 999,
        .timestamp = 1234567890,
        .op = Operation.Flush,
    };
    var bw = try BufferWriter.init(allocator);
    defer bw.deinit(allocator);
    const serialized = try original.serialize(&bw);
    const deserialized = try Packet.deserialize(allocator, serialized);
    defer Packet.free(allocator, deserialized);
    try expectEqual(original.checksum, deserialized.checksum);
    try expectEqual(original.packet_length, deserialized.packet_length);
    try expectEqual(original.packet_id, deserialized.packet_id);
    try expectEqual(original.session_id, deserialized.session_id);
    try expectEqual(original.correlation_id, deserialized.correlation_id);
    try expectEqual(original.timestamp, deserialized.timestamp);
    try expectEqual(@intFromEnum(original.op), @intFromEnum(deserialized.op));
}

test "serialize and deserialize Get operation with attributes" {
    const allocator = testing.allocator;
    var attrs = [_]Attribute{
        Attribute{ .U32 = .{ .name = "id", .value = 123 } },
        Attribute{ .I64 = .{ .name = "timestamp", .value = -456 } },
        Attribute{ .F64 = .{ .name = "price", .value = 99.99 } },
        Attribute{ .Pointer = .{ .name = "data", .value = "hello world" } },
    };
    const original = Packet{
        .checksum = 54321,
        .packet_length = 200,
        .packet_id = 2,
        .session_id = 84,
        .correlation_id = 1998,
        .timestamp = 9876543210,
        .op = Operation{ .Get = .{ .ns = "test_namespace", .attributes = &attrs } },
    };
    var bw = try BufferWriter.init(allocator);
    defer bw.deinit(allocator);
    const serialized = try original.serialize(&bw);
    const deserialized = try Packet.deserialize(allocator, serialized);
    defer Packet.free(allocator, deserialized);
    try expectEqual(original.checksum, deserialized.checksum);
    try expectEqualStrings(original.op.Get.ns, deserialized.op.Get.ns);
    try expectEqual(original.op.Get.attributes.len, deserialized.op.Get.attributes.len);
    try expectEqual(@intFromEnum(original.op.Get.attributes[0]), @intFromEnum(deserialized.op.Get.attributes[0]));
    try expectEqualStrings(original.op.Get.attributes[0].U32.name, deserialized.op.Get.attributes[0].U32.name);
    try expectEqual(original.op.Get.attributes[0].U32.value, deserialized.op.Get.attributes[0].U32.value);
    try expectEqualStrings(original.op.Get.attributes[1].I64.name, deserialized.op.Get.attributes[1].I64.name);
    try expectEqual(original.op.Get.attributes[1].I64.value, deserialized.op.Get.attributes[1].I64.value);
    try expectEqualStrings(original.op.Get.attributes[2].F64.name, deserialized.op.Get.attributes[2].F64.name);
    try expectEqual(original.op.Get.attributes[2].F64.value, deserialized.op.Get.attributes[2].F64.value);
    try expectEqualStrings(original.op.Get.attributes[3].Pointer.name, deserialized.op.Get.attributes[3].Pointer.name);
    try expectEqualStrings(original.op.Get.attributes[3].Pointer.value, deserialized.op.Get.attributes[3].Pointer.value);
}

test "serialize and deserialize Post operation" {
    const allocator = testing.allocator;
    const original = Packet{
        .checksum = 11111,
        .packet_length = 150,
        .packet_id = 3,
        .session_id = 21,
        .correlation_id = 5555,
        .timestamp = 1111111111,
        .op = Operation{ .Post = .{ .store_ns = "my.store", .ns = "documents", .value = "document content here" } },
    };
    var bw = try BufferWriter.init(allocator);
    defer bw.deinit(allocator);
    const serialized = try original.serialize(&bw);
    const deserialized = try Packet.deserialize(allocator, serialized);
    defer Packet.free(allocator, deserialized);
    try expectEqualStrings(original.op.Post.store_ns, deserialized.op.Post.store_ns);
    try expectEqualStrings(original.op.Post.ns, deserialized.op.Post.ns);
    try expectEqualStrings(original.op.Post.value, deserialized.op.Post.value);
}

test "serialize and deserialize Reply operation with data" {
    const allocator = testing.allocator;
    const original = Packet{
        .checksum = 22222,
        .packet_length = 75,
        .packet_id = 4,
        .session_id = 63,
        .correlation_id = 7777,
        .timestamp = 2222222222,
        .op = Operation{ .Reply = .{ .status = Status.ok, .data = "response data" } },
    };
    var bw = try BufferWriter.init(allocator);
    defer bw.deinit(allocator);
    const serialized = try original.serialize(&bw);
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
        .session_id = 105,
        .correlation_id = 8888,
        .timestamp = 3333333333,
        .op = Operation{ .Reply = .{ .status = Status.not_found, .data = null } },
    };
    var bw = try BufferWriter.init(allocator);
    defer bw.deinit(allocator);
    const serialized = try original.serialize(&bw);
    const deserialized = try Packet.deserialize(allocator, serialized);
    defer Packet.free(allocator, deserialized);
    try expectEqual(original.op.Reply.status, deserialized.op.Reply.status);
    try expect(deserialized.op.Reply.data == null);
}

test "serialize and deserialize Put operation" {
    const allocator = testing.allocator;
    var attrs = [_]Attribute{
        Attribute{ .U8 = .{ .name = "version", .value = 1 } },
        Attribute{ .I128 = .{ .name = "big_number", .value = 123456789012345678901234567890 } },
    };

    const original = Packet{
        .checksum = 44444,
        .packet_length = 300,
        .packet_id = 6,
        .session_id = 147,
        .correlation_id = 9999,
        .timestamp = 4444444444,
        .op = Operation{ .Put = .{ .ns = "storage", .value = "updated content", .attributes = &attrs } },
    };
    var bw = try BufferWriter.init(allocator);
    defer bw.deinit(allocator);
    const serialized = try original.serialize(&bw);
    const deserialized = try Packet.deserialize(allocator, serialized);
    defer Packet.free(allocator, deserialized);
    try expectEqualStrings(original.op.Put.ns, deserialized.op.Put.ns);
    try expectEqualStrings(original.op.Put.value, deserialized.op.Put.value);
    try expectEqual(original.op.Put.attributes.len, deserialized.op.Put.attributes.len);
    try expectEqualStrings(original.op.Put.attributes[0].U8.name, deserialized.op.Put.attributes[0].U8.name);
    try expectEqual(original.op.Put.attributes[0].U8.value, deserialized.op.Put.attributes[0].U8.value);
    try expectEqualStrings(original.op.Put.attributes[1].I128.name, deserialized.op.Put.attributes[1].I128.name);
    try expectEqual(original.op.Put.attributes[1].I128.value, deserialized.op.Put.attributes[1].I128.value);
}

test "serialize and deserialize Del operation" {
    const allocator = testing.allocator;
    var attrs = [_]Attribute{
        Attribute{ .F32 = .{ .name = "threshold", .value = 0.5 } },
    };
    const original = Packet{
        .checksum = 55555,
        .packet_length = 80,
        .packet_id = 7,
        .session_id = 189,
        .correlation_id = 1111,
        .timestamp = 5555555555,
        .op = Operation{ .Del = .{ .ns = "cache", .attributes = &attrs } },
    };
    var bw = try BufferWriter.init(allocator);
    defer bw.deinit(allocator);
    const serialized = try original.serialize(&bw);
    const deserialized = try Packet.deserialize(allocator, serialized);
    defer Packet.free(allocator, deserialized);
    try expectEqualStrings(original.op.Del.ns, deserialized.op.Del.ns);
    try expectEqual(original.op.Del.attributes.len, deserialized.op.Del.attributes.len);
    try expectEqualStrings(original.op.Del.attributes[0].F32.name, deserialized.op.Del.attributes[0].F32.name);
    try expectEqual(original.op.Del.attributes[0].F32.value, deserialized.op.Del.attributes[0].F32.value);
}

test "serialize and deserialize all attribute types" {
    const allocator = testing.allocator;
    var attrs = [_]Attribute{
        Attribute{ .I8 = .{ .name = "i8_val", .value = -127 } },
        Attribute{ .I16 = .{ .name = "i16_val", .value = -32767 } },
        Attribute{ .I32 = .{ .name = "i32_val", .value = -2147483647 } },
        Attribute{ .I64 = .{ .name = "i64_val", .value = -9223372036854775807 } },
        Attribute{ .U8 = .{ .name = "u8_val", .value = 255 } },
        Attribute{ .U16 = .{ .name = "u16_val", .value = 65535 } },
        Attribute{ .U32 = .{ .name = "u32_val", .value = 4294967295 } },
        Attribute{ .U64 = .{ .name = "u64_val", .value = 18446744073709551615 } },
        Attribute{ .F32 = .{ .name = "f32_val", .value = 3.14159 } },
        Attribute{ .F64 = .{ .name = "f64_val", .value = 2.718281828459045 } },
    };
    const original = Packet{
        .checksum = 66666,
        .packet_length = 500,
        .packet_id = 8,
        .session_id = 231,
        .correlation_id = 2222,
        .timestamp = 6666666666,
        .op = Operation{ .Get = .{ .ns = "all_types_test", .attributes = &attrs } },
    };
    var bw = try BufferWriter.init(allocator);
    defer bw.deinit(allocator);
    const serialized = try original.serialize(&bw);
    const deserialized = try Packet.deserialize(allocator, serialized);
    defer Packet.free(allocator, deserialized);
    try expectEqual(attrs.len, deserialized.op.Get.attributes.len);
    for (attrs, deserialized.op.Get.attributes) |orig_attr, deser_attr| {
        try expectEqual(@intFromEnum(orig_attr), @intFromEnum(deser_attr));
        switch (orig_attr) {
            .I8 => |data| {
                try expectEqualStrings(data.name, deser_attr.I8.name);
                try expectEqual(data.value, deser_attr.I8.value);
            },
            .I16 => |data| {
                try expectEqualStrings(data.name, deser_attr.I16.name);
                try expectEqual(data.value, deser_attr.I16.value);
            },
            .I32 => |data| {
                try expectEqualStrings(data.name, deser_attr.I32.name);
                try expectEqual(data.value, deser_attr.I32.value);
            },
            .I64 => |data| {
                try expectEqualStrings(data.name, deser_attr.I64.name);
                try expectEqual(data.value, deser_attr.I64.value);
            },
            .U8 => |data| {
                try expectEqualStrings(data.name, deser_attr.U8.name);
                try expectEqual(data.value, deser_attr.U8.value);
            },
            .U16 => |data| {
                try expectEqualStrings(data.name, deser_attr.U16.name);
                try expectEqual(data.value, deser_attr.U16.value);
            },
            .U32 => |data| {
                try expectEqualStrings(data.name, deser_attr.U32.name);
                try expectEqual(data.value, deser_attr.U32.value);
            },
            .U64 => |data| {
                try expectEqualStrings(data.name, deser_attr.U64.name);
                try expectEqual(data.value, deser_attr.U64.value);
            },
            .F32 => |data| {
                try expectEqualStrings(data.name, deser_attr.F32.name);
                try expectEqual(data.value, deser_attr.F32.value);
            },
            .F64 => |data| {
                try expectEqualStrings(data.name, deser_attr.F64.name);
                try expectEqual(data.value, deser_attr.F64.value);
            },
            else => {},
        }
    }
}

test "serialize and deserialize all status types" {
    const allocator = testing.allocator;
    const statuses = [_]Status{ .ok, .err, .not_found, .invalid_request, .server_error };
    for (statuses) |status| {
        const original = Packet{
            .checksum = 77777,
            .packet_length = 25,
            .packet_id = 9,
            .session_id = 273,
            .correlation_id = 3333,
            .timestamp = 7777777777,
            .op = Operation{ .Reply = .{ .status = status, .data = null } },
        };
        var bw = try BufferWriter.init(allocator);
        defer bw.deinit(allocator);
        const serialized = try original.serialize(&bw);
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
    var invalid_op_data = [_]u8{0} ** 48;
    invalid_op_data[47] = 255;
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
