const std = @import("std");

pub const ValueType = enum {
    I8,
    I16,
    I32,
    I64,
    I128,
    U8,
    U16,
    U32,
    U64,
    U128,
    F32,
    F64,
    F128,
    Pointer,
};

pub const Status = enum(u8) {
    ok = 0,
    err = 1,
    not_found = 2,
    invalid_request = 3,
    server_error = 4,
    no_index_on_field = 5,
    document_too_large = 6,
    not_leader = 7,

    pub fn toString(self: Status) []const u8 {
        return switch (self) {
            .ok => "Success",
            .err => "General error occurred",
            .not_found => "Resource not found",
            .invalid_request => "Invalid request format",
            .server_error => "Internal server error",
            .no_index_on_field => "No index on field",
            .document_too_large => "Document exceeds size limit",
            .not_leader => "Not the leader node",
        };
    }
};

/// Standard error codes for structured error responses.
/// Sent inside the Reply data payload as JSON: {"code":1001,"error":"store_not_found","message":"..."}
pub const ErrorCode = enum(u16) {
    // 1000-1099: Success / informational
    success = 1000,

    // 1100-1199: Not found errors
    not_found = 1100,
    store_not_found = 1101,
    space_not_found = 1102,
    user_not_found = 1103,
    index_not_found = 1104,
    key_not_found = 1105,

    // 1200-1299: Authentication / authorization errors
    unauthorized = 1200,
    invalid_credentials = 1201,
    session_expired = 1202,
    permission_denied = 1203,
    account_locked = 1204,
    user_disabled = 1205,
    user_already_exists = 1206,

    // 1300-1399: Validation / request errors
    invalid_request = 1300,
    invalid_namespace = 1301,
    invalid_query = 1302,
    key_too_large = 1303,
    document_too_large = 1304,
    batch_too_large = 1305,
    no_index_on_field = 1306,
    invalid_field_type = 1307,
    missing_required_field = 1308,
    duplicate_index = 1309,

    // 1400-1499: Server state errors
    server_offline = 1400,
    not_leader = 1401,
    read_only = 1402,
    store_already_exists = 1403,
    space_delete_in_progress = 1404,
    store_delete_in_progress = 1405,
    // 1500-1599: Internal server errors
    internal_error = 1500,
    io_error = 1501,
    wal_error = 1502,
    replication_error = 1503,

    pub fn toName(self: ErrorCode) []const u8 {
        return switch (self) {
            .success => "success",
            .not_found => "not_found",
            .store_not_found => "store_not_found",
            .space_not_found => "space_not_found",
            .user_not_found => "user_not_found",
            .index_not_found => "index_not_found",
            .key_not_found => "key_not_found",
            .unauthorized => "unauthorized",
            .invalid_credentials => "invalid_credentials",
            .session_expired => "session_expired",
            .permission_denied => "permission_denied",
            .account_locked => "account_locked",
            .user_disabled => "user_disabled",
            .user_already_exists => "user_already_exists",
            .invalid_request => "invalid_request",
            .invalid_namespace => "invalid_namespace",
            .invalid_query => "invalid_query",
            .key_too_large => "key_too_large",
            .document_too_large => "document_too_large",
            .batch_too_large => "batch_too_large",
            .no_index_on_field => "no_index_on_field",
            .invalid_field_type => "invalid_field_type",
            .missing_required_field => "missing_required_field",
            .duplicate_index => "duplicate_index",
            .server_offline => "server_offline",
            .not_leader => "not_leader",
            .read_only => "read_only",
            .store_already_exists => "store_already_exists",
            .space_delete_in_progress => "space_delete_in_progress",
            .store_delete_in_progress => "store_delete_in_progress",
            .internal_error => "internal_error",
            .io_error => "io_error",
            .wal_error => "wal_error",
            .replication_error => "replication_error",
        };
    }

    pub fn toStatus(self: ErrorCode) Status {
        return switch (self) {
            .success => .ok,
            .not_found, .store_not_found, .space_not_found, .user_not_found, .index_not_found, .key_not_found => .not_found,
            .unauthorized, .invalid_credentials, .session_expired, .permission_denied, .account_locked, .user_disabled, .user_already_exists => .err,
            .invalid_request, .invalid_namespace, .invalid_query, .key_too_large, .missing_required_field, .invalid_field_type, .duplicate_index => .invalid_request,
            .document_too_large, .batch_too_large => .document_too_large,
            .no_index_on_field => .no_index_on_field,
            .server_offline, .read_only, .store_already_exists, .space_delete_in_progress, .store_delete_in_progress => .invalid_request,
            .not_leader => .not_leader,
            .internal_error, .io_error, .wal_error, .replication_error => .server_error,
        };
    }

    /// Formats a structured JSON error string: {"code":1101,"error":"store_not_found","message":"..."}
    pub fn formatError(self: ErrorCode, allocator: std.mem.Allocator, message: []const u8) ![]u8 {
        var buf: std.ArrayList(u8) = .empty;
        errdefer buf.deinit(allocator);
        try buf.print(allocator,
            \\{{"code":{d},"error":"{s}","message":"{s}"}}
        , .{ @intFromEnum(self), self.toName(), message });
        return try buf.toOwnedSlice(allocator);
    }
};

pub const Attribute = union(enum) {
    I8: struct {
        name: []const u8,
        value: i8,
    },
    I16: struct {
        name: []const u8,
        value: i16,
    },
    I32: struct {
        name: []const u8,
        value: i32,
    },
    I64: struct {
        name: []const u8,
        value: i64,
    },
    I128: struct {
        name: []const u8,
        value: i128,
    },
    U8: struct {
        name: []const u8,
        value: u8,
    },
    U16: struct {
        name: []const u8,
        value: u16,
    },
    U32: struct {
        name: []const u8,
        value: u32,
    },
    U64: struct {
        name: []const u8,
        value: u64,
    },
    U128: struct {
        name: []const u8,
        value: u128,
    },
    F32: struct {
        name: []const u8,
        value: f32,
    },
    F64: struct {
        name: []const u8,
        value: f64,
    },
    F128: struct {
        name: []const u8,
        value: f128,
    },
    Pointer: struct {
        name: []const u8,
        value: []const u8,
    },

    pub fn calcAttributeSize(attr: *const Attribute) usize {
        var size: usize = 1; // type tag

        switch (attr.*) {
            .I8 => |data| size += 4 + data.name.len + 1,
            .I16 => |data| size += 4 + data.name.len + 2,
            .I32 => |data| size += 4 + data.name.len + 4,
            .I64 => |data| size += 4 + data.name.len + 8,
            .I128 => |data| size += 4 + data.name.len + 16,
            .U8 => |data| size += 4 + data.name.len + 1,
            .U16 => |data| size += 4 + data.name.len + 2,
            .U32 => |data| size += 4 + data.name.len + 4,
            .U64 => |data| size += 4 + data.name.len + 8,
            .U128 => |data| size += 4 + data.name.len + 16,
            .F32 => |data| size += 4 + data.name.len + 4,
            .F64 => |data| size += 4 + data.name.len + 8,
            .F128 => |data| size += 4 + data.name.len + 16,
            .Pointer => |data| size += 4 + data.name.len + 4 + data.value.len,
        }

        return size;
    }
};

pub const StatsTag = enum(u8) {
    WalStats = 1,
    DbStats = 2,
    IndexStats = 3,
    VLogStats = 4,
    GcStats = 5,
    HistoryStats = 6,
    AllStats = 255,
};

// Explicit operation tags to ensure correct wire protocol values
pub const OperationTag = enum(u8) {
    Create = 100,
    Drop = 101,
    List = 102,
    Insert = 103,
    BatchInsert = 104,
    Read = 105,
    Update = 106,
    Delete = 107,
    Range = 108,
    Query = 109,
    Aggregate = 110,
    Authenticate = 111,
    ShipWal = 112,
    Logout = 113,
    RegenerateKey = 114,
    Restore = 115,
    Backup = 116,
    Reply = 117,
    BatchReply = 118,
    Flush = 119,
    Shutdown = 120,
    Scan = 121,
    Stats = 122,
    Collect = 123,
    Vlogs = 124,
    SetMode = 125,
    UpdateUser = 126,
    GetConfig = 127,
    SetConfig = 128,
};

pub const Operation = union(OperationTag) {
    // ========== SCHEMA/METADATA OPERATIONS (Non-Document Entities) ==========
    // Tag 100: Create schema entities (Space, Store, Index, User, Backup - NOT Document)
    Create: struct {
        doc_type: DocType, // 1=Space, 2=Store, 3=Index, 5=User, 6=Backup (NOT 4=Document)
        ns: []const u8, // "space" | "space.store" | "space.store.index" | username | backup_name
        payload: []const u8, // JSON/CBOR data
        auto_create: bool, // Auto-provision parents if missing
        metadata: ?[]const u8, // Optional metadata (description, etc.)
    },

    // Tag 101: Drop schema entities (Space, Store, Index, User, Backup - NOT Document)
    Drop: struct {
        doc_type: DocType, // 1=Space, 2=Store, 3=Index, 5=User, 6=Backup (NOT 4=Document)
        name: []const u8, // Entity name or namespace
    },

    // Tag 102: List schema entities with pagination (Space, Store, Index, User, Backup - NOT Document)
    List: struct {
        doc_type: DocType, // 1=Space, 2=Store, 3=Index, 5=User, 6=Backup (NOT 4=Document)
        ns: ?[]const u8, // Optional namespace filter
        limit: ?u32,
        offset: ?u32,
    },

    // ========== DOCUMENT DATA OPERATIONS ==========
    // Tag 103: Insert single document
    Insert: struct {
        store_ns: []const u8, // "space.store"
        payload: []const u8, // CBOR encoded document
        auto_create: bool, // Auto-provision space/store if missing
    },

    // Tag 104: Insert multiple documents (batch)
    BatchInsert: struct {
        store_ns: []const u8,
        values: [][]const u8, // Array of document values (CBOR encoded)
    },

    // Tag 105: Read document by ID
    Read: struct {
        store_ns: []const u8,
        id: u128, // Document ID
    },

    // Tag 106: Update document
    Update: struct {
        store_ns: []const u8,
        id: u128, // Document ID
        payload: []const u8, // New CBOR data
    },

    // Tag 107: Delete document(s)
    Delete: struct {
        store_ns: []const u8,
        id: ?u128, // Optional - if null, uses query filters
        query_json: ?[]const u8, // Optional - filter JSON for query-based delete
    },

    // ========== QUERY OPERATIONS ==========
    // Tag 108: Range query on documents
    Range: struct {
        store_ns: []const u8,
        start_key: Attribute,
        end_key: Attribute,
    },

    // Tag 109: Query documents with filter/sort/limit
    Query: struct {
        store_ns: []const u8, // Store namespace
        query_json: []const u8,
    },

    // Tag 110: Aggregate documents
    Aggregate: struct {
        store_ns: []const u8, // Store namespace
        aggregate_json: []const u8,
    },

    // ========== AUTHENTICATION OPERATIONS ==========
    // Tag 111: Authenticate with uid/key
    Authenticate: struct {
        uid: []const u8,
        key: []const u8,
    },

    // Tag 112: Ship WAL record to sibling (server-to-server replication only)
    ShipWal: struct {
        op_kind: u8, // 0=insert, 1=update, 2=delete (OpKind ordinal)
        store_ns: []const u8, // "space.store"
        lsn: u64,
        doc_id: u128, // original document key
        timestamp: i64, // original write timestamp from primary
        data: []const u8, // CBOR payload; empty slice for delete
    },

    // Tag 113: Logout/revoke session
    Logout: void,

    // ========== USER MANAGEMENT OPERATIONS ==========
    // Tag 114: Regenerate key for a user
    RegenerateKey: struct {
        uid: []const u8,
    },

    // ========== BACKUP OPERATIONS ==========
    // Tag 115: Restore from backup
    Restore: struct {
        backup_path: []const u8,
        target_path: []const u8,
    },

    // Tag 116: Cleanup old backups
    Backup:  struct {
        path: []const u8,
    },
    // ========== SERVER CONTROL OPERATIONS ==========
    // Tag 117: Reply from server
    Reply: struct {
        status: Status,
        data: ?[]const u8,
    },

    // Tag 118: Batch reply from server
    BatchReply: struct {
        status: Status,
        results: [][]const u8, // Array of results (keys or error messages)
    },

    // Tag 119: Flush data to disk
    Flush: void,

    // Tag 120: Shutdown server
    Shutdown: void,

    // Tag 121: Scan documents (range read with limit/offset)
    Scan: struct {
        store_ns: []const u8, // Store namespace
        start_key: ?u128, // Optional starting key (null = from beginning)
        limit: u32, // Number of records to return
        skip: u32, // Number of records to skip
    },

    Stats: struct { stat: StatsTag },

    Collect: struct { vlogs: []const u8 },
    Vlogs: void,

    // Tag 125: Set server operation mode (admin only)
    SetMode: struct {
        online: bool, // true = online (normal), false = offline (admin-only)
    },

    // Tag 126: Update user role
    UpdateUser: struct {
        uid: []const u8,
        role: u8,
    },

    // ========== CONFIGURATION OPERATIONS ==========
    // Tag 127: Get server configuration
    GetConfig: void,

    // Tag 128: Set server configuration
    SetConfig: struct {
        data: []const u8, // YAML configuration string
    },

};

// Metadata

pub const DocType = enum(u8) {
    Space = 1,
    Store = 2,
    Index = 3,
    Document = 4,
    User = 5,
    Backup = 6,
};

pub const FieldType = enum(u8) {
    String = 1,
    U32 = 2,
    U64 = 3,
    I32 = 4,
    I64 = 5,
    F32 = 6,
    F64 = 7,
    Boolean = 8,
};

pub const SpaceStatus = enum(u8) {
    active = 0,
    deleting = 1,
};

pub const StoreStatus = enum(u8) {
    active = 0,
    deleting = 1,
};

pub const Space = struct {
    id: u16,
    ns: []const u8,
    description: ?[]const u8 = null,
    created_at: i64 = 0,
    status: SpaceStatus = .active,
};

pub const Store = struct {
    id: u16,
    store_id: u16, // Embedded in keys to route to correct indexes
    ns: []const u8,
    description: ?[]const u8 = null,
    created_at: i64 = 0,
    status: StoreStatus = .active,
};

pub const Index = struct {
    id: u16,
    store_id: u16, // Which store this index belongs to
    ns: []const u8,
    field: []const u8,
    field_type: FieldType,
    unique: bool = true,
    description: ?[]const u8 = null,
    created_at: i64 = 0,
    /// Filesystem path to this secondary index file.
    index_path: []const u8 = "",
};

pub const StoreInfo = struct {
    store: Store,
    indexes: []Index,
};

const VLog = struct {
    id: u16,
    file_name: []u8,
    created_at: i64,
};

pub const User = struct {
    id: u16,
    username: []const u8,
    password_hash: []const u8,
    role: u8, // 0=admin, 1=read_write, 2=read_only, 3=none
    created_at: i64 = 0,
};

pub const Backup = struct {
    id: u16,
    name: []const u8,
    backup_path: []const u8,
    size_bytes: u64 = 0,
    created_at: i64 = 0,
    description: ?[]const u8 = null,
};

// ========== NAMESPACE UTILITIES ==========

pub const NamespaceParts = struct {
    space: ?[]const u8,
    store: ?[]const u8,
    index: ?[]const u8,

    pub fn deinit(self: *NamespaceParts, allocator: std.mem.Allocator) void {
        if (self.space) |s| allocator.free(s);
        if (self.store) |s| allocator.free(s);
        if (self.index) |s| allocator.free(s);
    }
};

/// Parse a namespace string into its components
/// Examples:
///   "myspace" -> { space: "myspace", store: null, index: null }
///   "myspace.orders" -> { space: "myspace", store: "orders", index: null }
///   "myspace.orders.user_id_idx" -> { space: "myspace", store: "orders", index: "user_id_idx" }
pub fn parseNamespace(allocator: std.mem.Allocator, ns: []const u8) !NamespaceParts {
    var parts = NamespaceParts{
        .space = null,
        .store = null,
        .index = null,
    };

    var iter = std.mem.splitScalar(u8, ns, '.');
    var count: u8 = 0;

    while (iter.next()) |part| : (count += 1) {
        const part_copy = try allocator.dupe(u8, part);
        switch (count) {
            0 => parts.space = part_copy,
            1 => parts.store = part_copy,
            2 => parts.index = part_copy,
            else => {
                // Too many parts - free this part and cleanup
                allocator.free(part_copy);
                parts.deinit(allocator);
                return error.InvalidNamespace;
            },
        }
    }

    return parts;
}

/// Validate that a namespace string matches the expected DocType
/// Ensures the namespace has the correct number of parts for the entity type
pub fn validateNamespace(ns: []const u8, expected_type: DocType) !void {
    const part_count = std.mem.count(u8, ns, ".") + 1;

    switch (expected_type) {
        .Space => if (part_count != 1) return error.InvalidSpaceNamespace,
        .Store => if (part_count != 2) return error.InvalidStoreNamespace,
        .Index => if (part_count != 3) return error.InvalidIndexNamespace,
        .Document => if (part_count != 2) return error.InvalidDocumentNamespace,
        .User => if (part_count != 1) return error.InvalidUserNamespace,
        .Backup => if (part_count != 1) return error.InvalidBackupNamespace,
    }
}

// ========== Tests ==========

const testing = std.testing;

test "parseNamespace - single part (space)" {
    const allocator = testing.allocator;
    var parts = try parseNamespace(allocator, "myspace");
    defer parts.deinit(allocator);
    try testing.expectEqualStrings("myspace", parts.space.?);
    try testing.expect(parts.store == null);
    try testing.expect(parts.index == null);
}

test "parseNamespace - two parts (space.store)" {
    const allocator = testing.allocator;
    var parts = try parseNamespace(allocator, "myspace.orders");
    defer parts.deinit(allocator);
    try testing.expectEqualStrings("myspace", parts.space.?);
    try testing.expectEqualStrings("orders", parts.store.?);
    try testing.expect(parts.index == null);
}

test "parseNamespace - three parts (space.store.index)" {
    const allocator = testing.allocator;
    var parts = try parseNamespace(allocator, "myspace.orders.user_id_idx");
    defer parts.deinit(allocator);
    try testing.expectEqualStrings("myspace", parts.space.?);
    try testing.expectEqualStrings("orders", parts.store.?);
    try testing.expectEqualStrings("user_id_idx", parts.index.?);
}

test "parseNamespace - too many parts returns error" {
    const allocator = testing.allocator;
    try testing.expectError(error.InvalidNamespace, parseNamespace(allocator, "a.b.c.d"));
}

test "validateNamespace - correct part counts" {
    try validateNamespace("myspace", .Space);
    try validateNamespace("myspace.orders", .Store);
    try validateNamespace("myspace.orders.idx", .Index);
    try validateNamespace("myspace.orders", .Document);
    try validateNamespace("admin", .User);
    try validateNamespace("snap1", .Backup);
}

test "validateNamespace - wrong part counts" {
    try testing.expectError(error.InvalidSpaceNamespace, validateNamespace("a.b", .Space));
    try testing.expectError(error.InvalidStoreNamespace, validateNamespace("a", .Store));
    try testing.expectError(error.InvalidStoreNamespace, validateNamespace("a.b.c", .Store));
    try testing.expectError(error.InvalidIndexNamespace, validateNamespace("a.b", .Index));
    try testing.expectError(error.InvalidDocumentNamespace, validateNamespace("a", .Document));
    try testing.expectError(error.InvalidUserNamespace, validateNamespace("a.b", .User));
    try testing.expectError(error.InvalidBackupNamespace, validateNamespace("a.b", .Backup));
}

test "ValueType has all expected variants" {
    try testing.expectEqual(@as(usize, 14), @typeInfo(ValueType).@"enum".fields.len);
}

test "OperationTag wire values" {
    try testing.expectEqual(@as(u8, 100), @intFromEnum(OperationTag.Create));
    try testing.expectEqual(@as(u8, 103), @intFromEnum(OperationTag.Insert));
    try testing.expectEqual(@as(u8, 109), @intFromEnum(OperationTag.Query));
    try testing.expectEqual(@as(u8, 117), @intFromEnum(OperationTag.Reply));
    try testing.expectEqual(@as(u8, 125), @intFromEnum(OperationTag.SetMode));
}

test "Status toString" {
    try testing.expectEqualStrings("Success", Status.ok.toString());
    try testing.expectEqualStrings("Resource not found", Status.not_found.toString());
    try testing.expectEqualStrings("Internal server error", Status.server_error.toString());
}

test "ErrorCode toName" {
    try testing.expectEqualStrings("success", ErrorCode.success.toName());
    try testing.expectEqualStrings("store_not_found", ErrorCode.store_not_found.toName());
    try testing.expectEqualStrings("invalid_credentials", ErrorCode.invalid_credentials.toName());
    try testing.expectEqualStrings("batch_too_large", ErrorCode.batch_too_large.toName());
    try testing.expectEqualStrings("not_leader", ErrorCode.not_leader.toName());
    try testing.expectEqualStrings("internal_error", ErrorCode.internal_error.toName());
}

test "ErrorCode toStatus mapping" {
    try testing.expectEqual(Status.ok, ErrorCode.success.toStatus());
    try testing.expectEqual(Status.not_found, ErrorCode.store_not_found.toStatus());
    try testing.expectEqual(Status.not_found, ErrorCode.key_not_found.toStatus());
    try testing.expectEqual(Status.invalid_request, ErrorCode.invalid_request.toStatus());
    try testing.expectEqual(Status.document_too_large, ErrorCode.document_too_large.toStatus());
    try testing.expectEqual(Status.no_index_on_field, ErrorCode.no_index_on_field.toStatus());
    try testing.expectEqual(Status.not_leader, ErrorCode.not_leader.toStatus());
    try testing.expectEqual(Status.server_error, ErrorCode.internal_error.toStatus());
    try testing.expectEqual(Status.err, ErrorCode.invalid_credentials.toStatus());
}

test "ErrorCode numeric values" {
    try testing.expectEqual(@as(u16, 1000), @intFromEnum(ErrorCode.success));
    try testing.expectEqual(@as(u16, 1101), @intFromEnum(ErrorCode.store_not_found));
    try testing.expectEqual(@as(u16, 1201), @intFromEnum(ErrorCode.invalid_credentials));
    try testing.expectEqual(@as(u16, 1304), @intFromEnum(ErrorCode.document_too_large));
    try testing.expectEqual(@as(u16, 1401), @intFromEnum(ErrorCode.not_leader));
    try testing.expectEqual(@as(u16, 1500), @intFromEnum(ErrorCode.internal_error));
}

test "ErrorCode formatError" {
    const allocator = testing.allocator;
    const json = try ErrorCode.store_not_found.formatError(allocator, "store 'mydb' does not exist");
    defer allocator.free(json);
    try testing.expectEqualStrings(
        \\{"code":1101,"error":"store_not_found","message":"store 'mydb' does not exist"}
    , json);
}

test "Attribute calcAttributeSize" {
    const attr_i8 = Attribute{ .I8 = .{ .name = "age", .value = 25 } };
    try testing.expectEqual(@as(usize, 1 + 4 + 3 + 1), attr_i8.calcAttributeSize()); // tag + len + "age" + i8

    const attr_ptr = Attribute{ .Pointer = .{ .name = "name", .value = "hello" } };
    try testing.expectEqual(@as(usize, 1 + 4 + 4 + 4 + 5), attr_ptr.calcAttributeSize()); // tag + len + "name" + len + "hello"
}
