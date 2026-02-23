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

pub const Status = enum {
    ok,
    err,
    not_found,
    invalid_request,
    server_error,

    pub fn toString(self: Status) []const u8 {
        return switch (self) {
            .ok => "Success",
            .err => "General error occurred",
            .not_found => "Resource not found",
            .invalid_request => "Invalid request format",
            .server_error => "Internal server error",
        };
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

    pub fn calcAttributeSize(attr: *Attribute) usize {
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
    ResetPassword = 114,
    Restore = 115,
    CleanBackups = 116,
    Reply = 117,
    BatchReply = 118,
    Flush = 119,
    Shutdown = 120,
    Scan = 121,
    Stats = 122,
    Collect = 123,
    Vlogs = 124,
    SetMode = 125,
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
    // Tag 111: Authenticate with username/password
    Authenticate: struct {
        username: []const u8,
        password: []const u8,
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
    // Tag 114: Reset password
    ResetPassword: struct {
        username: []const u8,
        old_password: []const u8,
        new_password: []const u8,
    },

    // ========== BACKUP OPERATIONS ==========
    // Tag 115: Restore from backup
    Restore: struct {
        backup_path: []const u8,
        target_path: []const u8,
    },

    // Tag 116: Cleanup old backups
    CleanBackups: struct {
        backup_dir: []const u8,
        keep_count: u32,
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

    Collect: struct { vlog: u8 },
    Vlogs: void,

    // Tag 125: Set server operation mode (admin only)
    SetMode: struct {
        online: bool, // true = online (normal), false = offline (admin-only)
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

pub const Space = struct {
    id: u16,
    ns: []const u8,
    description: ?[]const u8 = null,
    created_at: i64 = 0,
};

pub const Store = struct {
    id: u16,
    store_id: u16, // Embedded in keys to route to correct indexes
    ns: []const u8,
    description: ?[]const u8 = null,
    created_at: i64 = 0,
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
                // Too many parts - cleanup and return error
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
