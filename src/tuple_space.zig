const std = @import("std");
const tuple = @import("tuple.zig");

// Export C-compatible functions for Python TupleSpace module - remived it for the time being to use std.heap.raw_c_allocator.

// // C-compatible allocator (matches std.mem.Allocator)
// pub const Allocator = extern struct {
//     alloc: *const fn (size: usize, user_data: *anyopaque) callconv(.C) ?*anyopaque,
//     realloc: *const fn (ptr: ?*anyopaque, size: usize, user_data: *anyopaque) callconv(.C) ?*anyopaque,
//     free: *const fn (ptr: ?*anyopaque, user_data: *anyopaque) callconv(.C) void,
//     user_data: *anyopaque,
// };

// Export C-compatible functions
export fn tuplespace_create() callconv(.C) ?*TupleSpace {
    const ts = std.heap.raw_c_allocator.create(TupleSpace) catch return null;
    ts.* = TupleSpace.init(std.heap.raw_c_allocator);
    return ts;
}

export fn tuplespace_destroy(ts: *TupleSpace) callconv(.C) void {
    ts.deinit();
    std.heap.raw_c_allocator.destroy(ts);
}

export fn tuplespace_put_int(ts: *TupleSpace, value: i64) callconv(.C) c_int {
    var elements = ts.allocator.alloc(tuple.Element, 1) catch return 1;
    elements[0] = .{ .tag = .Int, .data = .{ .Int = value } };
    const t = tuple.Tuple.init(ts.allocator, elements) catch {
        ts.allocator.free(elements);
        return 1;
    };
    ts.put(t) catch {
        t.deinit();
        ts.allocator.destroy(t);
        return 1;
    };
    return 0;
}

export fn tuplespace_get_int(ts: *TupleSpace, value: i64) callconv(.C) c_int {
    var elements = ts.allocator.alloc(tuple.Element, 1) catch return 1;
    defer ts.allocator.free(elements);
    elements[0] = .{ .tag = .Int, .data = .{ .Int = value } };
    const template = tuple.Tuple.init(ts.allocator, elements) catch return 1;
    defer {
        template.deinit();
        ts.allocator.destroy(template);
    }
    if (ts.read(template)) |_| {
        return 0; // Found
    }
    return 1; // Not found
}

export fn tuplespace_take_int(ts: *TupleSpace, value: i64, out_value: *i64) callconv(.C) c_int {
    var elements = ts.allocator.alloc(tuple.Element, 1) catch return 1;
    defer ts.allocator.free(elements);
    elements[0] = .{ .tag = .Int, .data = .{ .Int = value } };
    const template = tuple.Tuple.init(ts.allocator, elements) catch return 1;
    defer {
        template.deinit();
        ts.allocator.destroy(template);
    }
    if (ts.take(template)) |entry| {
        out_value.* = entry.tuple.elements[0].data.Int;
        return 0;
    }
    return 1; // Not found
}

export fn tuplespace_put_string(ts: *TupleSpace, ptr: [*c]const u8, len: usize) callconv(.C) c_int {
    if (ptr == null) return 1; // Fail if null
    std.debug.print("put_string: allocating elements\n", .{});
    var elements = ts.allocator.alloc(tuple.Element, 1) catch return 1;
    std.debug.print("put_string: duplicating string, len={}\n", .{len});
    const str = ts.allocator.dupe(u8, ptr[0..len]) catch {
        ts.allocator.free(elements);
        return 1;
    };
    elements[0] = .{ .tag = .String, .data = .{ .String = .{ .ptr = str, .len = len } } };
    std.debug.print("put_string: initializing tuple\n", .{});
    const t = tuple.Tuple.init(ts.allocator, elements) catch {
        ts.allocator.free(str);
        ts.allocator.free(elements);
        return 1;
    };
    std.debug.print("put_string: putting tuple\n", .{});
    ts.put(t) catch {
        t.deinit();
        ts.allocator.destroy(t);
        return 1;
    };
    std.debug.print("put_string: success\n", .{});
    return 0;
}

export fn tuplespace_take_string(ts: *TupleSpace, ptr: [*c]const u8, len: usize, out_ptr: *[*c]u8, out_len: *usize) callconv(.C) c_int {
    var elements = ts.allocator.alloc(tuple.Element, 1) catch return 1;
    defer ts.allocator.free(elements);
    const match_str = ts.allocator.dupe(u8, ptr[0..len]) catch return 1;
    defer ts.allocator.free(match_str);
    elements[0] = .{ .tag = .String, .data = .{ .String = .{ .ptr = match_str, .len = len } } };
    const template = tuple.Tuple.init(ts.allocator, elements) catch return 1;
    defer {
        template.deinit();
        ts.allocator.destroy(template);
    }
    if (ts.take(template)) |entry| {
        out_ptr.* = @constCast(entry.tuple.elements[0].data.String.ptr).ptr;
        out_len.* = entry.tuple.elements[0].data.String.len;
        return 0;
    }
    return 1;
}

export fn tuplespace_save(ts: *TupleSpace, path: [*c]const u8) callconv(.C) c_int {
    ts.saveToFile(std.mem.span(path)) catch return 1;
    return 0; // Success
}

pub const Allocator = tuple.Allocator;
pub const ElementTag = tuple.ElementTag;
pub const ElementData = tuple.ElementData;
pub const Element = tuple.Element;
pub const Tuple = tuple.Tuple;

pub const serializeTuple = tuple.Tuple.serializeTuple;
pub const deserializeTuple = tuple.Tuple.deserializeTuple;

pub const TupleSpaceError = error{
    // Memory-related errors
    OutOfMemory, // Allocation failures
    InvalidAllocation, // Unexpected allocator behavior

    // Serialization/Deserialization errors
    SerializationFailed, // Writing tuple space failed
    DeserializationFailed, // Reading tuple space failed
    InvalidDataFormat, // Corrupted or malformed data

    // Tuple operation errors
    TupleCreationFailed, // Failed to create a tuple
    TupleMatchFailed, // Unexpected mismatch (optional, if we want to enforce stricter matching)

    // Threading errors
    LockAcquisitionFailed, // Mutex lock failed
    ConditionWaitFailed, // Condition variable wait failed
    TimeoutExpired, // Explicit timeout error (e.g., takeWithTimeout)
    Timeout,

    // General errors

    FileNotFound,
    PermissionDenied,
    DiskFull,

    InvalidOperation, // Catch-all for unexpected states
};

pub const TupleSpaceEntry = struct {
    tuple: *Tuple,
    replication_count: u32,
    timestamp: i64,
    owner: ?[]u8,

    pub fn init(allocator: Allocator, t: *Tuple) anyerror!*TupleSpaceEntry { // Renamed 'tuple' to 't'
        const entry = try allocator.create(TupleSpaceEntry);
        entry.* = .{ .tuple = t, .replication_count = 1, .timestamp = std.time.milliTimestamp(), .owner = null };
        return entry;
    }

    pub fn deinit(self: *TupleSpaceEntry, allocator: Allocator) void {
        if (self.owner) |o| allocator.free(o);
        allocator.destroy(self);
    }
};

pub const TupleSpace = struct {
    entries: std.AutoHashMap(u64, std.ArrayList(*TupleSpaceEntry)),
    allocator: Allocator,
    mutex: std.Thread.Mutex,
    condition: std.Thread.Condition,

    pub fn init(allocator: Allocator) TupleSpace {
        return .{
            .entries = std.AutoHashMap(u64, std.ArrayList(*TupleSpaceEntry)).init(allocator),
            .allocator = allocator,
            .mutex = std.Thread.Mutex{},
            .condition = std.Thread.Condition{},
        };
    }

    pub fn deinit(self: *TupleSpace) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        var it = self.entries.valueIterator();
        while (it.next()) |list| {
            for (list.items) |entry| {
                entry.tuple.deinit();
                self.allocator.destroy(entry.tuple);
                entry.deinit(self.allocator);
            }
            list.deinit();
        }
        self.entries.deinit();
    }

    export fn tuplespace_read_string(ts: *TupleSpace, ptr: [*c]const u8, len: usize, out_ptr: *[*c]u8, out_len: *usize) callconv(.C) c_int {
        var elements = ts.allocator.alloc(tuple.Element, 1) catch return 1;
        defer ts.allocator.free(elements);
        const match_str = ts.allocator.dupe(u8, ptr[0..len]) catch return 1;
        defer ts.allocator.free(match_str);
        elements[0] = .{ .tag = .String, .data = .{ .String = .{ .ptr = match_str, .len = len } } };
        const template = tuple.Tuple.init(ts.allocator, elements) catch return 1;
        defer {
            template.deinit();
            ts.allocator.destroy(template);
        }
        if (ts.read(template)) |entry| {
            out_ptr.* = @constCast(entry.tuple.elements[0].data.String.ptr).ptr;
            out_len.* = entry.tuple.elements[0].data.String.len;
            return 0;
        }
        return 1;
    }

    // Adds a tuple to the tuple space, wrapping it in a TupleSpaceEntry.
    // Thread-safe: locks the mutex during insertion to prevent concurrent modifications.
    // - t: Pointer to the Tuple to add (ownership transferred to the TupleSpace).
    // Returns nothing, errors are propagated.
    pub fn put(self: *TupleSpace, t: *Tuple) !void {
        const entry = try TupleSpaceEntry.init(self.allocator, t);
        errdefer entry.deinit(self.allocator);

        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.entries.getPtr(t.id)) |list| {
            try list.append(entry);
        } else {
            var new_list = std.ArrayList(*TupleSpaceEntry).init(self.allocator);
            errdefer new_list.deinit();
            try new_list.append(entry);
            try self.entries.put(t.id, new_list);
        }

        self.condition.signal();
    }

    pub fn get(self: *TupleSpace, id: u64) ?*TupleSpaceEntry {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.entries.get(id)) |list| {
            return if (list.items.len > 0) list.items[0] else null;
        }
        return null;
    }

    // Removes and returns the first entry associated with the given tuple ID, if it exists.
    // Thread-safe: locks the mutex during removal to prevent concurrent modifications.
    // - id: The tuple ID to remove an entry for.
    // Returns the removed TupleSpaceEntry or null if no entry is found.
    pub fn remove(self: *TupleSpace, id: u64) ?*TupleSpaceEntry {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.entries.fetchRemove(id)) |kv| {
            var list = kv.value; // kv.value is the ArrayList(*TupleSpaceEntry)
            if (list.items.len > 0) {
                const entry = list.orderedRemove(0);
                if (list.items.len > 0) {
                    self.entries.put(id, list) catch unreachable;
                } else {
                    list.deinit();
                }
                return entry;
            } else {
                list.deinit();
            }
        }
        return null;
    }

    pub fn len(self: *TupleSpace) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        var total: usize = 0;
        var it = self.entries.valueIterator();
        while (it.next()) |list| {
            total += list.items.len;
        }
        return total;
    }

    pub fn read(self: *TupleSpace, template: *const Tuple) ?*TupleSpaceEntry {
        self.mutex.lock();
        defer self.mutex.unlock();
        var it = self.entries.valueIterator();
        while (it.next()) |list| {
            for (list.items) |entry| {
                if (tuplesMatch(template, entry.tuple)) return entry;
            }
        }
        return null;
    }

    pub fn take(self: *TupleSpace, template: *const Tuple) ?*TupleSpaceEntry {
        self.mutex.lock();
        defer self.mutex.unlock();

        var it = self.entries.iterator();
        while (it.next()) |kv| {
            const id = kv.key_ptr.*;
            if (self.entries.fetchRemove(id)) |removed_kv| {
                var list = removed_kv.value;
                for (list.items, 0..) |entry, i| {
                    if (tuplesMatch(template, entry.tuple)) {
                        const removed = list.orderedRemove(i);
                        if (list.items.len > 0) {
                            self.entries.put(id, list) catch unreachable;
                        } else {
                            list.deinit();
                        }
                        return removed;
                    }
                }
                // If no match, put the list back
                self.entries.put(id, list) catch unreachable;
            }
        }
        return null;
    }

    pub fn takeWithTimeout(self: *TupleSpace, template: *const Tuple, timeout_ms: u64) !?*TupleSpaceEntry {
        self.mutex.lock(); //catch return TupleSpaceError.LockAcquisitionFailed;
        defer self.mutex.unlock();

        const start_time = @as(u64, @bitCast(std.time.milliTimestamp()));
        while (true) {
            var found_entry: ?*TupleSpaceEntry = null;

            var it = self.entries.iterator();
            outer: while (it.next()) |kv| {
                const id = kv.key_ptr.*;
                if (self.entries.fetchRemove(id)) |removed_kv| {
                    var list = removed_kv.value;
                    for (list.items, 0..) |entry, i| {
                        if (tuplesMatch(template, entry.tuple)) {
                            found_entry = list.orderedRemove(i);
                            if (list.items.len > 0) {
                                self.entries.put(id, list) catch return TupleSpaceError.OutOfMemory;
                            } else {
                                list.deinit();
                            }
                            break :outer;
                        }
                    }
                    try self.entries.put(id, list);
                }
            }

            if (found_entry) |entry| return entry;

            const now = @as(u64, @bitCast(std.time.milliTimestamp()));
            const elapsed = now - start_time;
            // if (elapsed >= timeout_ms) return TupleSpaceError.TimeoutExpired;

            const remaining_ns = (timeout_ms - elapsed) * std.time.ns_per_ms;
            self.condition.timedWait(&self.mutex, remaining_ns) catch |err| switch (err) {
                error.Timeout => return null,
                else => return err, // Propagate other errors (e.g., system issues)
            };
        }
    }

    // Copies a TupleSpaceEntry, creating a deep copy of its tuple and associated data.
    // Thread-safe: locks the mutex during insertion of the new entry.
    // - entry: The TupleSpaceEntry to copy.
    // Returns a pointer to the new TupleSpaceEntry or an error if allocation fails.
    pub fn copy(self: *TupleSpace, entry: *TupleSpaceEntry) !*TupleSpaceEntry {
        const new_elements = try self.allocator.alloc(Element, entry.tuple.elements.len);
        errdefer self.allocator.free(new_elements);

        for (entry.tuple.elements, new_elements) |src_elem, *dst_elem| {
            dst_elem.tag = src_elem.tag;
            dst_elem.data = switch (src_elem.tag) {
                .Int => .{ .Int = src_elem.data.Int },
                .Float => .{ .Float = src_elem.data.Float },
                .String => blk: {
                    const new_ptr = try self.allocator.dupe(u8, src_elem.data.String.ptr);
                    break :blk .{ .String = .{ .ptr = new_ptr, .len = src_elem.data.String.len } };
                },
                .Tuple => .{ .Tuple = try copyTuple(self.allocator, src_elem.data.Tuple) },
                .FloatArray => blk: {
                    const new_ptr = try self.allocator.dupe(f64, src_elem.data.FloatArray.ptr[0..src_elem.data.FloatArray.len]);
                    break :blk .{ .FloatArray = .{ .ptr = new_ptr, .len = src_elem.data.FloatArray.len } };
                },
                .Wildcard => .{ .Wildcard = {} },
            };
        }

        const new_tuple = try Tuple.init(self.allocator, new_elements);
        errdefer {
            new_tuple.deinit();
            self.allocator.destroy(new_tuple);
        }

        const new_owner = if (entry.owner) |o| try self.allocator.dupe(u8, o) else null;
        errdefer if (new_owner) |o| self.allocator.free(o);

        const new_entry = try self.allocator.create(TupleSpaceEntry);
        new_entry.* = .{
            .tuple = new_tuple,
            .replication_count = entry.replication_count,
            .timestamp = std.time.milliTimestamp(),
            .owner = new_owner,
        };

        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.entries.getPtr(new_entry.tuple.id)) |list| {
            try list.append(new_entry);
        } else {
            var new_list = std.ArrayList(*TupleSpaceEntry).init(self.allocator);
            try new_list.append(new_entry);
            try self.entries.put(new_entry.tuple.id, new_list);
        }
        self.condition.signal();

        return new_entry;
    }

    pub fn takeAll(self: *TupleSpace, template: *const Tuple) !std.ArrayList(*TupleSpaceEntry) {
        var matches = std.ArrayList(*TupleSpaceEntry).init(self.allocator);
        errdefer {
            for (matches.items) |entry| entry.deinit(self.allocator);
            matches.deinit();
        }

        self.mutex.lock();
        defer self.mutex.unlock();

        var it = self.entries.iterator();
        var to_remove = std.ArrayList(u64).init(self.allocator);
        defer to_remove.deinit();

        while (it.next()) |kv| {
            const id = kv.key_ptr.*;
            const list = kv.value_ptr;
            var i: usize = 0;
            while (i < list.items.len) {
                if (tuplesMatch(template, list.items[i].tuple)) {
                    const entry = list.orderedRemove(i);
                    try matches.append(entry);
                } else {
                    i += 1;
                }
            }
            if (list.items.len == 0) {
                try to_remove.append(id);
            }
        }

        for (to_remove.items) |id| {
            if (self.entries.getPtr(id)) |list| {
                list.deinit();
            }
            _ = self.entries.remove(id);
        }

        return matches;
    }

    pub fn serializeTupleSpace(self: *TupleSpace, writer: anytype) anyerror!void {
        self.mutex.lock();
        defer self.mutex.unlock();

        var total_entries: u32 = 0;
        var it = self.entries.valueIterator();
        while (it.next()) |list| {
            total_entries += @intCast(list.items.len);
        }

        try writer.writeInt(u32, total_entries, .little);

        it = self.entries.valueIterator();
        while (it.next()) |list| {
            for (list.items) |entry| {
                try serializeTuple(entry.tuple, writer);
                try writer.writeInt(u32, entry.replication_count, .little);
                try writer.writeInt(i64, entry.timestamp, .little);
                if (entry.owner) |owner| {
                    try writer.writeByte(1);
                    try writer.writeInt(u32, @intCast(owner.len), .little);
                    try writer.writeAll(owner);
                } else {
                    try writer.writeByte(0);
                }
            }
        }
    }

    // Save tuple space to a file at the given path
    pub fn saveToFile(self: *TupleSpace, path: []const u8) !void {
        const file = try std.fs.cwd().createFile(path, .{});
        defer file.close();
        const writer = file.writer();
        try self.serializeTupleSpace(writer);
    }

    // Load tuple space from a file at the given path
    pub fn loadFromFile(allocator: Allocator, path: []const u8) !TupleSpace {
        const file = try std.fs.cwd().openFile(path, .{});
        defer file.close();
        const reader = file.reader();
        return try deserializeTupleSpace(allocator, reader);
    }
};

pub fn deserializeTupleSpace(allocator: Allocator, reader: anytype) !TupleSpace {
    var ts = TupleSpace.init(allocator);

    const entry_count = try reader.readInt(u32, .little); // Already unwrapped by try
    var i: u32 = 0;
    while (i < entry_count) : (i += 1) { // Now compares u32 to u32
        const t = try deserializeTuple(allocator, reader);
        errdefer {
            t.deinit();
            allocator.destroy(t);
        }
        const entry = try TupleSpaceEntry.init(allocator, t);
        errdefer entry.deinit(allocator);

        entry.replication_count = try reader.readInt(u32, .little);
        entry.timestamp = try reader.readInt(i64, .little);
        const has_owner = try reader.readByte();
        if (has_owner == 1) {
            const owner_len = try reader.readInt(u32, .little);
            const owner = try allocator.alloc(u8, owner_len);
            _ = try reader.read(owner);
            entry.owner = owner;
        } else {
            entry.owner = null;
        }

        ts.mutex.lock();
        defer ts.mutex.unlock();
        if (ts.entries.getPtr(entry.tuple.id)) |list| {
            try list.append(entry);
        } else {
            var new_list = std.ArrayList(*TupleSpaceEntry).init(allocator);
            try new_list.append(entry);
            try ts.entries.put(entry.tuple.id, new_list);
        }
    }
    return ts;
}

// Creates a deep copy of a Tuple, recursively copying nested tuples.
// - allocator: The allocator to use for the new tuple and its elements.
// - t: The Tuple to copy.
// Returns a pointer to the new Tuple or an error if allocation fails.
fn copyTuple(allocator: Allocator, t: *const Tuple) !*Tuple {
    const new_elements = try allocator.alloc(Element, t.elements.len);
    errdefer allocator.free(new_elements);

    for (t.elements, new_elements) |src_elem, *dst_elem| {
        dst_elem.tag = src_elem.tag;
        dst_elem.data = switch (src_elem.tag) {
            .Int => .{ .Int = src_elem.data.Int },
            .Float => .{ .Float = src_elem.data.Float },
            .String => blk: {
                const new_ptr = try allocator.dupe(u8, src_elem.data.String.ptr);
                break :blk .{ .String = .{ .ptr = new_ptr, .len = src_elem.data.String.len } };
            },
            .Tuple => .{ .Tuple = try copyTuple(allocator, src_elem.data.Tuple) },
            .FloatArray => blk: {
                const new_ptr = try allocator.dupe(f64, src_elem.data.FloatArray.ptr[0..src_elem.data.FloatArray.len]);
                break :blk .{ .FloatArray = .{ .ptr = new_ptr, .len = src_elem.data.FloatArray.len } };
            },
            .Wildcard => .{ .Wildcard = {} },
        };
    }
    return try Tuple.init(allocator, new_elements);
}

// Checks if a template tuple matches a target tuple. The template can be shorter than the target
// for partial matching, and wildcards in the template match any element in the target.
// For strings, "*" matches any string, and a shorter string matches as a prefix of the target string.
// - template: The tuple pattern to match against (may contain wildcards or prefix strings).
// - target: The tuple to check for a match.
// Returns true if the template matches the target up to the template's length, false otherwise.
pub fn tuplesMatch(template: *const Tuple, target: *const Tuple) bool {
    if (template.elements.len > target.elements.len) return false;

    for (template.elements, target.elements[0..template.elements.len]) |templ_elem, targ_elem| {
        if (templ_elem.tag == .Wildcard) continue;
        if (templ_elem.tag != targ_elem.tag) return false;

        switch (templ_elem.tag) {
            .Int => if (templ_elem.data.Int != targ_elem.data.Int) return false,
            .Float => if (templ_elem.data.Float != targ_elem.data.Float) return false,
            .String => {
                if (std.mem.eql(u8, templ_elem.data.String.ptr[0..templ_elem.data.String.len], "*")) continue; // "*" matches any string
                if (templ_elem.data.String.len > targ_elem.data.String.len) return false; // Template string can't be longer
                if (!std.mem.startsWith(u8, targ_elem.data.String.ptr[0..targ_elem.data.String.len], templ_elem.data.String.ptr[0..templ_elem.data.String.len])) return false; // Prefix match
            },
            .Tuple => if (!tuplesMatch(templ_elem.data.Tuple, targ_elem.data.Tuple)) return false,
            .FloatArray => if (!std.mem.eql(f64, templ_elem.data.FloatArray.ptr[0..templ_elem.data.FloatArray.len], targ_elem.data.FloatArray.ptr[0..targ_elem.data.FloatArray.len])) return false,
            .Wildcard => unreachable,
        }
    }
    return true;
}
