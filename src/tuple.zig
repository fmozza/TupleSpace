const std = @import("std");

// Global counter for unique IDs
var id_counter: u64 = 0;

/// Memory allocator type alias for consistency across the project.
pub const Allocator = std.mem.Allocator;

/// Tags representing the type of data an element can hold.
pub const ElementTag = enum {
    Int,
    Float,
    String,
    Tuple,
    FloatArray,
    Wildcard,
};

/// Union type for element data, corresponding to ElementTag variants.
pub const ElementData = union(ElementTag) {
    Int: i64,
    Float: f64,
    String: struct { ptr: []const u8, len: usize },
    Tuple: *Tuple,
    FloatArray: struct { ptr: []const f64, len: usize }, // Array of f64 values
    Wildcard: void,
};

/// Structure representing a single element in a tuple.
pub const Element = struct {
    tag: ElementTag,
    data: ElementData,
};

/// Structure representing a tuple, a collection of elements.
pub const Tuple = struct {
    id: u64, // Unique identifier for the tuple
    elements: []Element, // Slice of elements
    string_length: usize, // Total length of all string data in elements
    allocator: Allocator, // Allocator used for memory management

    // Creates a new Tuple with the given elements, allocating memory for the tuple struct.
    // Caller must call deinit() to free the tuple and its nested resources.
    // - allocator: Memory allocator to use for the tuple and its elements.
    // - elements: Slice of elements to initialize the tuple with (ownership transferred).
    // Returns a pointer to the new Tuple or an error if allocation fails.
    pub fn init(allocator: Allocator, elements: []Element) !*Tuple {
        const tuple = try allocator.create(Tuple);
        tuple.* = .{
            .id = generateTupleId(),
            .elements = elements,
            .string_length = calculateStringLength(elements),
            .allocator = allocator,
        };
        return tuple;
    }

    // Frees all resources owned by the tuple, including nested tuples and arrays.
    pub fn deinit(self: *Tuple) void {
        for (self.elements) |*elem| {
            switch (elem.tag) {
                .String => self.allocator.free(elem.data.String.ptr),
                .Tuple => {
                    elem.data.Tuple.deinit();
                    self.allocator.destroy(elem.data.Tuple);
                },
                .FloatArray => self.allocator.free(elem.data.FloatArray.ptr),
                else => {}, // Int, Float, Wildcard need no freeing
            }
        }
        self.allocator.free(self.elements);
    }

    // Serializes the tuple to a writer in a binary format.
    pub fn serializeTuple(self: *const Tuple, writer: anytype) !void {
        try writer.writeInt(u64, self.id, .little);
        try writer.writeInt(usize, self.elements.len, .little);
        for (self.elements) |elem| {
            try writer.writeInt(u8, @intFromEnum(elem.tag), .little);
            switch (elem.tag) {
                .Int => try writer.writeInt(i64, elem.data.Int, .little),
                .Float => try writer.writeInt(u64, @bitCast(elem.data.Float), .little),
                .String => {
                    try writer.writeInt(usize, elem.data.String.len, .little);
                    try writer.writeAll(elem.data.String.ptr);
                },
                .Tuple => try elem.data.Tuple.serializeTuple(writer),
                .FloatArray => {
                    try writer.writeInt(usize, elem.data.FloatArray.len, .little);
                    for (elem.data.FloatArray.ptr[0..elem.data.FloatArray.len]) |val| {
                        try writer.writeInt(u64, @bitCast(val), .little);
                    }
                },
                .Wildcard => {},
            }
        }
    }

    /// Deserializes a tuple from a reader, allocating memory as needed.
    // Deserializes a tuple from a reader, allocating memory as needed.
    // - allocator: The allocator to use for the tuple and its elements.
    // - reader: The source to read serialized data from.
    // Returns a pointer to the new Tuple or an error if deserialization fails.
    pub fn deserializeTuple(allocator: Allocator, reader: anytype) !*Tuple {
        const id = try reader.readInt(u64, .little);
        const elem_count = try reader.readInt(usize, .little);
        const elements = try allocator.alloc(Element, elem_count);
        errdefer allocator.free(elements);

        for (elements) |*elem| {
            const tag_int = try reader.readInt(u8, .little);
            const tag = @as(ElementTag, @enumFromInt(tag_int));
            elem.tag = tag;
            elem.data = switch (tag) {
                .Int => .{ .Int = try reader.readInt(i64, .little) },
                .Float => .{ .Float = @bitCast(try reader.readInt(u64, .little)) },
                .String => blk: {
                    const len = try reader.readInt(usize, .little);
                    const ptr = try allocator.alloc(u8, len);
                    errdefer allocator.free(ptr);
                    try reader.readNoEof(ptr);
                    break :blk .{ .String = .{ .ptr = ptr, .len = len } };
                },
                .Tuple => .{ .Tuple = try deserializeTuple(allocator, reader) },
                .FloatArray => blk: {
                    const len = try reader.readInt(usize, .little);
                    const ptr = try allocator.alloc(f64, len);
                    errdefer allocator.free(ptr);
                    for (ptr) |*val| {
                        val.* = @bitCast(try reader.readInt(u64, .little));
                    }
                    break :blk .{ .FloatArray = .{ .ptr = ptr, .len = len } };
                },
                .Wildcard => .{ .Wildcard = {} },
            };
        }

        const tuple = try allocator.create(Tuple);
        tuple.* = .{
            .id = id,
            .elements = elements,
            .string_length = calculateStringLength(elements),
            .allocator = allocator,
        };
        return tuple;
    }
};

/// Generates a unique tuple ID by combining timestamp and a counter.
fn generateTupleId() u64 {
    const timestamp = std.time.milliTimestamp(); // Returns i64
    id_counter += 1;
    // Convert i64 timestamp to u64 safely, then XOR with counter
    const timestamp_u64 = @as(u64, @bitCast(timestamp)); // Interpret bits as u64
    return timestamp_u64 ^ id_counter; // XOR ensures uniqueness
}

/// Calculates the total length of all string data in the elements.
fn calculateStringLength(elements: []const Element) usize {
    var total: usize = 0;
    for (elements) |elem| {
        if (elem.tag == .String) total += elem.data.String.len;
    }
    return total;
}
