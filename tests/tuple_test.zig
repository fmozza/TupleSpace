const std = @import("std");
const tuple_space = @import("tuple_space");
const TupleSpaceError = tuple_space.TupleSpaceError;

test "create tuple space entry" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var elements = try allocator.alloc(tuple_space.Element, 1);
    elements[0] = .{ .tag = .Int, .data = .{ .Int = 42 } };
    const t = try tuple_space.Tuple.init(allocator, elements);
    defer {
        t.deinit();
        allocator.destroy(t);
    }

    const entry = try tuple_space.TupleSpaceEntry.init(allocator, t);
    defer entry.deinit(allocator);

    try std.testing.expect(entry.replication_count == 1);
}

test "tuple space operations" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var ts = tuple_space.TupleSpace.init(allocator);
    defer ts.deinit();

    var elements = try allocator.alloc(tuple_space.Element, 1);
    elements[0] = .{ .tag = .Int, .data = .{ .Int = 42 } };
    const t = try tuple_space.Tuple.init(allocator, elements);
    _ = try ts.put(t);

    try std.testing.expect(ts.len() == 1);
    const entry = ts.get(t.id).?;
    try std.testing.expect(entry.tuple.elements[0].data.Int == 42);

    const removed = ts.remove(t.id).?;
    try std.testing.expect(ts.len() == 0);
    removed.tuple.deinit();
    allocator.destroy(removed.tuple);
    removed.deinit(allocator);
}

test "tuple space read and take" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var ts = tuple_space.TupleSpace.init(allocator);
    defer ts.deinit();

    var elements = try allocator.alloc(tuple_space.Element, 1);
    elements[0] = .{ .tag = .Int, .data = .{ .Int = 42 } };
    const t = try tuple_space.Tuple.init(allocator, elements);
    try ts.put(t);

    var templ_elements = try allocator.alloc(tuple_space.Element, 1);
    templ_elements[0] = .{ .tag = .Int, .data = .{ .Int = 42 } };
    const template = try tuple_space.Tuple.init(allocator, templ_elements);
    defer {
        template.deinit();
        allocator.destroy(template);
    }

    const read_entry = ts.read(template).?;
    try std.testing.expect(read_entry.tuple.elements[0].data.Int == 42);
    try std.testing.expect(ts.len() == 1);

    const taken = ts.take(template).?;
    try std.testing.expect(taken.tuple.elements[0].data.Int == 42);
    try std.testing.expect(ts.len() == 0);
    taken.tuple.deinit();
    allocator.destroy(taken.tuple);
    taken.deinit(allocator);
}

test "tuple space take with timeout" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var ts = tuple_space.TupleSpace.init(allocator);
    defer ts.deinit();

    var templ_elements = try allocator.alloc(tuple_space.Element, 1);
    templ_elements[0] = .{ .tag = .Int, .data = .{ .Int = 42 } };
    const template = try tuple_space.Tuple.init(allocator, templ_elements);
    defer { // Line ~246, semicolon removed
        template.deinit();
        allocator.destroy(template);
    }

    const no_match = try ts.takeWithTimeout(template, 50);
    try std.testing.expect(no_match == null);

    var elements = try allocator.alloc(tuple_space.Element, 1);
    elements[0] = .{ .tag = .Int, .data = .{ .Int = 42 } };
    const t = try tuple_space.Tuple.init(allocator, elements);
    try ts.put(t);

    if (try ts.takeWithTimeout(template, 100)) |taken| {
        try std.testing.expect(taken.tuple.elements[0].data.Int == 42);
        try std.testing.expect(ts.len() == 0);
        taken.tuple.deinit();
        allocator.destroy(taken.tuple);
        taken.deinit(allocator);
    } else {
        try std.testing.expect(false); // Fail the test if no tuple is taken
    }
}

test "tuple space copy" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var ts = tuple_space.TupleSpace.init(allocator);
    defer ts.deinit();

    var elements = try allocator.alloc(tuple_space.Element, 1);
    elements[0] = .{ .tag = .Int, .data = .{ .Int = 42 } };
    const t = try tuple_space.Tuple.init(allocator, elements);
    try ts.put(t);

    const original = ts.get(t.id).?;
    const copied = try ts.copy(original);
    try std.testing.expect(copied.tuple.elements[0].data.Int == 42);
    try std.testing.expect(ts.len() == 2);
}

test "tuple space serialization" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var ts = tuple_space.TupleSpace.init(allocator);
    defer ts.deinit();

    var elements = try allocator.alloc(tuple_space.Element, 1);
    elements[0] = .{ .tag = .Int, .data = .{ .Int = 42 } };
    const t = try tuple_space.Tuple.init(allocator, elements);
    try ts.put(t);

    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();
    try ts.serializeTupleSpace(buffer.writer());

    var stream = std.io.fixedBufferStream(buffer.items[0..buffer.items.len]);
    var ts2 = try tuple_space.deserializeTupleSpace(allocator, stream.reader());
    defer ts2.deinit();

    const entry = ts2.get(t.id).?;
    try std.testing.expect(entry.tuple.elements[0].data.Int == 42);
}

test "enhanced tuples match" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var target_elements = try allocator.alloc(tuple_space.Element, 2);
    target_elements[0] = .{ .tag = .Int, .data = .{ .Int = 42 } };
    target_elements[1] = .{ .tag = .String, .data = .{ .String = .{ .ptr = try allocator.dupe(u8, "testing"), .len = 7 } } };
    const target = try tuple_space.Tuple.init(allocator, target_elements);
    defer {
        target.deinit();
        allocator.destroy(target);
    }

    // Test partial length matching
    var partial_elements = try allocator.alloc(tuple_space.Element, 1);
    partial_elements[0] = .{ .tag = .Int, .data = .{ .Int = 42 } };
    const partial_template = try tuple_space.Tuple.init(allocator, partial_elements);
    defer {
        partial_template.deinit();
        allocator.destroy(partial_template);
    }
    try std.testing.expect(tuple_space.tuplesMatch(partial_template, target));

    // Test string wildcard
    var wildcard_elements = try allocator.alloc(tuple_space.Element, 2);
    wildcard_elements[0] = .{ .tag = .Int, .data = .{ .Int = 42 } };
    wildcard_elements[1] = .{ .tag = .String, .data = .{ .String = .{ .ptr = try allocator.dupe(u8, "*"), .len = 1 } } };
    const wildcard_template = try tuple_space.Tuple.init(allocator, wildcard_elements);
    defer {
        wildcard_template.deinit();
        allocator.destroy(wildcard_template);
    }
    try std.testing.expect(tuple_space.tuplesMatch(wildcard_template, target));

    // Test string prefix
    var prefix_elements = try allocator.alloc(tuple_space.Element, 2);
    prefix_elements[0] = .{ .tag = .Int, .data = .{ .Int = 42 } };
    prefix_elements[1] = .{ .tag = .String, .data = .{ .String = .{ .ptr = try allocator.dupe(u8, "test"), .len = 4 } } };
    const prefix_template = try tuple_space.Tuple.init(allocator, prefix_elements);
    defer {
        prefix_template.deinit();
        allocator.destroy(prefix_template);
    }
    try std.testing.expect(tuple_space.tuplesMatch(prefix_template, target));
}

test "tuple space basic get" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var ts = tuple_space.TupleSpace.init(allocator);
    defer ts.deinit();

    var elements = try allocator.alloc(tuple_space.Element, 1);
    elements[0] = .{ .tag = .Int, .data = .{ .Int = 42 } };
    const t = try tuple_space.Tuple.init(allocator, elements);
    try ts.put(t);

    const entry = ts.get(t.id).?;
    try std.testing.expect(entry.tuple.elements[0].data.Int == 42);
}

test "tuple space take all" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var ts = tuple_space.TupleSpace.init(allocator);
    defer ts.deinit();

    var elements = try allocator.alloc(tuple_space.Element, 1);
    elements[0] = .{ .tag = .Int, .data = .{ .Int = 100 } };
    const t1 = try tuple_space.Tuple.init(allocator, elements);
    try ts.put(t1);

    var taken_all = try ts.takeAll(t1);
    defer {
        for (taken_all.items) |entry| {
            entry.tuple.deinit();
            allocator.destroy(entry.tuple);
            entry.deinit(allocator);
        }
        taken_all.deinit();
    }
    try std.testing.expect(taken_all.items.len == 1);
}

test "tuple space wildcard matching" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var ts = tuple_space.TupleSpace.init(allocator);
    defer ts.deinit();

    var elements = try allocator.alloc(tuple_space.Element, 1);
    elements[0] = .{ .tag = .String, .data = .{ .String = .{ .ptr = try allocator.dupe(u8, "hello"), .len = 5 } } };
    const t = try tuple_space.Tuple.init(allocator, elements);
    try ts.put(t);

    var wildcard_elements = try allocator.alloc(tuple_space.Element, 1);
    wildcard_elements[0] = .{ .tag = .Wildcard, .data = .{ .Wildcard = {} } };
    const wildcard_template = try tuple_space.Tuple.init(allocator, wildcard_elements);
    defer {
        wildcard_template.deinit();
        allocator.destroy(wildcard_template);
    }

    const read_entry = ts.read(wildcard_template).?;
    try std.testing.expect(std.mem.eql(u8, read_entry.tuple.elements[0].data.String.ptr[0..5], "hello"));
}

// Test: Save and load tuple space from file
test "tuple space persistence" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Create and populate a tuple space
    var ts = tuple_space.TupleSpace.init(allocator);
    defer ts.deinit();

    var elements = try allocator.alloc(tuple_space.Element, 2);
    elements[0] = .{ .tag = .Int, .data = .{ .Int = 42 } };
    elements[1] = .{ .tag = .String, .data = .{ .String = .{ .ptr = try allocator.dupe(u8, "test"), .len = 4 } } };
    const t = try tuple_space.Tuple.init(allocator, elements);
    try ts.put(t);

    // Save to file
    const file_path = "tuple_space_test.dat";
    try ts.saveToFile(file_path);

    // Load into a new tuple space
    var loaded_ts = try tuple_space.TupleSpace.loadFromFile(allocator, file_path);
    defer loaded_ts.deinit();

    // Clean up the test file
    std.fs.cwd().deleteFile(file_path) catch |err| {
        std.debug.print("Failed to delete test file: {}\n", .{err});
    };

    // Verify contents
    try std.testing.expect(loaded_ts.len() == 1);
    const loaded_entry = loaded_ts.get(t.id).?;
    try std.testing.expect(loaded_entry.tuple.elements.len == 2);
    try std.testing.expect(loaded_entry.tuple.elements[0].data.Int == 42);
    try std.testing.expect(std.mem.eql(u8, loaded_entry.tuple.elements[1].data.String.ptr[0..4], "test"));
}
