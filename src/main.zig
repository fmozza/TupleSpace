const std = @import("std");
const tuple_space = @import("tuple_space.zig");

// Entry point: Demonstrates TupleSpace operations
pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var ts = tuple_space.TupleSpace.init(allocator);
    defer ts.deinit();

    // Example 1: Copy a tuple with mixed elements
    var original_elements = try allocator.alloc(tuple_space.Element, 3);
    original_elements[0] = .{ .tag = .Int, .data = .{ .Int = 42 } };
    original_elements[1] = .{ .tag = .Float, .data = .{ .Float = 3.14 } };
    original_elements[2] = .{ .tag = .String, .data = .{ .String = .{ .ptr = try allocator.dupe(u8, "hello"), .len = 5 } } };
    const original_tuple = try tuple_space.Tuple.init(allocator, original_elements);
    try ts.put(original_tuple);
    const copied = try ts.copy(ts.get(original_tuple.id).?);
    std.debug.print("Copied tuple ID: {}, Elements: {}\n", .{ copied.tuple.id, copied.tuple.elements.len });
    std.debug.print("Original tuple ID: {}, Elements: {}\n", .{ original_tuple.id, original_tuple.elements.len });

    // Example 2: Take a tuple with timeout
    {
        var timeout_elements = try allocator.alloc(tuple_space.Element, 1);
        timeout_elements[0] = .{ .tag = .Int, .data = .{ .Int = 42 } };
        const timeout_template = try tuple_space.Tuple.init(allocator, timeout_elements);
        defer {
            timeout_template.deinit();
            allocator.destroy(timeout_template);
        }

        var extra_elements = try allocator.alloc(tuple_space.Element, 1);
        extra_elements[0] = .{ .tag = .Int, .data = .{ .Int = 42 } };
        const extra_tuple = try tuple_space.Tuple.init(allocator, extra_elements);
        try ts.put(extra_tuple);
        if (try ts.takeWithTimeout(timeout_template, 100)) |taken| {
            std.debug.print("Taken with timeout: Int = {}\n", .{taken.tuple.elements[0].data.Int});
            taken.tuple.deinit();
            allocator.destroy(taken.tuple);
            taken.deinit(allocator);
        } else {
            std.debug.print("No tuple taken within 100ms\n", .{});
        }
    }

    // Example 3: Take all matching tuples
    var take_all_elements = try allocator.alloc(tuple_space.Element, 1);
    take_all_elements[0] = .{ .tag = .Int, .data = .{ .Int = 100 } };
    const take_all_template = try tuple_space.Tuple.init(allocator, take_all_elements);
    defer {
        take_all_template.deinit();
        allocator.destroy(take_all_template);
    }
    const int100_1 = try tuple_space.Tuple.init(allocator, try allocator.dupe(tuple_space.Element, &.{.{ .tag = .Int, .data = .{ .Int = 100 } }}));
    const int100_2 = try tuple_space.Tuple.init(allocator, try allocator.dupe(tuple_space.Element, &.{.{ .tag = .Int, .data = .{ .Int = 100 } }}));
    try ts.put(int100_1);
    try ts.put(int100_2);
    var taken_all = try ts.takeAll(take_all_template);
    defer {
        for (taken_all.items) |entry| {
            entry.tuple.deinit();
            allocator.destroy(entry.tuple);
            entry.deinit(allocator);
        }
        taken_all.deinit();
    }
    std.debug.print("Taken all: {} tuples with Int = {}\n", .{ taken_all.items.len, taken_all.items[0].tuple.elements[0].data.Int });

    // Example 4: Read with wildcard matching
    var wildcard_elements = try allocator.alloc(tuple_space.Element, 1);
    wildcard_elements[0] = .{ .tag = .Wildcard, .data = .{ .Wildcard = {} } };
    const wildcard_template = try tuple_space.Tuple.init(allocator, wildcard_elements);
    defer {
        wildcard_template.deinit();
        allocator.destroy(wildcard_template);
    }
    var wildcard_tuple_elements = try allocator.alloc(tuple_space.Element, 1);
    wildcard_tuple_elements[0] = .{ .tag = .String, .data = .{ .String = .{ .ptr = try allocator.dupe(u8, "hello"), .len = 5 } } };
    const wildcard_tuple = try tuple_space.Tuple.init(allocator, wildcard_tuple_elements);
    try ts.put(wildcard_tuple);
    if (ts.read(wildcard_template)) |taken| {
        switch (taken.tuple.elements[0].tag) {
            .Int => std.debug.print("Wildcard match found: Int = {}\n", .{taken.tuple.elements[0].data.Int}),
            .String => std.debug.print("Wildcard match found: String = {s}\n", .{taken.tuple.elements[0].data.String.ptr}),
            else => std.debug.print("Wildcard match found: Unexpected type\n", .{}),
        }
    } else {
        std.debug.print("No wildcard match found\n", .{});
    }
}
