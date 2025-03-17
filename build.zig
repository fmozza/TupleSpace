const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const tuple_space_module = b.addModule("tuple_space", .{
        .root_source_file = b.path("src/tuple_space.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Executable
    const exe = b.addExecutable(.{
        .name = "tuple_space",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    exe.root_module.addImport("tuple_space", tuple_space_module);
    exe.linkLibC(); // Fix libc dependency
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }
    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    // Tests
    const unit_tests = b.addTest(.{
        .root_source_file = b.path("tests/tuple_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    unit_tests.root_module.addImport("tuple_space", tuple_space_module);
    unit_tests.linkLibC(); // Add this to fix libc errors

    const run_unit_tests = b.addRunArtifact(unit_tests);
    run_unit_tests.step.dependOn(&unit_tests.step);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_unit_tests.step);

    // New shared library for Python
    const lib = b.addSharedLibrary(.{
        .name = "TupleSpace",
        .root_source_file = b.path("src/tuple_space.zig"),
        .target = target,
        .optimize = optimize,
    });
    lib.linkLibC();
    b.installArtifact(lib);
}
