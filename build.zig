const std = @import("std");

pub fn build(b: *std.build.Builder) void {
    const mode = b.standardReleaseOptions();
    const target = b.standardTargetOptions(.{});

    const static = b.addStaticLibrary("elf", "src/main.zig");
    static.setBuildMode(mode);
    static.setTarget(target);
    static.addIncludeDir("include");
    static.linkLibC();
    static.install();

    const shared = b.addSharedLibrary("elf", "src/main.zig", .{
        .versioned = .{
            .major = 1,
            .minor = 6,
            .patch = 8,
        },
    });
    shared.setBuildMode(mode);
    shared.setTarget(target);
    shared.addIncludeDir("include");
    shared.linkLibC();
    shared.install();

    var main_tests = b.addTest("src/main.zig");
    main_tests.setBuildMode(mode);

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&main_tests.step);
}
