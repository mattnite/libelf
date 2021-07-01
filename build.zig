const std = @import("std");

pub fn build(b: *std.build.Builder) void {
    const mode = b.standardReleaseOptions();
    const target = b.standardTargetOptions(.{});

    const static = b.addStaticLibrary("elf", "src/libelf.zig");
    static.setBuildMode(mode);
    static.setTarget(target);
    static.addIncludeDir("include");
    static.bundle_compiler_rt = true;
    static.linkLibC();
    static.install();

    const shared = b.addSharedLibrary("elf", "src/libelf.zig", .{
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

    var main_tests = b.addTest("src/libelf.zig");
    main_tests.setBuildMode(mode);
    main_tests.setTarget(target);
    main_tests.addIncludeDir("include");
    main_tests.bundle_compiler_rt = true;
    main_tests.linkLibC();
    main_tests.setBuildMode(mode);

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&main_tests.step);
}
