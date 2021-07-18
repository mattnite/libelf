const std = @import("std");
const Builder = std.build.Builder;
const LibExeObjStep = std.build.LibExeObjStep;

fn baseDir() []const u8 {
    return comptime std.fs.path.dirname(@src().file) orelse unreachable;
}

pub fn includeDir() []const u8 {
    return baseDir() ++ std.fs.path.sep_str ++ "include";
}

fn applyOpts(lib: *LibExeObjStep, target: std.build.Target, mode: std.builtin.Mode, bundle: bool) void {
    lib.addIncludeDir(includeDir());
    lib.setTarget(target);
    lib.setBuildMode(mode);
    lib.bundle_compiler_rt = bundle;
    lib.pie = true;
    lib.linkLibC();
}

pub fn addObject(b: *Builder, target: std.build.Target, mode: std.builtin.Mode) *LibExeObjStep {
    const ret = b.addObject("elf", baseDir() ++ std.fs.path.sep_str ++ "src" ++ std.fs.path.sep_str ++ "main.zig");
    applyOpts(ret, target, mode, false);
    return ret;
}

pub fn addStaticLibrary(b: *Builder, target: std.build.Target, mode: std.builtin.Mode) *LibExeObjStep {
    const ret = b.addStaticLibrary("elf", baseDir() ++ std.fs.path.sep_str ++ "src" ++ std.fs.path.sep_str ++ "main.zig");
    applyOpts(ret, target, mode, true);
    return ret;
}
