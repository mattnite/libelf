const std = @import("std");
const Builder = std.build.Builder;
const LibExeObjStep = std.build.LibExeObjStep;

fn baseDir() []const u8 {
    return comptime std.fs.path.dirname(@src().file) orelse unreachable;
}

pub fn includeDir() []const u8 {
    return baseDir() ++ std.fs.path.sep_str ++ "include";
}

pub fn addStaticLibrary(b: *Builder, target: std.build.Target, mode: std.builtin.Mode) *LibExeObjStep {
    const ret = b.addStaticLibrary("elf", baseDir() ++ std.fs.path.sep_str ++ "src" ++ std.fs.path.sep_str ++ "main.zig");
    ret.addIncludeDir(includeDir());
    ret.setTarget(target);
    ret.setBuildMode(mode);
    ret.bundle_compiler_rt = true;
    ret.pie = true;
    ret.linkLibC();

    return ret;
}
