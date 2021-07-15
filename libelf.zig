const std = @import("std");
const Builder = std.build.Builder;
const LibExeObjStep = std.build.LibExeObjStep;

var libelf: ?*LibExeObjStep = null;
var include_dir: ?[]const u8 = null;

fn baseDir() []const u8 {
    return comptime std.fs.path.dirname(@src().file) orelse unreachable;
}

pub fn includeDir() []const u8 {
    if (include_dir == null) {
        include_dir = baseDir() ++ std.fs.path.sep_str ++ "include";
    }

    return include_dir.?;
}

pub fn link(b: *Builder, obj: *LibExeObjStep, target: std.build.Target, mode: std.builtin.Mode) void {
    if (libelf == null) {
        libelf = b.addStaticLibrary("elf", baseDir() ++ std.fs.path.sep_str ++ "src" ++ std.fs.path.sep_str ++ "main.zig");
        libelf.?.addIncludeDir(includeDir());
        libelf.?.setTarget(target);
        libelf.?.setBuildMode(mode);
        libelf.?.bundle_compiler_rt = true;
        libelf.?.linkLibC();
    }

    obj.addIncludeDir(includeDir());
    obj.linkLibrary(libelf.?);
}
