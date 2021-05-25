const std = @import("std");
const c = @cImport({
    @cInclude("gelf.h");
});

pub fn main() !void {
    const allocator = std.heap.page_allocator;

    const args = try std.process.argsAlloc(allocator);
    defer allocator.free(args);

    const file = try std.fs.openFileAbsolute(if (args.len > 1) args[1] else args[0], .{});
    defer file.close();

    std.log.info("elf version: {}", .{c.elf_version(c.EV_CURRENT)});
    const elf = c.elf_begin(file.handle, .ELF_C_READ, null);
    if (elf == null) {
        std.log.err("error from libelf: {s}", .{c.elf_errmsg(c.elf_errno())});
    }
}
