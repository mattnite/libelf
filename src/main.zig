const std = @import("std");
const builtin = @import("builtin");
const c = @cImport({
    @cInclude("gelf.h");
    @cInclude("nlist.h");
});

const Allocator = std.mem.Allocator;

threadlocal var global_error: c_int = 0;
var global_version: c_uint = c.EV_NONE;

pub const Error = error{
    Unknown,
    UnknownVersion,
    UnknownType,
    InvalidHandle,
    SourceSize,
    DestSize,
    InvalidEncoding,
    OutOfMemory,
    InvalidFile,
    InvalidElf,
    InvalidOp,
    NoVersion,
    InvalidCmd,
    Range,
    ArchiveFmag,
    InvalidArchive,
    NoArchive,
    NoIndex,
    ReadError,
    WriteError,
    InvalidClass,
    InvalidIndex,
    InvalidOperand,
    InvalidSection,
    InvalidCommand,
    WrongOrderEhdr,
    FdDisabled,
    FdMismatch,
    OffsetRange,
    NotNulSection,
    DataMismatch,
    InvalidSectionHeader,
    InvalidData,
    DataEncoding,
    SectionTooSmall,
    InvalidAlign,
    InvalidShentsize,
    UpdateRo,
    Nofile,
    GroupNotRel,
    InvalidPhdr,
    NoPhdr,
    InvalidOffset,
    InvalidSectionType,
    InvalidSectionFlags,
    NotCompressed,
    AlreadyCompressed,
    UnknownCompressionType,
    CompressError,
    DecompressError,

    // remove later
    Todo,
};

fn seterrno(err: Error) void {
    global_error = @errorToInt(err);
}

var gpa = std.heap.GeneralPurposeAllocator(.{}){};
const allocator = &gpa.allocator;

const Scn = struct {
    elf: *Elf,
    state: State,
    data: std.ArrayList(c.Elf_Data),
    index: usize,

    const State = union(enum) {
        elf32: struct {
            shdr: *c.Elf32_Shdr,
        },
        elf64: struct {
            shdr: *c.Elf64_Shdr,
        },
    };

    fn init(elf: *Elf, state: State, index: usize) !Scn {
        std.log.debug("scn: {}", .{state});
        return Scn{
            .elf = elf,
            .state = state,
            .index = index,
            .data = std.ArrayList(c.Elf_Data).init(allocator),
        };
    }

    fn deinit(self: *Scn) void {
        self.data.deinit();
    }

    fn cast(scn: *c.Elf_Scn) *Scn {
        return @ptrCast(*Scn, @alignCast(@alignOf(*Scn), scn));
    }
};

const Memory = union(enum) {
    referenced: []u8,
    owned: []u8,

    fn get(self: Memory) []u8 {
        return switch (self) {
            .owned => |mem| mem,
            .referenced => |mem| mem,
        };
    }
};

const Elf = struct {
    kind: c.Elf_Kind,
    state: union(enum) {
        elf32: struct {
            ehdr: *c.Elf32_Ehdr,
            section_headers: []c.Elf32_Shdr,
        },
        elf64: struct {
            ehdr: *c.Elf64_Ehdr,
            section_headers: []c.Elf64_Shdr,
        },

        const Self = @This();

        fn shstrndx(self: Self) usize {
            return switch (self) {
                .elf32 => |elf| elf.ehdr.e_shstrndx,
                .elf64 => |elf| elf.ehdr.e_shstrndx,
            };
        }

        fn shnum(self: Self) usize {
            return switch (self) {
                .elf32 => |elf| elf.ehdr.e_shnum,
                .elf64 => |elf| elf.ehdr.e_shnum,
            };
        }
    },
    memory: Memory,
    sections: std.ArrayList(Scn),

    fn cast(elf: *c.Elf) *Elf {
        return @ptrCast(*Elf, @alignCast(@alignOf(*Elf), elf));
    }

    fn is_64(elf: *Elf) bool {
        return elf.state.elf64.ehdr.e_ident[c.EI_CLASS] == c.ELFCLASS64;
    }

    fn is_32(elf: *Elf) bool {
        return elf.state.elf64.ehdr.e_ident[c.EI_CLASS] == c.ELFCLASS32;
    }

    fn validEndianness(elf: *Elf) !bool {
        return switch (elf.state.elf64.ehdr.e_ident[c.EI_DATA]) {
            c.ELFDATA2LSB => builtin.target.cpu.arch.endian() == .Little,
            c.ELFDATA2MSB => builtin.target.cpu.arch.endian() == .Big,
            else => error.InvalidData,
        };
    }

    fn begin(fd: c_int, cmd: c.Elf_Cmd, ref: ?*Elf) Error!?*Elf {
        if (global_version != c.EV_CURRENT)
            return error.NoVersion;

        if (ref) |r| {
            // TODO: r.rwlock();
        } else {
            _ = std.os.fcntl(fd, std.c.F_GETFD, 0) catch {
                return error.InvalidFile;
            };
        }
        // TODO: defer if (ref) |r| r.unlock();

        return switch (cmd) {
            .ELF_C_NULL => null,
            .ELF_C_READ, .ELF_C_READ_MMAP => blk: {
                const file = std.fs.File{ .handle = fd };
                break :blk fromMemory(.{
                    .owned = file.reader().readAllAlloc(allocator, std.math.maxInt(usize)) catch |e| {
                        return error.InvalidFile;
                    },
                });
            },
            .ELF_C_WRITE => error.Todo,
            else => error.Todo,
        };
    }

    fn end(self: *Elf) void {
        for (self.sections.items) |*scn| scn.deinit();
        self.sections.deinit();

        switch (self.memory) {
            .owned => |mem| allocator.free(mem),
            .referenced => {},
        }

        allocator.destroy(self);
    }

    fn fromMemory(memory: Memory) Error!*Elf {
        const ehdr = @ptrCast(*c.GElf_Ehdr, @alignCast(@alignOf(*c.GElf_Ehdr), memory.get().ptr));
        std.log.debug("ehdr: {}", .{ehdr});

        const shdr = @ptrCast(*c.GElf_Shdr, @alignCast(@alignOf(*c.GElf_Shdr), memory.get()[ehdr.e_shoff..].ptr));
        var ret = try allocator.create(Elf);
        ret.* = Elf{
            .kind = .ELF_K_ELF,
            .state = switch (ehdr.e_ident[c.EI_CLASS]) {
                c.ELFCLASS32 => .{
                    .elf32 = .{
                        .ehdr = @ptrCast(*c.Elf32_Ehdr, ehdr),
                        .section_headers = blk: {
                            var slice: []c.Elf32_Shdr = undefined;
                            slice.ptr = @ptrCast([*]c.Elf32_Shdr, shdr);
                            slice.len = ehdr.e_shnum;
                            break :blk slice;
                        },
                    },
                },
                c.ELFCLASS64 => .{
                    .elf64 = .{
                        .ehdr = @ptrCast(*c.Elf64_Ehdr, ehdr),
                        .section_headers = blk: {
                            var slice: []c.Elf64_Shdr = undefined;
                            slice.ptr = @ptrCast([*]c.Elf64_Shdr, shdr);
                            slice.len = ehdr.e_shnum;
                            break :blk slice;
                        },
                    },
                },
                else => return error.InvalidElf,
            },
            .memory = memory,
            .sections = std.ArrayList(Scn).init(allocator),
        };

        // parse sections
        if (ret.is_64()) {
            for (ret.state.elf64.section_headers) |*header, index|
                try ret.sections.append(try Scn.init(ret, .{ .elf64 = .{ .shdr = header } }, index));
        } else {
            for (ret.state.elf32.section_headers) |*header, index|
                try ret.sections.append(try Scn.init(ret, .{ .elf32 = .{ .shdr = header } }, index));
        }

        return ret;
    }

    fn getehdr(self: *Elf, comptime T: type) *T {
        return @ptrCast(*T, @alignCast(@alignOf(*T), self.memory.get().ptr));
    }
};

export fn elf32_checksum(elf: ?*c.Elf) c_long {
    return -1;
}

export fn elf32_fsize(elf_type: c.Elf_Type, count: usize, version: c_uint) usize {
    return 0;
}

export fn elf32_getehdr(elf: ?*c.Elf) ?*c.Elf32_Ehdr {
    const e = Elf.cast(elf orelse return null);

    if (e.kind != .ELF_K_ELF) {
        seterrno(error.InvalidHandle);
        return null;
    } else if (e.is_64() or !(e.validEndianness() catch |err| {
        seterrno(err);
        return null;
    })) {
        seterrno(error.InvalidClass);
        return null;
    }

    return Elf.cast(elf orelse return null).getehdr(c.Elf32_Ehdr);
}

export fn elf32_getphdr(elf: ?*c.Elf) ?*c.Elf32_Phdr {
    return null;
}

export fn elf32_getshdr(scn: ?*c.Elf_Scn) ?*c.Elf32_Shdr {
    return if (scn) |s| Scn.cast(s).state.elf32.shdr else null;
}

export fn elf32_newehdr(elf: ?*c.Elf) ?*c.Elf32_Ehdr {
    return null;
}

export fn elf32_newphdr(elf: ?*c.Elf, cnt: usize) ?*c.Elf32_Phdr {
    return null;
}

export fn elf32_xlatetof(dest: ?*c.Elf_Data, src: ?*const c.Elf_Data, encode: c_uint) ?*c.Elf_Data {
    return null;
}

export fn elf32_xlatetom(dest: ?*c.Elf_Data, src: ?*const c.Elf_Data, encode: c_uint) ?*c.Elf_Data {
    return null;
}

export fn elf64_checksum(elf: ?*c.Elf) c_long {
    return -1;
}

export fn elf64_fsize(elf_type: c.Elf_Type, count: usize, version: c_uint) usize {
    return 0;
}

export fn elf64_getehdr(elf: ?*c.Elf) ?*c.Elf64_Ehdr {
    const e = Elf.cast(elf orelse return null);

    if (e.kind != .ELF_K_ELF) {
        seterrno(error.InvalidHandle);
        return null;
    } else if (!e.is_64() or !(e.validEndianness() catch |err| {
        seterrno(err);
        return null;
    })) {
        seterrno(error.InvalidClass);
        return null;
    }

    return Elf.cast(elf orelse return null).getehdr(c.Elf64_Ehdr);
}

export fn elf64_getphdr(elf: ?*c.Elf) ?*c.Elf64_Phdr {
    return null;
}

export fn elf64_getshdr(scn: ?*c.Elf_Scn) ?*c.Elf64_Shdr {
    return if (scn) |s| Scn.cast(s).state.elf64.shdr else null;
}

// libbpf
export fn elf64_newehdr(elf: ?*c.Elf) ?*c.Elf64_Ehdr {
    return null;
}

export fn elf64_newphdr(elf: ?*c.Elf, cnt: usize) ?*c.Elf64_Phdr {
    return null;
}

export fn elf64_xlatetof(dest: ?*c.Elf_Data, src: ?*const c.Elf_Data, encode: c_uint) ?*c.Elf_Data {
    return null;
}

export fn elf64_xlatetom(dest: ?*c.Elf_Data, src: ?*const c.Elf_Data, encode: c_uint) ?*c.Elf_Data {
    return null;
}

export fn elf_begin(fd: c_int, cmd: c.Elf_Cmd, ref: ?*c.Elf) ?*c.Elf {
    return @ptrCast(*c.Elf, Elf.begin(fd, cmd, if (ref) |r| Elf.cast(r) else null) catch |e| {
        seterrno(e);
        return null;
    });
}

export fn elf_clone(elf: ?*c.Elf, cmd: c.Elf_Cmd) ?*c.Elf {
    return null;
}

export fn elf_cntl(elf: ?*c.Elf, cmd: c.Elf_Cmd) c_int {
    return -1;
}

export fn elf_end(elf: ?*c.Elf) c_int {
    return if (elf) |e| blk: {
        @ptrCast(*Elf, Elf.cast(e)).end();
        break :blk 0;
    } else 0;
}

export fn elf_errmsg(err: c_int) ?[*:0]const u8 {
    return if (err == 0)
        "no error"
    else if (err > std.math.maxInt(u16))
        "unknown error"
    else switch (@intToError(@intCast(u16, err))) {
        error.Unknown => "unknown error",
        error.UnknownVersion => "unknown version",
        error.UnknownType => "unknown type",
        error.InvalidHandle => "invalid `Elf' handle",
        error.SourceSize => "invalid size of source operand",
        error.DestSize => "invalid size of destination operand",
        error.InvalidEncoding => "invalid encoding",
        error.OutOfMemory => "out of memory",
        error.InvalidFile => "invalid file descriptor",
        error.InvalidElf => "invalid ELF file data",
        error.InvalidOp => "invalid operation",
        error.NoVersion => "ELF version not set",
        error.InvalidCmd => "invalid command",
        error.Range => "offset out of range",
        error.ArchiveFmag => "invalid fmag field in archive header",
        error.InvalidArchive => "invalid archive file",
        error.NoArchive => "descriptor is not for an archive",
        error.NoIndex => "no index available",
        error.ReadError => "cannot read data from file",
        error.WriteError => "cannot write data to file",
        error.InvalidClass => "invalid binary class",
        error.InvalidIndex => "invalid section index",
        error.InvalidOperand => "invalid operand",
        error.InvalidSection => "invalid section",
        error.InvalidCommand => "invalid command",
        error.WrongOrderEhdr => "executable header not created first",
        error.FdDisabled => "file descriptor disabled",
        error.FdMismatch => "archive/member file descriptor mismatch",
        error.OffsetRange => "offset out of range",
        error.NotNulSection => "cannot manipulate null section",
        error.DataMismatch => "data/scn mismatch",
        error.InvalidSectionHeader => "invalid section header",
        error.InvalidData => "invalid data",
        error.DataEncoding => "unknown data encoding",
        error.SectionTooSmall => "section `sh_size' too small for data",
        error.InvalidAlign => "invalid section alignment",
        error.InvalidShentsize => "invalid section entry size",
        error.UpdateRo => "update() for write on read-only file",
        error.Nofile => "no such file",
        error.GroupNotRel => "only relocatable files can contain section groups",
        error.InvalidPhdr => "program header only allowed in executables, shared objects, and core files",
        error.NoPhdr => "file has no program header",
        error.InvalidOffset => "invalid offset",
        error.InvalidSectionType => "invalid section type",
        error.InvalidSectionFlags => "invalid section flags",
        error.NotCompressed => "section does not contain compressed data",
        error.AlreadyCompressed => "section contains compressed data",
        error.UnknownCompressionType => "unknown compression type",
        error.CompressError => "cannot compress data",
        error.DecompressError => "cannot decompress data",
        error.Todo => "got a todo error, this is for development only",
        else => "unknown error",
    };
}

export fn elf_errno() c_int {
    return -1;
}

export fn elf_fill(fill: c_int) void {}

export fn elf_flagdata(data: ?*c.Elf_Data, cmd: c.Elf_Cmd, flags: c_uint) c_uint {
    return 0;
}

export fn elf_flagehdr(elf: ?*c.Elf, cmd: c.Elf_Cmd, flags: c_uint) c_uint {
    return 0;
}

export fn elf_flagelf(elf: ?*c.Elf, cmd: c.Elf_Cmd, flags: c_uint) c_uint {
    return 0;
}

export fn elf_flagphdr(elf: ?*c.Elf, cmd: c.Elf_Cmd, flags: c_uint) c_uint {
    return 0;
}

export fn elf_flagscn(scn: ?*c.Elf_Scn, cmd: c.Elf_Cmd, flags: c_uint) c_uint {
    return 0;
}

export fn elf_flagshdr(scn: ?*c.Elf_Scn, cmd: c.Elf_Cmd, flags: c_uint) c_uint {
    return 0;
}

export fn elf_getarhdr(elf: ?*c.Elf) ?*c.Elf_Arhdr {
    return null;
}

export fn elf_getarsym(elf: ?*c.Elf, narsyms: *usize) ?*c.Elf_Arhdr {
    return null;
}

export fn elf_getbase(elf: ?*c.Elf) i64 {
    return -1;
}

// libbpf
export fn elf_getdata(scn: ?*c.Elf_Scn, data: ?*c.Elf_Data) ?*c.Elf_Data {
    return null;
}

export fn elf_getident(elf: ?*c.Elf, nbytes: ?*usize) ?[*]u8 {
    return null;
}

export fn elf_getscn(elf: ?*c.Elf, index: usize) ?*c.Elf_Scn {
    const e = Elf.cast(elf orelse return null);
    return if (index < e.sections.items.len)
        @ptrCast(*c.Elf_Scn, &e.sections.items[index])
    else
        null;
}

/// deprecated
export fn elf_getshnum(elf: ?*c.Elf, dst: ?*usize) c_int {
    return -1;
}

/// deprecated
export fn elf_getshstrndx(elf: ?*c.Elf, dst: ?*usize) c_int {
    return -1;
}

export fn elf_hash(string: [*:0]const u8) c_ulong {
    return 0;
}

export fn elf_kind(elf: ?*c.Elf) c.Elf_Kind {
    return Elf.cast(elf orelse return .ELF_K_NONE).kind;
}

export fn elf_memory(image: ?[*]u8, size: usize) ?*c.Elf {
    const slice = if (image) |img| blk: {
        var s: []u8 = undefined;
        s.ptr = img;
        s.len = size;
        break :blk s;
    } else {
        seterrno(error.InvalidOperand);
        return null;
    };

    return @ptrCast(*c.Elf, Elf.fromMemory(.{ .referenced = slice }) catch |e| {
        seterrno(e);
        return null;
    });
}

export fn elf_ndxscn(scn: ?*c.Elf_Scn) usize {
    return Scn.cast(scn orelse return c.SHN_UNDEF).index;
}

// libbpf
export fn elf_newdata(scn: ?*c.Elf_Scn) ?*c.Elf_Data {
    return null;
}

// TODO
export fn elf_newscn(elf: ?*c.Elf) ?*c.Elf_Scn {
    return null;
}

export fn elf_next(elf: ?*c.Elf) c.Elf_Cmd {
    return .ELF_C_NULL;
}

export fn elf_nextscn(elf: ?*c.Elf, scn: ?*c.Elf_Scn) ?*c.Elf_Scn {
    const e = Elf.cast(elf orelse return null);
    const s = Scn.cast(scn orelse return null);
    return if (s.index + 1 < e.sections.items.len)
        @ptrCast(*c.Elf_Scn, &e.sections.items[s.index + 1])
    else
        null;
}

export fn elf_rand(elf: ?*c.Elf, offset: usize) usize {
    return 0;
}

// libbpf
export fn elf_rawdata(scn: ?*c.Elf_Scn, data: ?*c.Elf_Data) ?*c.Elf_Data {
    return null;
}

export fn elf_rawfile(elf: ?*c.Elf, nbytes: *usize) ?[*]u8 {
    return null;
}

// libbpf
export fn elf_strptr(elf: ?*c.Elf, index: usize, offset: usize) ?[*:0]const u8 {
    return null;
}

// libbpf
export fn elf_update(elf: ?*c.Elf, cmd: c.Elf_Cmd) i64 {
    return -1;
}

export fn elf_version(version: c_uint) c_uint {
    return if (version == @as(c_uint, c.EV_NONE))
        c.EV_CURRENT
    else if (version == @as(c_uint, c.EV_CURRENT)) blk: {
        global_version = @as(c_uint, c.EV_CURRENT);
        break :blk @as(c_uint, c.EV_CURRENT);
    } else blk: {
        seterrno(error.UnknownVersion);
        break :blk @as(c_uint, c.EV_NONE);
    };
}

export fn gelf_checksum(elf: ?*c.Elf) c_long {
    return -1;
}

export fn gelf_fsize(elf: ?*c.Elf, elf_type: c.Elf_Type, count: usize, version: c_uint) usize {
    return 0;
}

// libbpf
export fn gelf_getclass(elf: ?*c.Elf) c_int {
    return 0;
}

export fn gelf_getdyn(data: ?*c.Elf_Data, ndx: c_int, dst: ?*c.GElf_Dyn) ?*c.GElf_Dyn {
    return null;
}

export fn gelf_getehdr(elf: ?*c.Elf, dst: ?*c.GElf_Ehdr) ?*c.GElf_Ehdr {
    if (elf == null or dst == null)
        return null;

    const e = Elf.cast(elf.?);
    if (e.kind != .ELF_K_ELF) {
        seterrno(error.InvalidHandle);
        return null;
    }

    // TODO: check for uncreated ehdr

    if (e.is_32()) {
        const ehdr = e.getehdr(c.Elf32_Ehdr);
        dst.?.e_type = ehdr.e_type;
        dst.?.e_machine = ehdr.e_machine;
        dst.?.e_version = ehdr.e_version;
        dst.?.e_entry = ehdr.e_entry;
        dst.?.e_phoff = ehdr.e_phoff;
        dst.?.e_shoff = ehdr.e_shoff;
        dst.?.e_flags = ehdr.e_flags;
        dst.?.e_ehsize = ehdr.e_ehsize;
        dst.?.e_phentsize = ehdr.e_phentsize;
        dst.?.e_phnum = ehdr.e_phnum;
        dst.?.e_shentsize = ehdr.e_shentsize;
        dst.?.e_shnum = ehdr.e_shnum;
        dst.?.e_shstrndx = ehdr.e_shstrndx;
    } else {
        dst.?.* = e.getehdr(c.GElf_Ehdr).*;
    }

    return dst.?;
}

export fn gelf_getmove(data: ?*c.Elf_Data, ndx: c_int, dst: ?*c.GElf_Move) ?*c.GElf_Move {
    return null;
}

export fn gelf_getphdr(elf: ?*c.Elf, ndr: c_int, dst: ?*c.GElf_Phdr) ?*c.GElf_Phdr {
    return null;
}

// libbpf
export fn gelf_getrel(data: ?*c.Elf_Data, ndx: c_int, dst: ?*c.GElf_Rel) ?*c.GElf_Rel {
    return null;
}

export fn gelf_getrela(data: ?*c.Elf_Data, ndx: c_int, dst: ?*c.GElf_Rela) ?*c.GElf_Rela {
    return null;
}

export fn gelf_getshdr(scn: ?*c.Elf_Scn, dst: ?*c.GElf_Shdr) ?*c.GElf_Shdr {
    if (scn == null or dst == null)
        return null;

    const s = Scn.cast(scn.?);
    switch (s.state) {
        .elf32 => |elf| {
            const shdr = elf.shdr;
            dst.?.sh_type = shdr.sh_type;
            dst.?.sh_flags = shdr.sh_flags;
            dst.?.sh_addr = shdr.sh_addr;
            dst.?.sh_offset = shdr.sh_offset;
            dst.?.sh_size = shdr.sh_size;
            dst.?.sh_link = shdr.sh_link;
            dst.?.sh_info = shdr.sh_info;
            dst.?.sh_addralign = shdr.sh_addralign;
            dst.?.sh_entsize = shdr.sh_entsize;
        },
        .elf64 => |elf| {
            dst.?.* = elf.shdr.*;
        },
    }

    return dst.?;
}

// libbpf
export fn gelf_getsym(data: ?*c.Elf_Data, ndx: c_int, dst: ?*c.GElf_Sym) ?*c.GElf_Sym {
    return null;
}

export fn gelf_getsyminfo(data: ?*c.Elf_Data, ndx: c_int, dst: ?*c.GElf_Syminfo) ?*c.GElf_Syminfo {
    return null;
}

export fn gelf_getsymshndx(symdata: ?*c.Elf_Data, shndxdata: ?*c.Elf_Data, ndx: c_int, sym: ?*c.GElf_Sym, xshndx: ?*c.Elf32_Word) ?*c.GElf_Sym {
    return null;
}

export fn gelf_getverdaux(data: ?*c.Elf_Data, offset: c_int, dst: ?*c.GElf_Verdef) ?*c.GElf_Verdef {
    return null;
}

export fn gelf_getverdef(data: ?*c.Elf_Data, offset: c_int, dsp: ?*c.GElf_Verdef) ?*c.GElf_Verdef {
    return null;
}

export fn gelf_getvernaux(data: ?*c.Elf_Data, offset: c_int, dst: ?*c.GElf_Vernaux) ?*c.GElf_Vernaux {
    return null;
}

export fn gelf_getverneed(data: ?*c.Elf_Data, offset: c_int, dst: ?*c.GElf_Verneed) ?*c.GElf_Verneed {
    return null;
}

export fn gelf_getversym(data: ?*c.Elf_Data, ndx: c_int, dst: ?*c.GElf_Versym) ?*c.GElf_Versym {
    return null;
}

export fn gelf_newehdr(elf: ?*c.Elf, class: c_int) ?*c_void {
    return null;
}

export fn gelf_newphdr(elf: ?*c.Elf, cnt: usize) ?*c_void {
    return null;
}

export fn gelf_update_dyn(__dst: [*c]c.Elf_Data, __ndx: c_int, __src: [*c]c.GElf_Dyn) c_int {
    return -1;
}

export fn gelf_update_ehdr(__elf: ?*c.Elf, __src: [*c]c.GElf_Ehdr) c_int {
    return -1;
}

export fn gelf_update_move(__data: [*c]c.Elf_Data, __ndx: c_int, __src: [*c]c.GElf_Move) c_int {
    return -1;
}

export fn gelf_update_phdr(__elf: ?*c.Elf, __ndx: c_int, __src: [*c]c.GElf_Phdr) c_int {
    return -1;
}

export fn gelf_update_rel(__dst: [*c]c.Elf_Data, __ndx: c_int, __src: [*c]c.GElf_Rel) c_int {
    return -1;
}

export fn gelf_update_rela(__dst: [*c]c.Elf_Data, __ndx: c_int, __src: [*c]c.GElf_Rela) c_int {
    return -1;
}

export fn gelf_update_shdr(__scn: ?*c.Elf_Scn, __src: [*c]c.GElf_Shdr) c_int {
    return -1;
}

export fn gelf_update_sym(__data: [*c]c.Elf_Data, __ndx: c_int, __src: [*c]c.GElf_Sym) c_int {
    return -1;
}

export fn gelf_update_syminfo(__data: [*c]c.Elf_Data, __ndx: c_int, __src: [*c]c.GElf_Syminfo) c_int {
    return -1;
}

export fn gelf_update_symshndx(__symdata: [*c]c.Elf_Data, __shndxdata: [*c]c.Elf_Data, __ndx: c_int, __sym: [*c]c.GElf_Sym, __xshndx: c.Elf32_Word) c_int {
    return -1;
}

export fn gelf_update_verdaux(__data: [*c]c.Elf_Data, __offset: c_int, __src: [*c]c.GElf_Verdaux) c_int {
    return -1;
}

export fn gelf_update_verdef(__data: [*c]c.Elf_Data, __offset: c_int, __src: [*c]c.GElf_Verdef) c_int {
    return -1;
}

export fn gelf_update_vernaux(__data: [*c]c.Elf_Data, __offset: c_int, __src: [*c]c.GElf_Vernaux) c_int {
    return -1;
}

export fn gelf_update_verneed(__data: [*c]c.Elf_Data, __offset: c_int, __src: [*c]c.GElf_Verneed) c_int {
    return -1;
}

export fn gelf_update_versym(__data: [*c]c.Elf_Data, __ndx: c_int, __src: [*c]c.GElf_Versym) c_int {
    return -1;
}

export fn gelf_xlatetof(elf: ?*c.Elf, dst: ?*c.Elf_Data, src: ?*const c.Elf_Data, encode: c_uint) ?*c.Elf_Data {
    return null;
}

export fn gelf_xlatetom(elf: ?*c.Elf, dst: ?*c.Elf_Data, src: ?*const c.Elf_Data, encode: c_uint) ?*c.Elf_Data {
    return null;
}

export fn nlist(__filename: [*c]const u8, __nl: [*c]c.struct_nlist) c_int {
    return -1;
}

export fn gelf_getlib(__data: [*c]c.Elf_Data, __ndx: c_int, __dst: [*c]c.GElf_Lib) [*c]c.GElf_Lib {
    return null;
}

export fn gelf_update_lib(__data: [*c]c.Elf_Data, __ndx: c_int, __src: [*c]c.GElf_Lib) c_int {
    return -1;
}

export fn elf32_offscn(__elf: ?*c.Elf, __offset: c.Elf32_Off) ?*c.Elf_Scn {
    return null;
}

export fn elf64_offscn(__elf: ?*c.Elf, __offset: c.Elf64_Off) ?*c.Elf_Scn {
    return null;
}

export fn gelf_offscn(__elf: ?*c.Elf, __offset: c.GElf_Off) ?*c.Elf_Scn {
    return null;
}

export fn elf_getaroff(__elf: ?*c.Elf) i64 {
    return -1;
}

export fn elf_gnu_hash(__string: [*c]const u8) c_ulong {
    return 0;
}

export fn elf_getdata_rawchunk(__elf: ?*c.Elf, __offset: i64, __size: usize, __type: c.Elf_Type) [*c]c.Elf_Data {
    return null;
}

export fn gelf_getauxv(__data: [*c]c.Elf_Data, __ndx: c_int, __dst: [*c]c.GElf_auxv_t) [*c]c.GElf_auxv_t {
    return null;
}

export fn gelf_update_auxv(__data: [*c]c.Elf_Data, __ndx: c_int, __src: [*c]c.GElf_auxv_t) c_int {
    return -1;
}

export fn gelf_getnote(__data: [*c]c.Elf_Data, __offset: usize, __result: [*c]c.GElf_Nhdr, __name_offset: [*c]usize, __desc_offset: [*c]usize) usize {
    return 0;
}

export fn elf_scnshndx(__scn: ?*c.Elf_Scn) c_int {
    return -1;
}

export fn elf_getshdrnum(elf: ?*c.Elf, dst: ?*usize) c_int {
    if (elf == null or dst == null)
        return -1;

    dst.?.* = Elf.cast(elf.?).state.shnum();
    return 0;
}

export fn elf_getshdrstrndx(elf: ?*c.Elf, dst: ?*usize) c_int {
    if (elf == null or dst == null)
        return -1;

    dst.?.* = Elf.cast(elf.?).state.shstrndx();
    return 0;
}

export fn elf_getphdrnum(__elf: ?*c.Elf, __dst: [*c]usize) c_int {
    return -1;
}

export fn elf32_getchdr(__scn: ?*c.Elf_Scn) [*c]c.Elf32_Chdr {
    return null;
}

export fn elf64_getchdr(__scn: ?*c.Elf_Scn) [*c]c.Elf64_Chdr {
    return null;
}

export fn gelf_getchdr(__scn: ?*c.Elf_Scn, __dst: [*c]c.GElf_Chdr) [*c]c.GElf_Chdr {
    return null;
}

export fn elf_compress(scn: ?*c.Elf_Scn, typ: c_int, flags: c_uint) c_int {
    return -1;
}

export fn elf_compress_gnu(scn: ?*c.Elf_Scn, compress: c_int, flags: c_uint) c_int {
    return -1;
}
