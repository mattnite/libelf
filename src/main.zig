const std = @import("std");
const builtin = @import("builtin");
const c = @cImport({
    @cInclude("gelf.h");
    @cInclude("nlist.h");
});

const Allocator = std.mem.Allocator;
const SectionList = std.TailQueue(Scn);
const DataList = std.TailQueue(ScnData);

threadlocal var global_error: c_int = 0;
var global_version: c_uint = c.EV_NONE;

const ScnData = struct {
    s: *Scn,
    d: c.Elf_Data,
};

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
    data_list: DataList,
    index: usize,

    const State = union(enum) {
        elf32: struct {
            shdr: *c.Elf32_Shdr,
        },
        elf64: struct {
            shdr: *c.Elf64_Shdr,
        },
    };

    fn init(elf: *Elf, self: *Scn, state: State, index: usize) !Scn {
        std.log.debug("scn: {}", .{state});
        return Scn{
            .elf = elf,
            .state = state,
            .index = index,
            .data_list = switch (state) {
                .elf32 => |e| blk: {
                    var ret = DataList{};
                    const node = try allocator.create(DataList.Node);
                    errdefer allocator.destroy(node);

                    node.* = .{
                        .data = .{
                            .s = self,
                            .d = .{
                                .d_buf = @intToPtr(?*c_void, @ptrToInt(elf.memory.get().ptr) + e.shdr.sh_offset),
                                .d_type = @intToEnum(c.Elf_Type, @intCast(c_int, e.shdr.sh_type)),
                                .d_version = global_version,
                                .d_size = e.shdr.sh_size,
                                .d_off = e.shdr.sh_offset,
                                .d_align = e.shdr.sh_addralign,
                            },
                        },
                    };

                    ret.append(node);
                    break :blk ret;
                },
                .elf64 => |e| blk: {
                    var ret = DataList{};
                    const node = try allocator.create(DataList.Node);
                    errdefer allocator.destroy(node);

                    node.* = .{
                        .data = .{
                            .s = self,
                            .d = .{
                                .d_buf = @intToPtr(?*c_void, @ptrToInt(elf.memory.get().ptr) + e.shdr.sh_offset),
                                .d_type = @intToEnum(c.Elf_Type, @intCast(c_int, e.shdr.sh_type)),
                                .d_version = global_version,
                                .d_size = e.shdr.sh_size,
                                .d_off = @intCast(i64, e.shdr.sh_offset),
                                .d_align = e.shdr.sh_addralign,
                            },
                        },
                    };

                    ret.append(node);
                    break :blk ret;
                },
            },
        };
    }

    fn deinit(self: *Scn) void {}

    fn cast(scn: *c.Elf_Scn) *Scn {
        return @ptrCast(*Scn, @alignCast(@alignOf(*Scn), scn));
    }

    fn offset(self: Scn) usize {
        return switch (self.state) {
            .elf32 => |elf| elf.shdr.sh_offset,
            .elf64 => |elf| elf.shdr.sh_offset,
        };
    }

    fn size(self: Scn) usize {
        return switch (self.state) {
            .elf32 => |elf| elf.shdr.sh_size,
            .elf64 => |elf| elf.shdr.sh_size,
        };
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
    memory: Memory,
    sections: SectionList,
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
        while (self.sections.pop()) |node| {
            node.data.deinit();
            allocator.destroy(node);
        }

        switch (self.memory) {
            .owned => |mem| allocator.free(mem),
            .referenced => {},
        }

        allocator.destroy(self);
    }

    fn fromMemory(memory: Memory) Error!*Elf {
        const ehdr = @ptrCast(*c.GElf_Ehdr, @alignCast(@alignOf(*c.GElf_Ehdr), memory.get().ptr));
        std.log.info("ehdr: {}", .{ehdr});

        const shdr = @ptrCast(*c.GElf_Shdr, @alignCast(@alignOf(*c.GElf_Shdr), memory.get()[ehdr.e_shoff..].ptr));
        var ret = try allocator.create(Elf);
        ret.* = switch (ehdr.e_ident[c.EI_CLASS]) {
            c.ELFCLASS32 => .{
                .kind = .ELF_K_ELF,
                .memory = memory,
                .sections = SectionList{},
                .state = .{
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
            },
            c.ELFCLASS64 => .{
                .kind = .ELF_K_ELF,
                .memory = memory,
                .sections = SectionList{},
                .state = .{
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
            },
            else => return error.InvalidElf,
        };

        // parse sections
        if (ret.is_64()) {
            for (ret.state.elf64.section_headers) |*header, index| {
                const node = try allocator.create(SectionList.Node);
                errdefer allocator.destroy(node);

                node.* = .{
                    .data = try Scn.init(ret, &node.data, .{
                        .elf64 = .{
                            .shdr = header,
                        },
                    }, index),
                };
                ret.sections.append(node);
            }
        } else {
            for (ret.state.elf32.section_headers) |*header, index| {
                const node = try allocator.create(SectionList.Node);
                errdefer allocator.destroy(node);

                node.* = .{
                    .data = try Scn.init(ret, &node.data, .{
                        .elf32 = .{
                            .shdr = header,
                        },
                    }, index),
                };
                ret.sections.append(node);
            }
        }

        return ret;
    }

    fn getehdr(self: *Elf, comptime T: type) *T {
        return @ptrCast(*T, @alignCast(@alignOf(*T), self.memory.get().ptr));
    }
};

/// Compute simple checksum from permanent parts of the ELF file
export fn elf32_checksum(elf: ?*c.Elf) c_long {
    return -1;
}

/// Return size of array of COUNT elements of the type denoted by TYPE
/// in the external representation.  The binary class is taken from ELF.
/// The result is based on version VERSION of the ELF standard.
export fn elf32_fsize(elf_type: c.Elf_Type, count: usize, version: c_uint) usize {
    return 0;
}

/// Retrieve class-dependent object file header
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

/// Get the number of program headers in the ELF file.  If the file uses
/// more headers than can be represented in the e_phnum field of the ELF
/// header the information from the sh_info field in the zeroth section
/// header is used.
export fn elf32_getphdr(elf: ?*c.Elf) ?*c.Elf32_Phdr {
    return null;
}

/// Retrieve section header of ELFCLASS32 binary
export fn elf32_getshdr(scn: ?*c.Elf_Scn) ?*c.Elf32_Shdr {
    return if (scn) |s| Scn.cast(s).state.elf32.shdr else null;
}

// Create ELF header if none exists
export fn elf32_newehdr(elf: ?*c.Elf) ?*c.Elf32_Ehdr {
    return null;
}

/// Create ELF program header
export fn elf32_newphdr(elf: ?*c.Elf, cnt: usize) ?*c.Elf32_Phdr {
    return null;
}

/// Convert data structure from to the representation in memory
/// represented by ELF file representation
export fn elf32_xlatetof(dest: ?*c.Elf_Data, src: ?*const c.Elf_Data, encode: c_uint) ?*c.Elf_Data {
    return null;
}

/// Convert data structure from the representation in the file represented
/// by ELF to their memory representation
export fn elf32_xlatetom(dest: ?*c.Elf_Data, src: ?*const c.Elf_Data, encode: c_uint) ?*c.Elf_Data {
    return null;
}

/// Compute simple checksum from permanent parts of the ELF file
export fn elf64_checksum(elf: ?*c.Elf) c_long {
    return -1;
}

/// Return size of array of COUNT elements of the type denoted by TYPE
/// in the external representation.  The binary class is taken from ELF.
/// The result is based on version VERSION of the ELF standard.
export fn elf64_fsize(elf_type: c.Elf_Type, count: usize, version: c_uint) usize {
    return 0;
}

/// Retrieve class-dependent object file header
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

/// Retrieve class-dependent program header table
export fn elf64_getphdr(elf: ?*c.Elf) ?*c.Elf64_Phdr {
    return null;
}

/// Retrieve section header of ELFCLASS64 binary
export fn elf64_getshdr(scn: ?*c.Elf_Scn) ?*c.Elf64_Shdr {
    return if (scn) |s| Scn.cast(s).state.elf64.shdr else null;
}

/// Create ELF header if none exists
export fn elf64_newehdr(elf: ?*c.Elf) ?*c.Elf64_Ehdr {
    const e = Elf.cast(elf orelse return null);
    if (e.kind != .ELF_K_ELF) {
        seterrno(error.InvalidHandle);
        return null;
    }

    if (!e.is_64()) {
        seterrno(error.InvalidClass);
        return null;
    }

    // TODO: make ehdr optional for the case of user created elf
    return null;
}

/// Create ELF program header
export fn elf64_newphdr(elf: ?*c.Elf, cnt: usize) ?*c.Elf64_Phdr {
    return null;
}

// Convert data structure from to the representation in memory
// represented by ELF file representation
export fn elf64_xlatetof(dest: ?*c.Elf_Data, src: ?*const c.Elf_Data, encode: c_uint) ?*c.Elf_Data {
    return null;
}

/// Convert data structure from the representation in the file represented
/// by ELF to their memory representation
export fn elf64_xlatetom(dest: ?*c.Elf_Data, src: ?*const c.Elf_Data, encode: c_uint) ?*c.Elf_Data {
    return null;
}

/// Return descriptor for ELF file to work according to CMD
export fn elf_begin(fd: c_int, cmd: c.Elf_Cmd, ref: ?*c.Elf) ?*c.Elf {
    return @ptrCast(*c.Elf, Elf.begin(fd, cmd, if (ref) |r| Elf.cast(r) else null) catch |e| {
        seterrno(e);
        return null;
    });
}

/// Create a clone of an existing ELF descriptor
export fn elf_clone(elf: ?*c.Elf, cmd: c.Elf_Cmd) ?*c.Elf {
    return null;
}

// Control ELF descriptor
export fn elf_cntl(elf: ?*c.Elf, cmd: c.Elf_Cmd) c_int {
    return -1;
}

/// Free resources allocated for ELF
export fn elf_end(elf: ?*c.Elf) c_int {
    return if (elf) |e| blk: {
        @ptrCast(*Elf, Elf.cast(e)).end();
        break :blk 0;
    } else 0;
}

/// Return error string for ERROR.  If ERROR is zero, return error string
/// for most recent error or NULL is none occurred.  If ERROR is -1 the
/// behaviour is similar to the last case except that not NULL but a legal
/// string is returned.
export fn elf_errmsg(err: c_int) ?[*:0]const u8 {
    const last_error = global_error;
    return if (err == 0)
        "no error"
    else if (err < -1 or err > std.math.maxInt(u16))
        "unknown error"
    else switch (@intToError(@intCast(u16, if (err == -1) last_error else err))) {
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
        error.Todo => "TODO",
        else => "unknown error",
    };
}

/// Return error code of last failing function call.  This value is kept
/// separately for each thread
export fn elf_errno() c_int {
    defer global_error = 0;
    return global_error;
}

/// Set fill bytes used to fill holes in data structures
export fn elf_fill(fill: c_int) void {}

/// Set or clear flags for ELF data
export fn elf_flagdata(data: ?*c.Elf_Data, cmd: c.Elf_Cmd, flags: c_uint) c_uint {
    return 0;
}

/// Set or clear flags for ELF header
export fn elf_flagehdr(elf: ?*c.Elf, cmd: c.Elf_Cmd, flags: c_uint) c_uint {
    return 0;
}

/// Set or clear flags for ELF file
export fn elf_flagelf(elf: ?*c.Elf, cmd: c.Elf_Cmd, flags: c_uint) c_uint {
    return 0;
}

/// Set or clear flags for ELF program header
export fn elf_flagphdr(elf: ?*c.Elf, cmd: c.Elf_Cmd, flags: c_uint) c_uint {
    return 0;
}

/// Set or clear flags for ELF section
export fn elf_flagscn(scn: ?*c.Elf_Scn, cmd: c.Elf_Cmd, flags: c_uint) c_uint {
    return 0;
}

/// Set or clear flags for ELF section header
export fn elf_flagshdr(scn: ?*c.Elf_Scn, cmd: c.Elf_Cmd, flags: c_uint) c_uint {
    return 0;
}

/// Return header of archive
export fn elf_getarhdr(elf: ?*c.Elf) ?*c.Elf_Arhdr {
    return null;
}

export fn elf_getarsym(elf: ?*c.Elf, narsyms: *usize) ?*c.Elf_Arhdr {
    return null;
}

export fn elf_getbase(elf: ?*c.Elf) i64 {
    return -1;
}

/// Get data from section while translating from file representation to
/// memory representation.  The Elf_Data d_type is set based on the
/// section type if known.  Otherwise d_type is set to ELF_T_BYTE.  If
/// the section contains compressed data then d_type is always set to
/// ELF_T_CHDR.
export fn elf_getdata(scn: ?*c.Elf_Scn, data: ?*c.Elf_Data) ?*c.Elf_Data {
    return if (scn == null)
        null
    else if (data == null)
        if (Scn.cast(scn.?).data_list.first) |node| &node.data.d else null
    else blk: {
        var it = Scn.cast(scn.?).data_list.first;
        break :blk while (it) |node| : (it = it.?.next) {
            if (node.prev) |prev| if (&prev.data.d == data.?)
                break &node.data.d;
        } else null;
    };
}

export fn elf_getident(elf: ?*c.Elf, nbytes: ?*usize) ?[*]u8 {
    return null;
}

/// Get section at INDEX.
export fn elf_getscn(elf: ?*c.Elf, index: usize) ?*c.Elf_Scn {
    const e = Elf.cast(elf orelse return null);
    return if (index < e.sections.len) blk: {
        var it = e.sections.first;
        break :blk @ptrCast(*c.Elf_Scn, while (it) |node| : (it = it.?.next) {
            if (node.data.index == index)
                break node;
        } else return null);
    } else null;
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

/// Determine what kind of file is associated with ELF.
export fn elf_kind(elf: ?*c.Elf) c.Elf_Kind {
    return Elf.cast(elf orelse return .ELF_K_NONE).kind;
}

/// Create descriptor for memory region.
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

/// Get index of section
export fn elf_ndxscn(scn: ?*c.Elf_Scn) usize {
    return Scn.cast(scn orelse return c.SHN_UNDEF).index;
}

/// Create new data descriptor for section SCN
export fn elf_newdata(scn: ?*c.Elf_Scn) ?*c.Elf_Data {
    const s = Scn.cast(scn orelse return null);
    if (s.index == 0) {
        seterrno(error.NotNulSection);
        return null;
    }

    // TODO: see corresponding C code, for some reason this isn't allowed for 32
    // bit elf or one with missing ehdr?
    if (s.elf.is_32()) {
        seterrno(error.WrongOrderEhdr);
        return null;
    }

    const node = allocator.create(DataList.Node) catch |err| {
        seterrno(err);
        return null;
    };
    node.* = .{
        .data = ScnData{
            .s = s,
            .d = .{
                .d_version = c.EV_CURRENT,
                .d_buf = null,
                .d_type = .ELF_T_BYTE,
                .d_size = 0,
                .d_off = 0,
                .d_align = 0,
            },
        },
    };

    s.data_list.append(node);
    return &node.data.d;
}

/// Create a new section and append it at the end of the table
export fn elf_newscn(elf: ?*c.Elf) ?*c.Elf_Scn {
    const e = Elf.cast(elf orelse return null);
    const node = allocator.create(SectionList.Node) catch |err| {
        seterrno(err);
        return null;
    };

    node.* = .{
        .data = .{
            .elf = e,
            .data_list = DataList{},
            .index = e.sections.len,
            // TODO: probably not make this undefined
            .state = undefined,
        },
    };

    e.sections.append(node);
    return null;
}

/// Advance archive descriptor to next element
export fn elf_next(elf: ?*c.Elf) c.Elf_Cmd {
    return .ELF_C_NULL;
}

/// Get section with next section index.
export fn elf_nextscn(elf: ?*c.Elf, scn: ?*c.Elf_Scn) ?*c.Elf_Scn {
    const e = Elf.cast(elf orelse return null);
    const s = Scn.cast(scn orelse return null);
    const node = @fieldParentPtr(SectionList.Node, "data", s);

    return if (node.next) |next| @ptrCast(*c.Elf_Scn, &next.data) else null;
}

export fn elf_rand(elf: ?*c.Elf, offset: usize) usize {
    return 0;
}

/// Get uninterpreted section content.
export fn elf_rawdata(scn: ?*c.Elf_Scn, data: ?*c.Elf_Data) ?*c.Elf_Data {
    // TODO
    return null;
}

export fn elf_rawfile(elf: ?*c.Elf, nbytes: *usize) ?[*]u8 {
    return null;
}

/// Return pointer to string at OFFSET in section INDEX
export fn elf_strptr(elf: ?*c.Elf, index: usize, offset: usize) ?[*:0]const u8 {
    const e = Elf.cast(elf orelse return null);
    var it = e.sections.first;
    return while (it) |node| : (it = it.?.next) {
        if (node.data.index == index) {
            const scn = node.data;
            const data = e.memory.get()[scn.offset() .. scn.offset() + scn.size()];
            const str = data[offset..];

            // check for null terminator
            if (null == std.mem.indexOf(u8, str, &.{0})) {
                seterrno(error.InvalidIndex);
                return null;
            }

            break @ptrCast([*:0]const u8, str.ptr);
        }
    } else null;
}

/// Update ELF descriptor and write file to disk
export fn elf_update(elf: ?*c.Elf, cmd: c.Elf_Cmd) i64 {
    // TODO
    return -1;
}

/// Coordinate ELF library and application versions
export fn elf_version(version: c_uint) c_uint {
    std.debug.attachSegfaultHandler();
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

/// Compute simple checksum from permanent parts of the ELF file
export fn gelf_checksum(elf: ?*c.Elf) c_long {
    return -1;
}

/// Return size of array of COUNT elements of the type denoted by TYPE
/// in the external representation.  The binary class is taken from ELF.
/// The result is based on version VERSION of the ELF standard.
export fn gelf_fsize(elf: ?*c.Elf, elf_type: c.Elf_Type, count: usize, version: c_uint) usize {
    return 0;
}

/// Get class of the file associated with ELF.  */
export fn gelf_getclass(elf: ?*c.Elf) c_int {
    // TODO
    return 0;
}

/// Get information from dynamic table at the given index
export fn gelf_getdyn(data: ?*c.Elf_Data, ndx: c_int, dst: ?*c.GElf_Dyn) ?*c.GElf_Dyn {
    return null;
}

/// Retrieve object file header.
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

/// Get move structure at the given index
export fn gelf_getmove(data: ?*c.Elf_Data, ndx: c_int, dst: ?*c.GElf_Move) ?*c.GElf_Move {
    return null;
}

/// Retrieve program header table entry
export fn gelf_getphdr(elf: ?*c.Elf, ndr: c_int, dst: ?*c.GElf_Phdr) ?*c.GElf_Phdr {
    return null;
}

/// Retrieve REL relocation info at the given index.
export fn gelf_getrel(data: ?*c.Elf_Data, ndx: c_int, dst: ?*c.GElf_Rel) ?*c.GElf_Rel {
    // TODO
    return null;
}

/// Retrieve RELA relocation info at the given index
export fn gelf_getrela(data: ?*c.Elf_Data, ndx: c_int, dst: ?*c.GElf_Rela) ?*c.GElf_Rela {
    return null;
}

/// Retrieve section header.
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

/// Retrieve symbol information from the symbol table at the given index.
export fn gelf_getsym(data: ?*c.Elf_Data, ndx: c_int, dst: ?*c.GElf_Sym) ?*c.GElf_Sym {
    // TODO
    return null;
}

/// Retrieve additional symbol information from the symbol table at the
/// given index
export fn gelf_getsyminfo(data: ?*c.Elf_Data, ndx: c_int, dst: ?*c.GElf_Syminfo) ?*c.GElf_Syminfo {
    return null;
}

/// Retrieve symbol information and separate section index from the
/// symbol table at the given index
export fn gelf_getsymshndx(symdata: ?*c.Elf_Data, shndxdata: ?*c.Elf_Data, ndx: c_int, sym: ?*c.GElf_Sym, xshndx: ?*c.Elf32_Word) ?*c.GElf_Sym {
    return null;
}

/// Retrieve additional symbol version definition information at given
/// offset
export fn gelf_getverdaux(data: ?*c.Elf_Data, offset: c_int, dst: ?*c.GElf_Verdef) ?*c.GElf_Verdef {
    return null;
}

/// Retrieve symbol version definition information at given offset
export fn gelf_getverdef(data: ?*c.Elf_Data, offset: c_int, dsp: ?*c.GElf_Verdef) ?*c.GElf_Verdef {
    return null;
}

/// Retrieve additional required symbol version information at given offset
export fn gelf_getvernaux(data: ?*c.Elf_Data, offset: c_int, dst: ?*c.GElf_Vernaux) ?*c.GElf_Vernaux {
    return null;
}

/// Retrieve required symbol version information at given offset
export fn gelf_getverneed(data: ?*c.Elf_Data, offset: c_int, dst: ?*c.GElf_Verneed) ?*c.GElf_Verneed {
    return null;
}

/// Retrieve symbol version information at given index
export fn gelf_getversym(data: ?*c.Elf_Data, ndx: c_int, dst: ?*c.GElf_Versym) ?*c.GElf_Versym {
    return null;
}

/// Create new ELF header if none exists.  Creates an Elf32_Ehdr if CLASS
/// is ELFCLASS32 or an Elf64_Ehdr if CLASS is ELFCLASS64.  Returns NULL
/// on error.
export fn gelf_newehdr(elf: ?*c.Elf, class: c_int) ?*c_void {
    return null;
}

/// Create new program header with PHNUM entries.  Creates either an
/// Elf32_Phdr or an Elf64_Phdr depending on whether the given ELF is
/// ELFCLASS32 or ELFCLASS64.  Returns NULL on error.
export fn gelf_newphdr(elf: ?*c.Elf, cnt: usize) ?*c_void {
    return null;
}

/// Update information in dynamic table at the given index
export fn gelf_update_dyn(__dst: [*c]c.Elf_Data, __ndx: c_int, __src: [*c]c.GElf_Dyn) c_int {
    return -1;
}

/// Update the ELF header
export fn gelf_update_ehdr(__elf: ?*c.Elf, __src: [*c]c.GElf_Ehdr) c_int {
    return -1;
}

/// Update move structure at the given index
export fn gelf_update_move(__data: [*c]c.Elf_Data, __ndx: c_int, __src: [*c]c.GElf_Move) c_int {
    return -1;
}

/// Update the program header
export fn gelf_update_phdr(__elf: ?*c.Elf, __ndx: c_int, __src: [*c]c.GElf_Phdr) c_int {
    return -1;
}

/// Update REL relocation information at given index
export fn gelf_update_rel(__dst: [*c]c.Elf_Data, __ndx: c_int, __src: [*c]c.GElf_Rel) c_int {
    return -1;
}

/// Update RELA relocation information at given index
export fn gelf_update_rela(__dst: [*c]c.Elf_Data, __ndx: c_int, __src: [*c]c.GElf_Rela) c_int {
    return -1;
}

/// Update section header
export fn gelf_update_shdr(__scn: ?*c.Elf_Scn, __src: [*c]c.GElf_Shdr) c_int {
    return -1;
}

/// Update symbol information in the symbol table at the given index
export fn gelf_update_sym(__data: [*c]c.Elf_Data, __ndx: c_int, __src: [*c]c.GElf_Sym) c_int {
    return -1;
}

/// Update additional symbol information in the symbol table at the
/// given index
export fn gelf_update_syminfo(__data: [*c]c.Elf_Data, __ndx: c_int, __src: [*c]c.GElf_Syminfo) c_int {
    return -1;
}

/// Update symbol information and separate section index in the symbol
/// table at the given index
export fn gelf_update_symshndx(__symdata: [*c]c.Elf_Data, __shndxdata: [*c]c.Elf_Data, __ndx: c_int, __sym: [*c]c.GElf_Sym, __xshndx: c.Elf32_Word) c_int {
    return -1;
}

/// Update additional symbol version definition information
export fn gelf_update_verdaux(__data: [*c]c.Elf_Data, __offset: c_int, __src: [*c]c.GElf_Verdaux) c_int {
    return -1;
}

/// Update symbol version definition information
export fn gelf_update_verdef(__data: [*c]c.Elf_Data, __offset: c_int, __src: [*c]c.GElf_Verdef) c_int {
    return -1;
}

/// Update additional required symbol version information
export fn gelf_update_vernaux(__data: [*c]c.Elf_Data, __offset: c_int, __src: [*c]c.GElf_Vernaux) c_int {
    return -1;
}

/// Update required symbol version information
export fn gelf_update_verneed(__data: [*c]c.Elf_Data, __offset: c_int, __src: [*c]c.GElf_Verneed) c_int {
    return -1;
}

/// Update symbol version information
export fn gelf_update_versym(__data: [*c]c.Elf_Data, __ndx: c_int, __src: [*c]c.GElf_Versym) c_int {
    return -1;
}

/// Convert data structure from to the representation in memory
/// represented by ELF file representation
export fn gelf_xlatetof(elf: ?*c.Elf, dst: ?*c.Elf_Data, src: ?*const c.Elf_Data, encode: c_uint) ?*c.Elf_Data {
    return null;
}

/// Convert data structure from the representation in the file represented
/// by ELF to their memory representation
export fn gelf_xlatetom(elf: ?*c.Elf, dst: ?*c.Elf_Data, src: ?*const c.Elf_Data, encode: c_uint) ?*c.Elf_Data {
    return null;
}

/// Get specified entries from file
export fn nlist(__filename: [*c]const u8, __nl: [*c]c.struct_nlist) c_int {
    return -1;
}

/// Get library from table at the given index
export fn gelf_getlib(__data: [*c]c.Elf_Data, __ndx: c_int, __dst: [*c]c.GElf_Lib) [*c]c.GElf_Lib {
    return null;
}

/// Update library in table at the given index
export fn gelf_update_lib(__data: [*c]c.Elf_Data, __ndx: c_int, __src: [*c]c.GElf_Lib) c_int {
    return -1;
}

/// Get section at OFFSET
export fn elf32_offscn(__elf: ?*c.Elf, __offset: c.Elf32_Off) ?*c.Elf_Scn {
    return null;
}

/// Get section at OFFSET
export fn elf64_offscn(__elf: ?*c.Elf, __offset: c.Elf64_Off) ?*c.Elf_Scn {
    return null;
}

/// Get section at OFFSET
export fn gelf_offscn(__elf: ?*c.Elf, __offset: c.GElf_Off) ?*c.Elf_Scn {
    return null;
}

/// Return offset in archive for current file ELF
export fn elf_getaroff(__elf: ?*c.Elf) i64 {
    return -1;
}

/// Compute hash value using the GNU-specific hash function
export fn elf_gnu_hash(__string: [*c]const u8) c_ulong {
    return 0;
}

/// Get data translated from a chunk of the file contents as section data
/// would be for TYPE.  The resulting Elf_Data pointer is valid until
/// elf_end (ELF) is called.
export fn elf_getdata_rawchunk(__elf: ?*c.Elf, __offset: i64, __size: usize, __type: c.Elf_Type) [*c]c.Elf_Data {
    return null;
}

/// Get auxv entry at the given index
export fn gelf_getauxv(__data: [*c]c.Elf_Data, __ndx: c_int, __dst: [*c]c.GElf_auxv_t) [*c]c.GElf_auxv_t {
    return null;
}

/// Update auxv entry at the given index
export fn gelf_update_auxv(__data: [*c]c.Elf_Data, __ndx: c_int, __src: [*c]c.GElf_auxv_t) c_int {
    return -1;
}

/// Get note header at the given offset into the data, and the offsets of
/// the note's name and descriptor data.  Returns the offset of the next
/// note header, or 0 for an invalid offset or corrupt note header.
export fn gelf_getnote(__data: [*c]c.Elf_Data, __offset: usize, __result: [*c]c.GElf_Nhdr, __name_offset: [*c]usize, __desc_offset: [*c]usize) usize {
    return 0;
}

/// Get the section index of the extended section index table for the
/// given symbol table
export fn elf_scnshndx(__scn: ?*c.Elf_Scn) c_int {
    return -1;
}

/// Get the number of sections in the ELF file.  If the file uses more
/// sections than can be represented in the e_shnum field of the ELF
/// header the information from the sh_size field in the zeroth section
/// header is used.
export fn elf_getshdrnum(elf: ?*c.Elf, dst: ?*usize) c_int {
    if (elf == null or dst == null)
        return -1;

    dst.?.* = Elf.cast(elf.?).state.shnum();
    return 0;
}

/// Get the section index of the section header string table in the ELF
/// file.  If the index cannot be represented in the e_shstrndx field of
/// the ELF header the information from the sh_link field in the zeroth
/// section header is used.
export fn elf_getshdrstrndx(elf: ?*c.Elf, dst: ?*usize) c_int {
    if (elf == null or dst == null)
        return -1;

    dst.?.* = Elf.cast(elf.?).state.shstrndx();
    return 0;
}

/// Get the number of program headers in the ELF file.  If the file uses
/// more headers than can be represented in the e_phnum field of the ELF
/// header the information from the sh_info field in the zeroth section
/// header is used.
export fn elf_getphdrnum(__elf: ?*c.Elf, __dst: [*c]usize) c_int {
    return -1;
}

/// Returns compression header for a section if section data is
/// compressed.  Returns NULL and sets elf_errno if the section isn't
/// compressed or an error occurred.
export fn elf32_getchdr(__scn: ?*c.Elf_Scn) [*c]c.Elf32_Chdr {
    return null;
}

/// Returns compression header for a section if section data is
/// compressed.  Returns NULL and sets elf_errno if the section isn't
/// compressed or an error occurred.
export fn elf64_getchdr(__scn: ?*c.Elf_Scn) [*c]c.Elf64_Chdr {
    return null;
}

/// Get compression header of section if any.  Returns NULL and sets
/// elf_errno if the section isn't compressed or an error occurred.
export fn gelf_getchdr(__scn: ?*c.Elf_Scn, __dst: [*c]c.GElf_Chdr) [*c]c.GElf_Chdr {
    return null;
}

/// Compress or decompress the data of a section and adjust the section
/// header.
///
/// elf_compress works by setting or clearing the SHF_COMPRESS flag
/// from the section Shdr and will encode or decode a Elf32_Chdr or
/// Elf64_Chdr at the start of the section data.  elf_compress_gnu will
/// encode or decode any section, but is traditionally only used for
/// sections that have a name starting with ".debug" when
/// uncompressed or ".zdebug" when compressed and stores just the
/// uncompressed size.  The GNU compression method is deprecated and
/// should only be used for legacy support.
///
/// elf_compress takes a compression type that should be either zero to
/// decompress or an ELFCOMPRESS algorithm to use for compression.
/// Currently only ELFCOMPRESS_ZLIB is supported.  elf_compress_gnu
/// will compress in the traditional GNU compression format when
/// compress is one and decompress the section data when compress is
/// zero.
///
/// The FLAGS argument can be zero or ELF_CHF_FORCE.  If FLAGS contains
/// ELF_CHF_FORCE then it will always compress the section, even if
/// that would not reduce the size of the data section (including the
/// header).  Otherwise elf_compress and elf_compress_gnu will compress
/// the section only if the total data size is reduced.
///
/// On successful compression or decompression the function returns
/// one.  If (not forced) compression is requested and the data section
/// would not actually reduce in size, the section is not actually
/// compressed and zero is returned.  Otherwise -1 is returned and
/// elf_errno is set.
///
/// It is an error to request compression for a section that already
/// has SHF_COMPRESSED set, or (for elf_compress) to request
/// decompression for an section that doesn't have SHF_COMPRESSED set.
/// If a section has SHF_COMPRESSED set then calling elf_compress_gnu
/// will result in an error.  The section has to be decompressed first
/// using elf_compress.  Calling elf_compress on a section compressed
/// with elf_compress_gnu is fine, but probably useless.
///
/// It is always an error to call these functions on SHT_NOBITS
/// sections or if the section has the SHF_ALLOC flag set.
/// elf_compress_gnu will not check whether the section name starts
/// with ".debug" or .zdebug".  It is the responsibility of the caller
/// to make sure the deprecated GNU compression method is only called
/// on correctly named sections (and to change the name of the section
/// when using elf_compress_gnu).
///
/// All previous returned Shdrs and Elf_Data buffers are invalidated by
/// this call and should no longer be accessed.
///
/// Note that although this changes the header and data returned it
/// doesn't mark the section as dirty.  To keep the changes when
/// calling elf_update the section has to be flagged ELF_F_DIRTY.  */
export fn elf_compress(scn: ?*c.Elf_Scn, typ: c_int, flags: c_uint) c_int {
    return -1;
}

/// Compress or decompress the data of a section and adjust the section
/// header.
///
/// elf_compress works by setting or clearing the SHF_COMPRESS flag
/// from the section Shdr and will encode or decode a Elf32_Chdr or
/// Elf64_Chdr at the start of the section data.  elf_compress_gnu will
/// encode or decode any section, but is traditionally only used for
/// sections that have a name starting with ".debug" when
/// uncompressed or ".zdebug" when compressed and stores just the
/// uncompressed size.  The GNU compression method is deprecated and
/// should only be used for legacy support.
///
/// elf_compress takes a compression type that should be either zero to
/// decompress or an ELFCOMPRESS algorithm to use for compression.
/// Currently only ELFCOMPRESS_ZLIB is supported.  elf_compress_gnu
/// will compress in the traditional GNU compression format when
/// compress is one and decompress the section data when compress is
/// zero.
///
/// The FLAGS argument can be zero or ELF_CHF_FORCE.  If FLAGS contains
/// ELF_CHF_FORCE then it will always compress the section, even if
/// that would not reduce the size of the data section (including the
/// header).  Otherwise elf_compress and elf_compress_gnu will compress
/// the section only if the total data size is reduced.
///
/// On successful compression or decompression the function returns
/// one.  If (not forced) compression is requested and the data section
/// would not actually reduce in size, the section is not actually
/// compressed and zero is returned.  Otherwise -1 is returned and
/// elf_errno is set.
///
/// It is an error to request compression for a section that already
/// has SHF_COMPRESSED set, or (for elf_compress) to request
/// decompression for an section that doesn't have SHF_COMPRESSED set.
/// If a section has SHF_COMPRESSED set then calling elf_compress_gnu
/// will result in an error.  The section has to be decompressed first
/// using elf_compress.  Calling elf_compress on a section compressed
/// with elf_compress_gnu is fine, but probably useless.
///
/// It is always an error to call these functions on SHT_NOBITS
/// sections or if the section has the SHF_ALLOC flag set.
/// elf_compress_gnu will not check whether the section name starts
/// with ".debug" or .zdebug".  It is the responsibility of the caller
/// to make sure the deprecated GNU compression method is only called
/// on correctly named sections (and to change the name of the section
/// when using elf_compress_gnu).
///
/// All previous returned Shdrs and Elf_Data buffers are invalidated by
/// this call and should no longer be accessed.
///
/// Note that although this changes the header and data returned it
/// doesn't mark the section as dirty.  To keep the changes when
/// calling elf_update the section has to be flagged ELF_F_DIRTY.  */
export fn elf_compress_gnu(scn: ?*c.Elf_Scn, compress: c_int, flags: c_uint) c_int {
    return -1;
}
