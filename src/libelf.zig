const std = @import("std");
const builtin = @import("builtin");
const c = @cImport({
    @cInclude("gelf.h");
    @cInclude("nlist.h");
});

const log = std.log.scoped(.libelf);

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
    log.debug("setting errno to {s}", .{@errorName(err)});
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
        log.debug("scn: {}", .{state});
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
                                .d_buf = @intToPtr(?*c_void, @ptrToInt(elf.memory.ptr) + e.shdr.sh_offset),
                                .d_type = shdrTypeToDataType(e.shdr.sh_type),
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
                                .d_buf = @intToPtr(?*c_void, @ptrToInt(elf.memory.ptr) + e.shdr.sh_offset),
                                .d_type = shdrTypeToDataType(e.shdr.sh_type),
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

    fn shdrTypeToDataType(sh_type: usize) c.Elf_Type {
        return switch (sh_type) {
            c.SHT_SYMTAB => c.ELF_T_SYM,
            c.SHT_RELA => c.ELF_T_RELA,
            c.SHT_HASH => c.ELF_T_WORD,
            c.SHT_DYNAMIC => c.ELF_T_DYN,
            c.SHT_REL => c.ELF_T_REL,
            c.SHT_DYNSYM => c.ELF_T_SYM,
            c.SHT_INIT_ARRAY => c.ELF_T_ADDR,
            c.SHT_FINI_ARRAY => c.ELF_T_ADDR,
            c.SHT_PREINIT_ARRAY => c.ELF_T_ADDR,
            c.SHT_GROUP => c.ELF_T_WORD,
            c.SHT_SYMTAB_SHNDX => c.ELF_T_WORD,
            c.SHT_NOTE => c.ELF_T_NHDR,
            c.SHT_GNU_verdef => c.ELF_T_VDEF,
            c.SHT_GNU_verneed => c.ELF_T_VNEED,
            c.SHT_GNU_versym => c.ELF_T_HALF,
            c.SHT_SUNW_syminfo => c.ELF_T_SYMINFO,
            c.SHT_SUNW_move => c.ELF_T_MOVE,
            c.SHT_GNU_LIBLIST => c.ELF_T_LIB,
            c.SHT_GNU_HASH => c.ELF_T_GNUHASH,
            else => c.ELF_T_BYTE,
        };
    }

    fn deinit(self: *Scn) void {
        _ = self;
    }

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

const Elf = struct {
    arena: std.heap.ArenaAllocator,
    kind: c.Elf_Kind,
    memory: []u8,
    sections: SectionList,
    state: union(enum) {
        elf32: struct {
            ehdr: ?*c.Elf32_Ehdr,
            section_headers: []c.Elf32_Shdr,
        },
        elf64: struct {
            ehdr: ?*c.Elf64_Ehdr,
            section_headers: []c.Elf64_Shdr,
        },

        const Self = @This();

        fn shstrndx(self: Self) !usize {
            return switch (self) {
                .elf32 => |elf| if (elf.ehdr) |h| h.e_shstrndx else return error.InvalidData,
                .elf64 => |elf| if (elf.ehdr) |h| h.e_shstrndx else return error.InvalidData,
            };
        }

        fn shnum(self: Self) !usize {
            return switch (self) {
                .elf32 => |elf| if (elf.ehdr) |h| h.e_shnum else return error.InvalidData,
                .elf64 => |elf| if (elf.ehdr) |h| h.e_shnum else return error.InvalidData,
            };
        }
    },

    fn cast(elf: *c.Elf) *Elf {
        return @ptrCast(*Elf, @alignCast(@alignOf(*Elf), elf));
    }

    fn is_64(elf: *Elf) bool {
        return elf.memory[c.EI_CLASS] == c.ELFCLASS64;
    }

    fn is_32(elf: *Elf) bool {
        return elf.memory[c.EI_CLASS] == c.ELFCLASS32;
    }

    fn validEndianness(elf: *Elf) !bool {
        return switch (elf.memory[c.EI_DATA]) {
            c.ELFDATA2LSB => builtin.target.cpu.arch.endian() == .Little,
            c.ELFDATA2MSB => builtin.target.cpu.arch.endian() == .Big,
            else => error.InvalidData,
        };
    }

    fn begin(fd: c_int, cmd: c.Elf_Cmd, ref: ?*Elf) Error!?*Elf {
        if (global_version != c.EV_CURRENT)
            return error.NoVersion;

        if (ref) |r| {
            _ = r;
            // TODO: r.rwlock();
        } else {
            _ = std.os.fcntl(fd, std.c.F_GETFD, 0) catch {
                return error.InvalidFile;
            };
        }
        // TODO: defer if (ref) |r| r.unlock();

        return switch (cmd) {
            c.ELF_C_NULL => null,
            c.ELF_C_READ, c.ELF_C_READ_MMAP => blk: {
                const file = std.fs.File{ .handle = fd };
                var arena = std.heap.ArenaAllocator.init(allocator);
                errdefer arena.deinit();

                break :blk fromMemory(
                    file.reader().readAllAlloc(&arena.allocator, std.math.maxInt(usize)) catch {
                        return error.InvalidFile;
                    },
                    arena,
                );
            },
            c.ELF_C_WRITE => error.Todo,
            else => error.Todo,
        };
    }

    fn end(self: *Elf) void {
        while (self.sections.pop()) |node| {
            node.data.deinit();
            allocator.destroy(node);
        }

        self.arena.deinit();
        allocator.destroy(self);
    }

    fn fromMemory(memory: []u8, arena: ?std.heap.ArenaAllocator) Error!*Elf {
        const class = memory[c.EI_CLASS];
        var a = arena orelse std.heap.ArenaAllocator.init(allocator);

        var ret = try allocator.create(Elf);
        errdefer allocator.destroy(ret);

        ret.* = switch (class) {
            c.ELFCLASS32 => .{
                .arena = a,
                .kind = c.ELF_K_ELF,
                .memory = memory,
                .sections = SectionList{},
                .state = .{
                    .elf32 = .{
                        .ehdr = @ptrCast(*c.Elf32_Ehdr, @alignCast(@alignOf(*c.Elf32_Ehdr), memory.ptr)),
                        .section_headers = blk: {
                            const ehdr = @ptrCast(*c.Elf32_Ehdr, @alignCast(@alignOf(*c.Elf32_Ehdr), memory.ptr));

                            if (ehdr.e_shoff > memory.len)
                                return error.InvalidElf;

                            const sections = try a.allocator.alloc(c.Elf32_Shdr, ehdr.e_shnum);
                            std.mem.copy(u8, std.mem.sliceAsBytes(sections), memory[ehdr.e_shoff .. ehdr.e_shoff + (ehdr.e_shnum * @sizeOf(c.Elf32_Shdr))]);
                            break :blk sections;
                        },
                    },
                },
            },
            c.ELFCLASS64 => .{
                .arena = a,
                .kind = c.ELF_K_ELF,
                .memory = memory,
                .sections = SectionList{},
                .state = .{
                    .elf64 = .{
                        .ehdr = @ptrCast(*c.Elf64_Ehdr, @alignCast(@alignOf(*c.Elf64_Ehdr), memory.ptr)),
                        .section_headers = blk: {
                            const ehdr = @ptrCast(*c.Elf64_Ehdr, @alignCast(@alignOf(*c.Elf64_Ehdr), memory.ptr));

                            if (ehdr.e_shoff > memory.len)
                                return error.InvalidElf;

                            const sections = try a.allocator.alloc(c.Elf64_Shdr, ehdr.e_shnum);
                            std.mem.copy(u8, std.mem.sliceAsBytes(sections), memory[ehdr.e_shoff .. ehdr.e_shoff + (ehdr.e_shnum * @sizeOf(c.Elf64_Shdr))]);
                            break :blk sections;
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
};

/// Compute simple checksum from permanent parts of the ELF file
export fn elf32_checksum(elf: ?*c.Elf) c_long {
    _ = elf;
    return -1;
}

/// Return size of array of COUNT elements of the type denoted by TYPE
/// in the external representation.  The binary class is taken from ELF.
/// The result is based on version VERSION of the ELF standard.
export fn elf32_fsize(elf_type: c.Elf_Type, count: usize, version: c_uint) usize {
    _ = elf_type;
    _ = count;
    _ = version;
    return 0;
}

/// Retrieve class-dependent object file header
export fn elf32_getehdr(elf: ?*c.Elf) ?*c.Elf32_Ehdr {
    const e = Elf.cast(elf orelse return null);

    if (e.kind != c.ELF_K_ELF) {
        seterrno(error.InvalidHandle);
        return null;
    } else if (e.is_64() or !(e.validEndianness() catch |err| {
        seterrno(err);
        return null;
    })) {
        seterrno(error.InvalidClass);
        return null;
    }

    return Elf.cast(elf orelse return null).state.elf32.ehdr orelse {
        seterrno(error.InvalidData);
        return null;
    };
}

/// Get the number of program headers in the ELF file.  If the file uses
/// more headers than can be represented in the e_phnum field of the ELF
/// header the information from the sh_info field in the zeroth section
/// header is used.
export fn elf32_getphdr(elf: ?*c.Elf) ?*c.Elf32_Phdr {
    _ = elf;
    return null;
}

/// Retrieve section header of ELFCLASS32 binary
export fn elf32_getshdr(scn: ?*c.Elf_Scn) ?*c.Elf32_Shdr {
    return if (scn) |s| Scn.cast(s).state.elf32.shdr else null;
}

// Create ELF header if none exists
export fn elf32_newehdr(elf: ?*c.Elf) ?*c.Elf32_Ehdr {
    _ = elf;
    return null;
}

/// Create ELF program header
export fn elf32_newphdr(elf: ?*c.Elf, cnt: usize) ?*c.Elf32_Phdr {
    _ = elf;
    _ = cnt;
    return null;
}

/// Convert data structure from to the representation in memory
/// represented by ELF file representation
export fn elf32_xlatetof(dest: ?*c.Elf_Data, src: ?*const c.Elf_Data, encode: c_uint) ?*c.Elf_Data {
    _ = dest;
    _ = src;
    _ = encode;
    return null;
}

/// Convert data structure from the representation in the file represented
/// by ELF to their memory representation
export fn elf32_xlatetom(dest: ?*c.Elf_Data, src: ?*const c.Elf_Data, encode: c_uint) ?*c.Elf_Data {
    _ = dest;
    _ = src;
    _ = encode;
    return null;
}

/// Compute simple checksum from permanent parts of the ELF file
export fn elf64_checksum(elf: ?*c.Elf) c_long {
    _ = elf;
    return -1;
}

/// Return size of array of COUNT elements of the type denoted by TYPE
/// in the external representation.  The binary class is taken from ELF.
/// The result is based on version VERSION of the ELF standard.
export fn elf64_fsize(elf_type: c.Elf_Type, count: usize, version: c_uint) usize {
    _ = elf_type;
    _ = count;
    _ = version;
    return 0;
}

/// Retrieve class-dependent object file header
export fn elf64_getehdr(elf: ?*c.Elf) ?*c.Elf64_Ehdr {
    const e = Elf.cast(elf orelse return null);

    if (e.kind != c.ELF_K_ELF) {
        seterrno(error.InvalidHandle);
        return null;
    } else if (!e.is_64() or !(e.validEndianness() catch |err| {
        seterrno(err);
        return null;
    })) {
        seterrno(error.InvalidClass);
        return null;
    }

    return Elf.cast(elf orelse return null).state.elf64.ehdr orelse {
        seterrno(error.InvalidData);
        return null;
    };
}

/// Retrieve class-dependent program header table
export fn elf64_getphdr(elf: ?*c.Elf) ?*c.Elf64_Phdr {
    _ = elf;
    return null;
}

/// Retrieve section header of ELFCLASS64 binary
export fn elf64_getshdr(scn: ?*c.Elf_Scn) ?*c.Elf64_Shdr {
    return if (scn) |s| Scn.cast(s).state.elf64.shdr else null;
}

/// Create ELF header if none exists
export fn elf64_newehdr(elf: ?*c.Elf) ?*c.Elf64_Ehdr {
    const e = Elf.cast(elf orelse return null);
    if (e.kind != c.ELF_K_ELF) {
        seterrno(error.InvalidHandle);
        return null;
    }

    if (!e.is_64()) {
        seterrno(error.InvalidClass);
        return null;
    }

    // TODO: what to initialize with?
    const ret = e.arena.allocator.create(c.Elf64_Ehdr) catch |err| {
        seterrno(err);
        return null;
    };

    e.state.elf64.ehdr = ret;
    return ret;
}

/// Create ELF program header
export fn elf64_newphdr(elf: ?*c.Elf, cnt: usize) ?*c.Elf64_Phdr {
    _ = elf;
    _ = cnt;
    return null;
}

// Convert data structure from to the representation in memory
// represented by ELF file representation
export fn elf64_xlatetof(dest: ?*c.Elf_Data, src: ?*const c.Elf_Data, encode: c_uint) ?*c.Elf_Data {
    _ = dest;
    _ = src;
    _ = encode;
    return null;
}

/// Convert data structure from the representation in the file represented
/// by ELF to their memory representation
export fn elf64_xlatetom(dest: ?*c.Elf_Data, src: ?*const c.Elf_Data, encode: c_uint) ?*c.Elf_Data {
    _ = dest;
    _ = src;
    _ = encode;
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
    _ = elf;
    _ = cmd;
    return null;
}

// Control ELF descriptor
export fn elf_cntl(elf: ?*c.Elf, cmd: c.Elf_Cmd) c_int {
    _ = elf;
    _ = cmd;
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
export fn elf_fill(fill: c_int) void {
    _ = fill;
}

/// Set or clear flags for ELF data
export fn elf_flagdata(data: ?*c.Elf_Data, cmd: c.Elf_Cmd, flags: c_uint) c_uint {
    _ = data;
    _ = cmd;
    _ = flags;
    return 0;
}

/// Set or clear flags for ELF header
export fn elf_flagehdr(elf: ?*c.Elf, cmd: c.Elf_Cmd, flags: c_uint) c_uint {
    _ = elf;
    _ = cmd;
    _ = flags;
    return 0;
}

/// Set or clear flags for ELF file
export fn elf_flagelf(elf: ?*c.Elf, cmd: c.Elf_Cmd, flags: c_uint) c_uint {
    _ = elf;
    _ = cmd;
    _ = flags;
    return 0;
}

/// Set or clear flags for ELF program header
export fn elf_flagphdr(elf: ?*c.Elf, cmd: c.Elf_Cmd, flags: c_uint) c_uint {
    _ = elf;
    _ = cmd;
    _ = flags;
    return 0;
}

/// Set or clear flags for ELF section
export fn elf_flagscn(scn: ?*c.Elf_Scn, cmd: c.Elf_Cmd, flags: c_uint) c_uint {
    _ = scn;
    _ = cmd;
    _ = flags;
    return 0;
}

/// Set or clear flags for ELF section header
export fn elf_flagshdr(scn: ?*c.Elf_Scn, cmd: c.Elf_Cmd, flags: c_uint) c_uint {
    _ = scn;
    _ = cmd;
    _ = flags;
    return 0;
}

/// Return header of archive
export fn elf_getarhdr(elf: ?*c.Elf) ?*c.Elf_Arhdr {
    _ = elf;
    return null;
}

export fn elf_getarsym(elf: ?*c.Elf, narsyms: *usize) ?*c.Elf_Arhdr {
    _ = elf;
    _ = narsyms;
    return null;
}

export fn elf_getbase(elf: ?*c.Elf) i64 {
    _ = elf;
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
    _ = elf;
    _ = nbytes;
    return null;
}

/// Get section at INDEX.
export fn elf_getscn(elf: ?*c.Elf, index: usize) ?*c.Elf_Scn {
    const e = Elf.cast(elf orelse return null);
    return if (index < e.sections.len) blk: {
        var it = e.sections.first;
        break :blk @ptrCast(*c.Elf_Scn, while (it) |node| : (it = it.?.next) {
            if (node.data.index == index)
                break &node.data;
        } else return null);
    } else null;
}

/// deprecated
export fn elf_getshnum(elf: ?*c.Elf, dst: ?*usize) c_int {
    _ = elf;
    _ = dst;
    return -1;
}

/// deprecated
export fn elf_getshstrndx(elf: ?*c.Elf, dst: ?*usize) c_int {
    _ = elf;
    _ = dst;
    return -1;
}

export fn elf_hash(string: [*:0]const u8) c_ulong {
    _ = string;
    return 0;
}

/// Determine what kind of file is associated with ELF.
export fn elf_kind(elf: ?*c.Elf) c.Elf_Kind {
    return Elf.cast(elf orelse return c.ELF_K_NONE).kind;
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

    return @ptrCast(*c.Elf, Elf.fromMemory(slice, null) catch |e| {
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
                .d_type = c.ELF_T_BYTE,
                .d_size = 0,
                .d_off = 0,
                .d_align = 0,
            },
        },
    };

    s.data_list.append(node);
    return &node.data.d;
}

fn newscn(elf: *Elf) Error!*Scn {
    const node = try allocator.create(SectionList.Node);
    errdefer allocator.destroy(node);

    node.* = .{
        .data = .{
            .elf = elf,
            .data_list = DataList{},
            .index = elf.sections.len,
            .state = if (elf.is_32()) .{
                .elf32 = .{
                    .shdr = blk: {
                        const ret = try elf.arena.allocator.create(c.Elf32_Shdr);
                        @memset(@ptrCast([*]u8, ret), 0, @sizeOf(c.Elf32_Shdr));
                        break :blk ret;
                    },
                },
            } else .{
                .elf64 = .{
                    .shdr = blk: {
                        const ret = try elf.arena.allocator.create(c.Elf64_Shdr);
                        @memset(@ptrCast([*]u8, ret), 0, @sizeOf(c.Elf64_Shdr));
                        break :blk ret;
                    },
                },
            },
        },
    };

    elf.sections.append(node);
    return &node.data;
}

/// Create a new section and append it at the end of the table
export fn elf_newscn(elf: ?*c.Elf) ?*c.Elf_Scn {
    const e = Elf.cast(elf orelse return null);
    return @ptrCast(*c.Elf_Scn, newscn(e) catch |err| {
        seterrno(err);
        return null;
    });
}

/// Advance archive descriptor to next element
export fn elf_next(elf: ?*c.Elf) c.Elf_Cmd {
    _ = elf;
    return c.ELF_C_NULL;
}

/// Get section with next section index.
export fn elf_nextscn(elf: ?*c.Elf, scn: ?*c.Elf_Scn) ?*c.Elf_Scn {
    const e = Elf.cast(elf orelse return null);
    const s = Scn.cast(scn orelse return if (e.sections.first) |first| if (first.next) |node| @ptrCast(*c.Elf_Scn, &node.data) else null else null);
    const node = @fieldParentPtr(SectionList.Node, "data", s);

    return if (node.next) |next| @ptrCast(*c.Elf_Scn, &next.data) else null;
}

export fn elf_rand(elf: ?*c.Elf, offset: usize) usize {
    _ = elf;
    _ = offset;
    return 0;
}

/// Get uninterpreted section content.
export fn elf_rawdata(scn: ?*c.Elf_Scn, data: ?*c.Elf_Data) ?*c.Elf_Data {
    //const s = Scn.cast(scn orelse {
    //    seterrno(error.InvalidHandle);
    //    return null;
    //});

    //if (s.elf.kind != .ELF_K_ELF) {
    //    seterrno(error.InvalidHandle);
    //    return null;
    //}

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

    // TODO
    //return null;
}

export fn elf_rawfile(elf: ?*c.Elf, nbytes: *usize) ?[*]u8 {
    _ = elf;
    _ = nbytes;
    return null;
}

/// Return pointer to string at OFFSET in section INDEX
export fn elf_strptr(elf: ?*c.Elf, index: usize, offset: usize) ?[*:0]const u8 {
    const e = Elf.cast(elf orelse return null);
    var it = e.sections.first;
    return while (it) |node| : (it = it.?.next) {
        if (node.data.index == index) {
            const scn = node.data;
            if (offset >= scn.size()) {
                seterrno(error.InvalidIndex);
                return null;
            }

            const data = e.memory[scn.offset() .. scn.offset() + scn.size()];
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
    switch (cmd) {
        c.ELF_C_NULL, c.ELF_C_WRITE, c.ELF_C_WRITE_MMAP => {},
        else => {
            seterrno(error.InvalidCommand);
            return -1;
        },
    }

    const e = Elf.cast(elf orelse return -1);
    if (e.kind != c.ELF_K_ELF) {
        seterrno(error.InvalidHandle);
        return -1;
    }

    // Make sure we have an ELF header
    return -1;
}

/// Coordinate ELF library and application versions
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

/// Compute simple checksum from permanent parts of the ELF file
export fn gelf_checksum(elf: ?*c.Elf) c_long {
    _ = elf;
    return -1;
}

/// Return size of array of COUNT elements of the type denoted by TYPE
/// in the external representation.  The binary class is taken from ELF.
/// The result is based on version VERSION of the ELF standard.
export fn gelf_fsize(elf: ?*c.Elf, elf_type: c.Elf_Type, count: usize, version: c_uint) usize {
    _ = elf;
    _ = elf_type;
    _ = count;
    _ = version;
    return 0;
}

/// Get class of the file associated with ELF
export fn gelf_getclass(elf: ?*c.Elf) c_int {
    const e = Elf.cast(elf orelse return c.ELFCLASSNONE);
    return if (e.kind != c.ELF_K_ELF)
        c.ELFCLASSNONE
    else switch (e.state) {
        .elf32 => c.ELFCLASS32,
        .elf64 => c.ELFCLASS64,
    };
}

/// Get information from dynamic table at the given index
export fn gelf_getdyn(data: ?*c.Elf_Data, ndx: c_int, dst: ?*c.GElf_Dyn) ?*c.GElf_Dyn {
    _ = data;
    _ = ndx;
    _ = dst;
    return null;
}

/// Retrieve object file header.
export fn gelf_getehdr(elf: ?*c.Elf, dst: ?*c.GElf_Ehdr) ?*c.GElf_Ehdr {
    if (elf == null or dst == null)
        return null;

    const e = Elf.cast(elf.?);
    if (e.kind != c.ELF_K_ELF) {
        seterrno(error.InvalidHandle);
        return null;
    }

    if (e.is_32()) {
        const ehdr = e.state.elf32.ehdr orelse {
            seterrno(error.InvalidData);
            return null;
        };

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
        dst.?.* = (e.state.elf64.ehdr orelse {
            seterrno(error.InvalidData);
            return null;
        }).*;
    }

    return dst.?;
}

/// Get move structure at the given index
export fn gelf_getmove(data: ?*c.Elf_Data, ndx: c_int, dst: ?*c.GElf_Move) ?*c.GElf_Move {
    _ = data;
    _ = ndx;
    _ = dst;
    return null;
}

/// Retrieve program header table entry
export fn gelf_getphdr(elf: ?*c.Elf, ndr: c_int, dst: ?*c.GElf_Phdr) ?*c.GElf_Phdr {
    _ = elf;
    _ = ndr;
    _ = dst;
    return null;
}

/// Retrieve REL relocation info at the given index.
export fn gelf_getrel(data: ?*c.Elf_Data, ndx: c_int, dst: ?*c.GElf_Rel) ?*c.GElf_Rel {
    const d = dst orelse return null;
    const data_scn = @fieldParentPtr(
        ScnData,
        "d",
        @ptrCast(*c.Elf_Data, data orelse return null),
    );

    if (data_scn.d.d_type != c.ELF_T_REL) {
        seterrno(error.InvalidHandle);
        return null;
    }

    if (data_scn.s.elf.is_32()) {
        var rels: []c.Elf32_Rel = undefined;
        rels.ptr = @ptrCast([*]c.Elf32_Rel, @alignCast(@alignOf([*]c.Elf32_Rel), data_scn.d.d_buf));
        rels.len = data_scn.d.d_size / @sizeOf(c.Elf32_Rel);

        if (ndx >= rels.len or ndx < 0) {
            seterrno(error.InvalidIndex);
            return null;
        }

        const rel = &rels[@intCast(usize, ndx)];
        d.r_offset = rel.r_offset;
        d.r_info = (rel.r_info << 24) + (rel.r_info & 0xff);
    } else {
        var rels: []c.Elf64_Rel = undefined;
        rels.ptr = @ptrCast([*]c.Elf64_Rel, @alignCast(@alignOf([*]c.Elf64_Rel), data_scn.d.d_buf));
        rels.len = data_scn.d.d_size / @sizeOf(c.Elf64_Rel);

        if (ndx >= rels.len or ndx < 0) {
            seterrno(error.InvalidIndex);
            return null;
        }

        d.* = rels[@intCast(usize, ndx)];
    }

    return d;
}

/// Retrieve RELA relocation info at the given index
export fn gelf_getrela(data: ?*c.Elf_Data, ndx: c_int, dst: ?*c.GElf_Rela) ?*c.GElf_Rela {
    _ = data;
    _ = ndx;
    _ = dst;
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
    const data_scn = @fieldParentPtr(ScnData, "d", data orelse {
        return null;
    });
    const d = dst orelse {
        return null;
    };

    if (data_scn.d.d_type != c.ELF_T_SYM) {
        seterrno(error.InvalidHandle);
        return null;
    }

    if (data_scn.s.elf.is_32()) {
        var syms: []c.Elf32_Sym = undefined;
        syms.ptr = @ptrCast([*]c.Elf32_Sym, @alignCast(@alignOf([*]c.Elf32_Sym), data_scn.d.d_buf));
        syms.len = data_scn.d.d_size / @sizeOf(c.Elf32_Sym);

        if (ndx >= syms.len and ndx > 0) {
            seterrno(error.InvalidIndex);
            return null;
        }

        const sym = &syms[@intCast(usize, ndx)];
        d.st_name = sym.st_name;
        d.st_info = sym.st_info;
        d.st_other = sym.st_other;
        d.st_shndx = sym.st_shndx;
        d.st_value = sym.st_value;
        d.st_size = sym.st_size;
    } else {
        var syms: []c.GElf_Sym = undefined;
        syms.ptr = @ptrCast([*]c.GElf_Sym, @alignCast(@alignOf([*]c.GElf_Sym), data_scn.d.d_buf));
        syms.len = data_scn.d.d_size / @sizeOf(c.GElf_Sym);

        if (ndx >= syms.len and ndx > 0) {
            seterrno(error.InvalidIndex);
            return null;
        }

        d.* = syms[@intCast(usize, ndx)];
    }

    {
        const e = data_scn.s.elf;
        var strndx: usize = 0;

        const rc = elf_getshdrstrndx(@ptrCast(*c.Elf, e), &strndx);
        if (rc != 0) @panic("no idea bruh");
    }

    return d;
}

/// Retrieve additional symbol information from the symbol table at the
/// given index
export fn gelf_getsyminfo(data: ?*c.Elf_Data, ndx: c_int, dst: ?*c.GElf_Syminfo) ?*c.GElf_Syminfo {
    _ = data;
    _ = ndx;
    _ = dst;
    return null;
}

/// Retrieve symbol information and separate section index from the
/// symbol table at the given index
export fn gelf_getsymshndx(symdata: ?*c.Elf_Data, shndxdata: ?*c.Elf_Data, ndx: c_int, sym: ?*c.GElf_Sym, xshndx: ?*c.Elf32_Word) ?*c.GElf_Sym {
    _ = symdata;
    _ = shndxdata;
    _ = ndx;
    _ = sym;
    _ = xshndx;
    return null;
}

/// Retrieve additional symbol version definition information at given
/// offset
export fn gelf_getverdaux(data: ?*c.Elf_Data, offset: c_int, dst: ?*c.GElf_Verdef) ?*c.GElf_Verdef {
    _ = data;
    _ = offset;
    _ = dst;
    return null;
}

/// Retrieve symbol version definition information at given offset
export fn gelf_getverdef(data: ?*c.Elf_Data, offset: c_int, dsp: ?*c.GElf_Verdef) ?*c.GElf_Verdef {
    _ = data;
    _ = offset;
    _ = dsp;
    return null;
}

/// Retrieve additional required symbol version information at given offset
export fn gelf_getvernaux(data: ?*c.Elf_Data, offset: c_int, dst: ?*c.GElf_Vernaux) ?*c.GElf_Vernaux {
    _ = data;
    _ = offset;
    _ = dst;
    return null;
}

/// Retrieve required symbol version information at given offset
export fn gelf_getverneed(data: ?*c.Elf_Data, offset: c_int, dst: ?*c.GElf_Verneed) ?*c.GElf_Verneed {
    _ = data;
    _ = offset;
    _ = dst;
    return null;
}

/// Retrieve symbol version information at given index
export fn gelf_getversym(data: ?*c.Elf_Data, ndx: c_int, dst: ?*c.GElf_Versym) ?*c.GElf_Versym {
    _ = data;
    _ = ndx;
    _ = dst;
    return null;
}

/// Create new ELF header if none exists.  Creates an Elf32_Ehdr if CLASS
/// is ELFCLASS32 or an Elf64_Ehdr if CLASS is ELFCLASS64.  Returns NULL
/// on error.
export fn gelf_newehdr(elf: ?*c.Elf, class: c_int) ?*c_void {
    _ = elf;
    _ = class;
    return null;
}

/// Create new program header with PHNUM entries.  Creates either an
/// Elf32_Phdr or an Elf64_Phdr depending on whether the given ELF is
/// ELFCLASS32 or ELFCLASS64.  Returns NULL on error.
export fn gelf_newphdr(elf: ?*c.Elf, cnt: usize) ?*c_void {
    _ = elf;
    _ = cnt;
    return null;
}

/// Update information in dynamic table at the given index
export fn gelf_update_dyn(dst: [*c]c.Elf_Data, ndx: c_int, src: [*c]c.GElf_Dyn) c_int {
    _ = dst;
    _ = ndx;
    _ = src;
    return -1;
}

/// Update the ELF header
export fn gelf_update_ehdr(elf: ?*c.Elf, src: [*c]c.GElf_Ehdr) c_int {
    _ = elf;
    _ = src;
    return -1;
}

/// Update move structure at the given index
export fn gelf_update_move(data: [*c]c.Elf_Data, ndx: c_int, src: [*c]c.GElf_Move) c_int {
    _ = data;
    _ = ndx;
    _ = src;
    return -1;
}

/// Update the program header
export fn gelf_update_phdr(elf: ?*c.Elf, ndx: c_int, src: [*c]c.GElf_Phdr) c_int {
    _ = elf;
    _ = ndx;
    _ = src;
    return -1;
}

/// Update REL relocation information at given index
export fn gelf_update_rel(dst: [*c]c.Elf_Data, ndx: c_int, src: [*c]c.GElf_Rel) c_int {
    _ = dst;
    _ = ndx;
    _ = src;
    return -1;
}

/// Update RELA relocation information at given index
export fn gelf_update_rela(dst: [*c]c.Elf_Data, ndx: c_int, src: [*c]c.GElf_Rela) c_int {
    _ = dst;
    _ = ndx;
    _ = src;
    return -1;
}

/// Update section header
export fn gelf_update_shdr(scn: ?*c.Elf_Scn, src: [*c]c.GElf_Shdr) c_int {
    _ = scn;
    _ = src;
    return -1;
}

/// Update symbol information in the symbol table at the given index
export fn gelf_update_sym(data: [*c]c.Elf_Data, ndx: c_int, src: [*c]c.GElf_Sym) c_int {
    _ = data;
    _ = ndx;
    _ = src;
    return -1;
}

/// Update additional symbol information in the symbol table at the
/// given index
export fn gelf_update_syminfo(data: [*c]c.Elf_Data, ndx: c_int, src: [*c]c.GElf_Syminfo) c_int {
    _ = data;
    _ = ndx;
    _ = src;
    return -1;
}

/// Update symbol information and separate section index in the symbol
/// table at the given index
export fn gelf_update_symshndx(symdata: [*c]c.Elf_Data, shndxdata: [*c]c.Elf_Data, ndx: c_int, sym: [*c]c.GElf_Sym, xshndx: c.Elf32_Word) c_int {
    _ = symdata;
    _ = shndxdata;
    _ = ndx;
    _ = sym;
    _ = xshndx;
    return -1;
}

/// Update additional symbol version definition information
export fn gelf_update_verdaux(data: [*c]c.Elf_Data, offset: c_int, src: [*c]c.GElf_Verdaux) c_int {
    _ = data;
    _ = offset;
    _ = src;
    return -1;
}

/// Update symbol version definition information
export fn gelf_update_verdef(data: [*c]c.Elf_Data, offset: c_int, src: [*c]c.GElf_Verdef) c_int {
    _ = data;
    _ = offset;
    _ = src;
    return -1;
}

/// Update additional required symbol version information
export fn gelf_update_vernaux(data: [*c]c.Elf_Data, offset: c_int, src: [*c]c.GElf_Vernaux) c_int {
    _ = data;
    _ = offset;
    _ = src;
    return -1;
}

/// Update required symbol version information
export fn gelf_update_verneed(data: [*c]c.Elf_Data, offset: c_int, src: [*c]c.GElf_Verneed) c_int {
    _ = data;
    _ = offset;
    _ = src;
    return -1;
}

/// Update symbol version information
export fn gelf_update_versym(data: [*c]c.Elf_Data, ndx: c_int, src: [*c]c.GElf_Versym) c_int {
    _ = data;
    _ = ndx;
    _ = src;
    return -1;
}

/// Convert data structure from to the representation in memory
/// represented by ELF file representation
export fn gelf_xlatetof(elf: ?*c.Elf, dst: ?*c.Elf_Data, src: ?*const c.Elf_Data, encode: c_uint) ?*c.Elf_Data {
    _ = elf;
    _ = dst;
    _ = src;
    _ = encode;
    return null;
}

/// Convert data structure from the representation in the file represented
/// by ELF to their memory representation
export fn gelf_xlatetom(elf: ?*c.Elf, dst: ?*c.Elf_Data, src: ?*const c.Elf_Data, encode: c_uint) ?*c.Elf_Data {
    _ = elf;
    _ = dst;
    _ = src;
    _ = encode;
    return null;
}

/// Get specified entries from file
export fn nlist(filename: [*c]const u8, nl: [*c]c.struct_nlist) c_int {
    _ = filename;
    _ = nl;
    return -1;
}

/// Get library from table at the given index
export fn gelf_getlib(data: [*c]c.Elf_Data, ndx: c_int, dst: [*c]c.GElf_Lib) [*c]c.GElf_Lib {
    _ = data;
    _ = ndx;
    _ = dst;
    return null;
}

/// Update library in table at the given index
export fn gelf_update_lib(data: [*c]c.Elf_Data, ndx: c_int, src: [*c]c.GElf_Lib) c_int {
    _ = data;
    _ = ndx;
    _ = src;
    return -1;
}

/// Get section at OFFSET
export fn elf32_offscn(elf: ?*c.Elf, offset: c.Elf32_Off) ?*c.Elf_Scn {
    _ = elf;
    _ = offset;
    return null;
}

/// Get section at OFFSET
export fn elf64_offscn(elf: ?*c.Elf, offset: c.Elf64_Off) ?*c.Elf_Scn {
    _ = elf;
    _ = offset;
    return null;
}

/// Get section at OFFSET
export fn gelf_offscn(elf: ?*c.Elf, offset: c.GElf_Off) ?*c.Elf_Scn {
    _ = elf;
    _ = offset;
    return null;
}

/// Return offset in archive for current file ELF
export fn elf_getaroff(elf: ?*c.Elf) i64 {
    _ = elf;
    return -1;
}

/// Compute hash value using the GNU-specific hash function
export fn elf_gnu_hash(string: [*c]const u8) c_ulong {
    _ = string;
    return 0;
}

/// Get data translated from a chunk of the file contents as section data
/// would be for TYPE.  The resulting Elf_Data pointer is valid until
/// elf_end (ELF) is called.
export fn elf_getdata_rawchunk(elf: ?*c.Elf, offset: i64, size: usize, typ: c.Elf_Type) [*c]c.Elf_Data {
    _ = elf;
    _ = offset;
    _ = size;
    _ = typ;
    return null;
}

/// Get auxv entry at the given index
export fn gelf_getauxv(data: [*c]c.Elf_Data, ndx: c_int, dst: [*c]c.GElf_auxv_t) [*c]c.GElf_auxv_t {
    _ = data;
    _ = ndx;
    _ = dst;
    return null;
}

/// Update auxv entry at the given index
export fn gelf_update_auxv(data: [*c]c.Elf_Data, ndx: c_int, src: [*c]c.GElf_auxv_t) c_int {
    _ = data;
    _ = ndx;
    _ = src;
    return -1;
}

/// Get note header at the given offset into the data, and the offsets of
/// the note's name and descriptor data.  Returns the offset of the next
/// note header, or 0 for an invalid offset or corrupt note header.
export fn gelf_getnote(data: [*c]c.Elf_Data, offset: usize, result: [*c]c.GElf_Nhdr, name_offset: [*c]usize, desc_offset: [*c]usize) usize {
    _ = data;
    _ = offset;
    _ = result;
    _ = name_offset;
    _ = desc_offset;
    return 0;
}

/// Get the section index of the extended section index table for the
/// given symbol table
export fn elf_scnshndx(scn: ?*c.Elf_Scn) c_int {
    _ = scn;
    return -1;
}

/// Get the number of sections in the ELF file.  If the file uses more
/// sections than can be represented in the e_shnum field of the ELF
/// header the information from the sh_size field in the zeroth section
/// header is used.
export fn elf_getshdrnum(elf: ?*c.Elf, dst: ?*usize) c_int {
    if (elf == null or dst == null)
        return -1;

    dst.?.* = Elf.cast(elf.?).state.shnum() catch |e| {
        seterrno(e);
        return -1;
    };

    return 0;
}

/// Get the section index of the section header string table in the ELF
/// file.  If the index cannot be represented in the e_shstrndx field of
/// the ELF header the information from the sh_link field in the zeroth
/// section header is used.
export fn elf_getshdrstrndx(elf: ?*c.Elf, dst: ?*usize) c_int {
    if (elf == null or dst == null)
        return -1;

    dst.?.* = Elf.cast(elf.?).state.shstrndx() catch |e| {
        seterrno(e);
        return -1;
    };

    return 0;
}

/// Get the number of program headers in the ELF file.  If the file uses
/// more headers than can be represented in the e_phnum field of the ELF
/// header the information from the sh_info field in the zeroth section
/// header is used.
export fn elf_getphdrnum(elf: ?*c.Elf, dst: [*c]usize) c_int {
    _ = elf;
    _ = dst;
    return -1;
}

/// Returns compression header for a section if section data is
/// compressed.  Returns NULL and sets elf_errno if the section isn't
/// compressed or an error occurred.
export fn elf32_getchdr(scn: ?*c.Elf_Scn) [*c]c.Elf32_Chdr {
    _ = scn;
    return null;
}

/// Returns compression header for a section if section data is
/// compressed.  Returns NULL and sets elf_errno if the section isn't
/// compressed or an error occurred.
export fn elf64_getchdr(scn: ?*c.Elf_Scn) [*c]c.Elf64_Chdr {
    _ = scn;
    return null;
}

/// Get compression header of section if any.  Returns NULL and sets
/// elf_errno if the section isn't compressed or an error occurred.
export fn gelf_getchdr(scn: ?*c.Elf_Scn, dst: [*c]c.GElf_Chdr) [*c]c.GElf_Chdr {
    _ = scn;
    _ = dst;
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
    _ = scn;
    _ = typ;
    _ = flags;
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
    _ = scn;
    _ = compress;
    _ = flags;
    return -1;
}
