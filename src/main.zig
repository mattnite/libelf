const std = @import("std");
const c = @cImport({
    @cInclude("gelf.h");
    @cInclude("nlist.h");
});

export fn elf32_checksum(elf: ?*c.Elf) c_long {
    return -1;
}

export fn elf32_fsize(elf_type: c.Elf_Type, count: usize, version: c_uint) usize {
    return 0;
}

export fn elf32_getehdr(elf: ?*c.Elf) ?*c.Elf32_Ehdr {
    return null;
}

export fn elf32_getphdr(elf: ?*c.Elf) ?*c.Elf32_Phdr {
    return null;
}

export fn elf32_getshdr(scn: ?*c.Elf_Scn) ?*c.Elf32_Shdr {
    return null;
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

// libbpf
export fn elf64_getehdr(elf: ?*c.Elf) ?*c.Elf64_Ehdr {
    return null;
}

export fn elf64_getphdr(elf: ?*c.Elf) ?*c.Elf64_Phdr {
    return null;
}

// libbpf
export fn elf64_getshdr(scn: ?*c.Elf_Scn) ?*c.Elf64_Shdr {
    return null;
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

// libbpf
export fn elf_begin(fd: c_int, cmd: c.Elf_Cmd, ref: ?*c.Elf) ?*c.Elf {
    return null;
}

export fn elf_clone(elf: ?*c.Elf, cmd: c.Elf_Cmd) ?*c.Elf {
    return null;
}

export fn elf_cntl(elf: ?*c.Elf, cmd: c.Elf_Cmd) c_int {
    return -1;
}

// libbpf
export fn elf_end(elf: ?*c.Elf) c_int {
    return -1;
}

// libbpf
export fn elf_errmsg(err: c_int) ?[*:0]const u8 {
    return null;
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

// libbpf
export fn elf_getscn(elf: ?*c.Elf, index: usize) ?*c.Elf_Scn {
    return null;
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
    return .ELF_K_NONE;
}

// libbpf
export fn elf_memory(image: [*]u8, size: usize) ?*c.Elf {
    return null;
}

// libbpf
export fn elf_ndxscn(scn: ?*c.Elf_Scn) usize {
    return 0;
}

// libbpf
export fn elf_newdata(scn: ?*c.Elf_Scn) ?*c.Elf_Data {
    return null;
}

// libbpf
export fn elf_newscn(elf: ?*c.Elf) ?*c.Elf_Scn {
    return null;
}

// libbpf
export fn elf_next(elf: ?*c.Elf) c.Elf_Cmd {
    return .ELF_C_NULL;
}

// libbpf
export fn elf_nextscn(elf: ?*c.Elf, scn: ?*c.Elf_Scn) ?*c.Elf_Scn {
    return null;
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

// libbpf
export fn elf_version(version: c_uint) c_uint {
    return 0;
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

// libbpf
export fn gelf_getehdr(elf: ?*c.Elf, dst: ?*c.GElf_Ehdr) ?*c.GElf_Ehdr {
    return null;
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

// libbpf
export fn gelf_getshdr(scn: ?*c.Elf_Scn, dst: ?*c.GElf_Shdr) ?*c.GElf_Shdr {
    return null;
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

export fn elf_getshdrnum(__elf: ?*c.Elf, __dst: [*c]usize) c_int {
    return -1;
}

// libbpf
export fn elf_getshdrstrndx(__elf: ?*c.Elf, __dst: [*c]usize) c_int {
    return -1;
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
