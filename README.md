# libelf in zig

`libelf` as part of [elfutils](https://sourceware.org/elfutils/) has been a
major pain in the ass. All I want to do is make statically compiled programs
that use eBPF (libbpf depends on libelf), and elfutils's build system and use of
gnu extensions make it difficult/next to impossible to compile with clang (I'm
addicted to zig's toolchain because I can target `x86_64-linux-musl` from
anywhere and it just works). A lot of other people seem to have the exact same
issue so here we are shaving yaks and reimplementing the damn lib in zig and
exporting it to the same fucking C ABI.

# Dependencies & features

The aim is to just have one full featured build, I'm not sure if missing
features breaks other software but let's find out!

- -lz
- -lbz2
- -llzma
- -lzstd
