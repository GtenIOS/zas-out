const std = @import("std");
const LdCmd = @import("ldcmd.zig");
const SectionType = enum {
    Text,
    Const,
    Data,
    Bss,
};

pub const Section = struct {
    type: SectionType,
    data: ?std.ArrayList(u8),
    offset: u64,
    vaddr: u64,
    res_size: ?usize = null,

    const Self = @This();
    pub fn initText(data: std.ArrayList(u8), offset: u64, vaddr: u64) Self {
        return Self { .type = .Text, .data = data, .offset = offset, .vaddr = vaddr };
    }

    pub fn initConst(data: std.ArrayList(u8), offset: u64, vaddr: u64) Self {
        return Self { .type = .Const, .data = data, .offset = offset, .vaddr = vaddr };
    }

    pub fn initData(data: std.ArrayList(u8), offset: u64, vaddr: u64) Self {
        return Self { .type = .Data, .data = data, .offset = offset, .vaddr = vaddr };
    }

    pub fn initBss(vaddr: u64, res_size: usize) Self {
        if (res_size == 0) { @panic("Size must not be zero"); }
        return Self { .type = .Bss, .data = null, .offset = 0, .vaddr = vaddr, .res_size = res_size };
    }

    pub fn toHeader(self: Self) SectionHeader {
        const size: usize = blk: {
            if (self.data) |data| { break :blk data.items.len; } else { break :blk self.res_size orelse 0; }
        };
        return switch (self.type) {
            .Text => SectionHeader.initText(self.vaddr, size, @intCast(u32, self.offset)),
            .Const => SectionHeader.initConst(self.vaddr, size, @intCast(u32, self.offset)),
            .Data => SectionHeader.initData(self.vaddr, size, @intCast(u32, self.offset)),
            .Bss => SectionHeader.initBss(self.vaddr, size, @intCast(u32, self.offset)),
        };
    }
};

const sec_text: [16]u8 = [16]u8 { '_', '_', 't', 'e', 'x', 't', 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };
const sec_const: [16]u8 = [16]u8 { '_', '_', 'c', 'o', 'n', 's', 't', 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };
const sec_data: [16]u8 = [16]u8 { '_', '_', 'd', 'a', 't', 'a', 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };
const sec_bss: [16]u8 = [16]u8 { '_', '_', 'b', 's', 's', 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };
const s_attr_pure_instrs: u32 = 0x80000000;
const s_attr_some_instrs: u32 = 0x00000400;
const s_zerofill: u32 = 0x1;
pub const SectionHeader = struct {
    name: [16]u8,
    seg_name: [16]u8,
    addr: u64,
    size: u64,
    offset: u32,
    alignment: u32 = 0,
    reloc_ofst: u32 = 0,
    no_of_relocs: u32 = 0,
    flags: u32 = 0,
    res1: u32 = 0,
    res2: u32 = 0,
    res3: u32 = 0,

    const Self = @This();
    pub fn initText(addr: u64, size: u64, offset: u32) Self {
        return Self { .name = sec_text, .seg_name = LdCmd.seg_text, .addr = addr, .size = size, .offset = offset, .flags = s_attr_pure_instrs | s_attr_some_instrs };
    }

    pub fn initConst(addr: u64, size: u64, offset: u32) Self {
        return Self { .name = sec_const, .seg_name = LdCmd.seg_text, .addr = addr, .size = size, .offset = offset };
    }

    pub fn initData(addr: u64, size: u64, offset: u32) Self {
        return Self { .name = sec_data, .seg_name = LdCmd.seg_data, .addr = addr, .size = size, .offset = offset };
    }

    pub fn initBss(addr: u64, size: u64, offset: u32) Self {
        return Self { .name = sec_bss, .seg_name = LdCmd.seg_data, .addr = addr, .size = size, .offset = offset, .flags = s_zerofill };
    }
};
