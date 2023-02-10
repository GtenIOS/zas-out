const std = @import("std");
const CommSection = @import("common").section.Section;
const Elf64PhtEntry = @import("elfhdr.zig").Elf64PhtEntry;
pub const SectionFlag = enum(u3) {
    Exe = 1,
    Write = 2,
    Read = 4,
};

pub const SectionType = enum(u4) {
    Loadable = 1,
    DynLinkInfo,
};

pub const Section = struct {
    name: []const u8,
    flags: u8, // Must be a combination of `SectionFlag`
    data: ?std.ArrayList(u8),
    res_size: ?usize = null,
    type: SectionType,
    offset: u64,
    vaddr: u64,
    padding_bytes_size: u16,
    const Self = @This();

    pub fn initFromText(sec_data: std.ArrayList(u8), data_size: usize, align_size: u16, offset: u64, vaddr: u64) Self {
        var padding_bytes_size: u16 = 0;
        if (align_size >= 2) {
            padding_bytes_size = align_size - @intCast(u16, (offset + data_size) % align_size);
        }
        return Self{ .name = ".text", .flags = @enumToInt(SectionFlag.Exe) | @enumToInt(SectionFlag.Read), .data = sec_data, .type = .Loadable, .offset = offset, .vaddr = vaddr, .padding_bytes_size = padding_bytes_size };
    }

    pub fn initFromData(sec_data: ?std.ArrayList(u8), data_size: usize, align_size: u16, offset: u64, vaddr: u64) Self {
        var padding_bytes_size: u16 = 0;
        if (align_size >= 2) {
            padding_bytes_size = align_size - @intCast(u16, data_size % align_size);
        }
        return Self{ .name = ".data", .flags = @enumToInt(SectionFlag.Write) | @enumToInt(SectionFlag.Read), .data = sec_data, .type = .Loadable, .offset = offset, .vaddr = vaddr, .padding_bytes_size = padding_bytes_size };
    }

    pub fn initFromRoData(sec_data: ?std.ArrayList(u8), data_size: usize, align_size: u16, offset: u64, vaddr: u64) Self {
        var padding_bytes_size: u16 = 0;
        if (align_size >= 2) {
            padding_bytes_size = align_size - @intCast(u16, (offset + data_size) % align_size);
        }
        return Self{ .name = ".rodata", .flags = @enumToInt(SectionFlag.Read), .data = sec_data, .type = .Loadable, .offset = offset, .vaddr = vaddr, .padding_bytes_size = padding_bytes_size };
    }

    pub fn initFromBss(res_size: usize, offset: u64, vaddr: u64) Self {
        return Self{ .name = ".bss", .flags = @enumToInt(SectionFlag.Write) | @enumToInt(SectionFlag.Read), .data = null, .res_size = res_size, .type = .Loadable, .offset = offset, .vaddr = vaddr, .padding_bytes_size = 0 };
    }

    pub inline fn alignToSize(self: *Self, alignment: u16) !void {
        if (alignment < 2) return;
        const rem_bytes = alignment - (self.data.items.len % alignment);
        if (rem_bytes > 0) try self.data.appendNTimes(0, rem_bytes);
    }

    pub inline fn toPhtEntry(self: Self, align_size: u16) Elf64PhtEntry {
        const file_sz = blk: {
            if (self.data) |data| { break :blk data.items.len; } else { break :blk 0; }
        };
        const res_sz = self.res_size orelse 0;
        return Elf64PhtEntry{ .segment_type = @enumToInt(self.type), .flags = self.flags, .offset = self.offset, .vaddr = self.vaddr, .paddr = self.vaddr, .size_in_file = file_sz, .size_in_mem = file_sz + res_sz, .p_align = align_size };
    }
};
