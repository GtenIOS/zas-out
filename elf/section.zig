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
    data: std.ArrayList(u8),
    type: SectionType,
    offset: u64,
    vaddr: u64,
    padding_bytes_size: u16,
    const Self = @This();

    pub fn initFromText(sec_data: std.ArrayList(u8), align_size: u16, offset: u64, vaddr: u64) Self {
        var padding_bytes_size: u16 = 0;
        if (align_size >= 2) {
            padding_bytes_size = align_size - @intCast(u16, (offset + sec_data.items.len) % align_size);
        }
        return Self{ .name = ".text", .flags = @enumToInt(SectionFlag.Exe) | @enumToInt(SectionFlag.Read), .data = sec_data, .type = .Loadable, .offset = offset, .vaddr = vaddr, .padding_bytes_size = padding_bytes_size };
    }

    pub fn initFromData(sec_data: std.ArrayList(u8), align_size: u16, offset: u64, vaddr: u64) Self {
        var padding_bytes_size: u16 = 0;
        if (align_size >= 2) {
            padding_bytes_size = align_size - @intCast(u16, sec_data.items.len % align_size);
        }
        return Self{ .name = ".data", .flags = @enumToInt(SectionFlag.Write) | @enumToInt(SectionFlag.Read), .data = sec_data, .type = .Loadable, .offset = offset, .vaddr = vaddr, .padding_bytes_size = padding_bytes_size };
    }

    pub fn initFromRoData(sec_data: std.ArrayList(u8), align_size: u16, offset: u64, vaddr: u64) Self {
        var padding_bytes_size: u16 = 0;
        if (align_size >= 2) {
            padding_bytes_size = align_size - @intCast(u16, (offset + sec_data.items.len) % align_size);
        }
        return Self{ .name = ".rodata", .flags = @enumToInt(SectionFlag.Read), .data = sec_data, .type = .Loadable, .offset = offset, .vaddr = vaddr, .padding_bytes_size = padding_bytes_size };
    }

    pub inline fn alignToSize(self: *Self, alignment: u16) !void {
        if (alignment < 2) return;
        const rem_bytes = alignment - (self.data.items.len % alignment);
        if (rem_bytes > 0) try self.data.appendNTimes(0, rem_bytes);
    }

    pub inline fn toPhtEntry(self: Self, align_size: u16) Elf64PhtEntry {
        return Elf64PhtEntry{ .segment_type = @enumToInt(self.type), .flags = self.flags, .offset = self.offset, .vaddr = self.vaddr, .paddr = self.vaddr, .size_in_file = self.data.items.len, .size_in_mem = self.data.items.len, .p_align = align_size };
    }
};
