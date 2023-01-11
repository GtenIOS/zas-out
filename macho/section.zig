const std = @import("std");
const CommSection = @import("common").section.Section;
const LoadCmdSeg = @import("ldcmd.zig").LoadCmdSeg;

const SectionType = enum {
    Text,
    Data,
    Rodata,
};

pub const Section = struct {
    type: SectionType,
    data: std.ArrayList(u8),
    ovlp_ofst: ?u64 = null,
    offset: u64,
    vaddr: u64,
    padding_bytes_size: u16,
    const Self = @This();

    pub fn initFromText(sec_data: std.ArrayList(u8), align_size: u16, ovlp_ofst: u64, offset: u64, vaddr: u64) Self {
        var padding_bytes_size: u16 = 0;
        if (align_size >= 2) {
            padding_bytes_size = align_size - @intCast(u16, (ovlp_ofst + sec_data.items.len) % align_size);
        }
        return Self{ .type = .Text, .data = sec_data, .ovlp_ofst = ovlp_ofst, .offset = offset, .vaddr = vaddr, .padding_bytes_size = padding_bytes_size };
    }

    pub fn initFromData(sec_data: std.ArrayList(u8), align_size: u16, offset: u64, vaddr: u64) Self {
        var padding_bytes_size: u16 = 0;
        if (align_size >= 2) {
            padding_bytes_size = align_size - @intCast(u16, sec_data.items.len % align_size);
        }
        return Self{ .type = .Data, .data = sec_data, .offset = offset, .vaddr = vaddr, .padding_bytes_size = padding_bytes_size };
    }

    pub fn initFromRoData(sec_data: std.ArrayList(u8), align_size: u16, offset: u64, vaddr: u64) Self {
        var padding_bytes_size: u16 = 0;
        if (align_size >= 2) {
            padding_bytes_size = align_size - @intCast(u16, sec_data.items.len % align_size);
        }
        return Self{ .type = .Rodata, .data = sec_data, .offset = offset, .vaddr = vaddr, .padding_bytes_size = padding_bytes_size };
    }

    pub inline fn ovlpSize(self: Self) u64 {
        return if (self.ovlp_ofst) |ovlp_ofst| ovlp_ofst else 0;
    }

    pub inline fn alignedSize(self: Self, alignment: u16) u64 {
        const sec_size = self.ovlpSize() + self.data.items.len;
        if (alignment < 2) return sec_size;
        const rem_bytes = alignment - (sec_size % alignment);
        return sec_size + rem_bytes;
    }

    pub inline fn toLoadCmdSeg(self: Self, alignment: u16) LoadCmdSeg {
        return switch (self.type) {
            .Text => LoadCmdSeg.initText(self.offset, self.alignedSize(alignment)),
            .Data => LoadCmdSeg.initData(self.offset, self.alignedSize(alignment)),
            .Rodata => LoadCmdSeg.initRoData(self.offset, self.alignedSize(alignment)),
        };
    }
};
