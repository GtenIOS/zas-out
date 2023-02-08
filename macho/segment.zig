const std = @import("std");
const LoadCmdSeg = @import("ldcmd.zig").LoadCmdSeg;
const Section = @import("section.zig").Section;

const SegmentType = enum {
    Text,
    Data,
};

pub const Segment = struct {
    type: SegmentType,
    ovlp_ofst: ?u64 = null,
    offset: u64,
    vaddr: u64,
    secs: std.ArrayList(*const Section),
    padding_bytes_size: u16,
    const Self = @This();

    fn totalSecSize(secs: []*const Section, include_reserve: bool) usize {
        return blk: {
            var sec_data_size: usize = 0;
            for (secs) |sec| {
                if (sec.*.data) |sec_data| { sec_data_size += sec_data.items.len; }
                if (include_reserve) { if (sec.*.res_size) |res_size| { sec_data_size += res_size; } }
            }
            break :blk sec_data_size;
        };
    }

    pub fn initFromText(secs: std.ArrayList(*const Section), align_size: u16, ovlp_ofst: u64, offset: u64, vaddr: u64) Self {
        if (secs.items.len == 0) @panic("Segment should atleast contain one section");
        const sec_data_size = totalSecSize(secs.items, false);
        var padding_bytes_size: u16 = 0;
        if (align_size >= 2) {
            padding_bytes_size = align_size - @intCast(u16, (sec_data_size + ovlp_ofst) % align_size);
        }
        return Self{ .type = .Text, .ovlp_ofst = ovlp_ofst, .offset = offset, .vaddr = vaddr, .secs = secs, .padding_bytes_size = padding_bytes_size };
    }

    pub fn initFromData(secs: std.ArrayList(*const Section), align_size: u16, offset: u64, vaddr: u64) Self {
        if (secs.items.len == 0) @panic("Segment should atleast contain one section");
        const sec_data_size = totalSecSize(secs.items, false);
        var padding_bytes_size: u16 = 0;
        if (align_size >= 2 and sec_data_size > 0) {
            padding_bytes_size = align_size - @intCast(u16, sec_data_size % align_size);
        }
        return Self{ .type = .Data, .offset = offset, .vaddr = vaddr, .secs = secs, .padding_bytes_size = padding_bytes_size };
    }

    pub inline fn ovlpSize(self: Self) u64 {
        return self.ovlp_ofst orelse 0;
    }

    pub inline fn secSize(self: Self, include_reserve: bool) usize {
        return totalSecSize(self.secs.items, include_reserve);
    }

    pub inline fn alignedSize(self: Self, alignment: u16, include_reserve: bool) u64 {
        const sec_size = self.ovlpSize() + self.secSize(include_reserve);
        if (alignment < 2 or sec_size == 0 or sec_size % alignment == 0) return sec_size;
        const rem_bytes = alignment - (sec_size % alignment);
        return sec_size + rem_bytes;
    }

    pub inline fn toLoadCmdSeg(self: Self, alignment: u16) LoadCmdSeg {
        return switch (self.type) {
            .Text => LoadCmdSeg.initText(self.offset, self.alignedSize(alignment, false), @intCast(u32, self.secs.items.len)),
            .Data => LoadCmdSeg.initData(self.offset, self.alignedSize(alignment, false), self.alignedSize(alignment, true), @intCast(u32, self.secs.items.len)),
        };
    }
};
