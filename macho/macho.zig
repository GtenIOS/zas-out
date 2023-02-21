const std = @import("std");
const MachoSeg = @import("segment.zig").Segment;
const Section = @import("common").section.Section;
const SectionType = @import("common").section.SectionType;
const MachoSec = @import("section.zig").Section;
const reloc = @import("common").reloc;
const Relocation = reloc.Relocation;
const RelocType = reloc.RelocType;
const byte = @import("common").byte;
const Symbol = @import("common").symbol.Symbol;

const Mach64Hdr = @import("machdr.zig").Mach64Hdr;
const ldcmd = @import("ldcmd.zig");
const LoadCmdSeg = ldcmd.LoadCmdSeg;
const LoadCmdDyldInfo = ldcmd.LoadCmdDyldInfo;
const DyldExportInfoTerm0 = ldcmd.DyldExportInfoTerm0;
const DyldExportInfoTerm2 = ldcmd.DyldExportInfoTerm2;
const LoadCmdSymtab = ldcmd.LoadCmdSymtab;
const LoadCmdDySymtab = ldcmd.LoadCmdDySymtab;
const LoadCmdDyLinker = ldcmd.LoadCmdDyLinker;
const LoadCmdDyLib = ldcmd.LoadCmdDyLib;
const LoadCmdMain = ldcmd.LoadCmdMain;

const page_size = 0x1000;
const vm_size = 0x0000000100000000;
const ld_cmd_seg_size = 72;
const ld_cmd_dyldinfo_size = 48;
const ld_cmd_symtab_size = 24;
const ld_cmd_dysymtab_size = 80;
const ld_cmd_dylinker_size = 32;
const ld_cmd_dylib_size = 56;
const ld_cmd_main_size = 24;
const sec_hdr_size = 80;
pub const Macho = struct {
    inline fn nextOffset(start: u64, len: u64, p_align: u16) u64 {
        const curr_end = start + len;
        if (p_align > 1) {
            const rem_bytes = curr_end % p_align;
            std.log.info("curr end: {d}, rem: {d} next offset: {d} align_size: {d}", .{ curr_end, if (rem_bytes == 0) 0 else p_align - rem_bytes, if (rem_bytes == 0) curr_end else curr_end + (p_align - rem_bytes), p_align });
            const rem_size = if (rem_bytes == 0) 0 else p_align - rem_bytes;
            return curr_end + rem_size;
        } else return curr_end;
    }

    fn machoSegsFromMachoSecs(allocator: std.mem.Allocator, sections: []const MachoSec, sec_ofst: usize) !std.ArrayList(MachoSeg) {
        var data_seg_secs: std.ArrayList(MachoSec) = std.ArrayList(MachoSec).init(allocator);
        errdefer data_seg_secs.deinit();
        var text_seg_secs: std.ArrayList(MachoSec) = std.ArrayList(MachoSec).init(allocator);
        errdefer text_seg_secs.deinit();
        for (sections) |macho_sec| {
            // Skip empty sections
            const sec_size = blk: {
                if (macho_sec.data) |data| {
                    break :blk data.items.len;
                } else {
                    break :blk macho_sec.res_size orelse 0;
                }
            };
            if (sec_size == 0) continue;

            switch (macho_sec.type) {
                .Text, .Const => try text_seg_secs.append(macho_sec),
                else => try data_seg_secs.append(macho_sec),
            }
        }

        var segs: std.ArrayList(MachoSeg) = std.ArrayList(MachoSeg).init(allocator);
        errdefer segs.deinit();

        const text_seg: MachoSeg = MachoSeg.initFromText(text_seg_secs, page_size, sec_ofst, 0, vm_size);
        try segs.append(text_seg);
        var vm_ofst: u64 = nextOffset(0, text_seg.secSize(false), page_size);

        if (data_seg_secs.items.len > 0) {
            const data_seg: MachoSeg = MachoSeg.initFromData(data_seg_secs, page_size, vm_ofst, vm_size + vm_ofst);
            try segs.append(data_seg);
        }

        return segs;
    }

    fn convCommSecsToMachoSecs(allocator: std.mem.Allocator, sections: []const Section, sec_ofst: usize, text_seg_size: usize, text_sec_size: usize, data_seg_file_size: usize) !std.ArrayList(MachoSec) {
        const text_seg_padding = page_size - (@intCast(u16, (sec_ofst + text_seg_size)) % page_size);
        const text_sec_start_ofst = sec_ofst + text_seg_padding;
        const data_seg_start_ofst = page_size - ((text_sec_start_ofst + text_seg_size) % page_size);
        var secs: std.ArrayList(MachoSec) = std.ArrayList(MachoSec).init(allocator);
        errdefer secs.deinit();
        for (sections) |comm_sec| {
            if (comm_sec.data) |sec_data| {
                switch (comm_sec.type) {
                    .Text => {
                        const sec = MachoSec.initText(sec_data, text_sec_start_ofst, vm_size + text_sec_start_ofst);
                        try secs.append(sec);
                    },
                    .Rodata => {
                        const const_sec_start_ofst = text_sec_start_ofst + text_sec_size;
                        const sec = MachoSec.initConst(sec_data, const_sec_start_ofst, vm_size + const_sec_start_ofst);
                        try secs.append(sec);
                    },
                    .Data => {
                        const sec = MachoSec.initData(sec_data, data_seg_start_ofst, vm_size + data_seg_start_ofst);
                        try secs.append(sec);
                    },
                    else => {},
                }
            } else if (comm_sec.type == .Text) {
                return error.EmptyTextSection;
            } else if (comm_sec.type == .Bss) {
                if ((comm_sec.res_size orelse 0) > 0) {
                    const sec = MachoSec.initBss(vm_size + data_seg_start_ofst + data_seg_file_size, comm_sec.res_size.?);
                    try secs.append(sec);
                }
            } else {
                return error.UnsupportedEmptyDataSection;
            }
        }

        return secs;
    }

    const CountAndSizesTuple = std.meta.Tuple(&[_]type{ usize, [2]usize, [2]usize, usize });
    fn determineSegCountAndSize(sections: []const Section) CountAndSizesTuple {
        var seg_count: usize = 0;
        var text_seg_size: usize = 0;
        var text_sec_size: usize = 0;
        var data_seg_file_size: usize = 0;
        var data_seg_virt_size: usize = 0;
        var added_text_seg: bool = false;
        var added_data_seg: bool = false;
        var total_sec_count: usize = 0;
        for (sections) |comm_sec| {
            if (comm_sec.virt_size() == 0) continue;

            total_sec_count += 1;
            switch (comm_sec.type) {
                .Text => {
                    if (!added_text_seg) {
                        added_text_seg = true;
                        seg_count += 1;
                    }
                    if (comm_sec.data) |sec_data| {
                        text_seg_size += sec_data.items.len;
                        text_sec_size = sec_data.items.len;
                    }
                },
                .Rodata => {
                    if (!added_text_seg) {
                        added_text_seg = true;
                        seg_count += 1;
                    }
                    if (comm_sec.data) |sec_data| {
                        text_seg_size += sec_data.items.len;
                    }
                },
                .Data => {
                    if (!added_data_seg) {
                        added_data_seg = true;
                        seg_count += 1;
                    }
                    if (comm_sec.data) |sec_data| {
                        data_seg_file_size += sec_data.items.len;
                        data_seg_virt_size += sec_data.items.len;
                    }
                },
                .Bss => {
                    if (!added_data_seg) {
                        added_data_seg = true;
                        seg_count += 1;
                    }
                    data_seg_virt_size += comm_sec.res_size orelse 0;
                },
            }
        }

        return .{ seg_count, .{ text_sec_size, text_seg_size }, .{ data_seg_file_size, data_seg_virt_size }, total_sec_count };
    }

    // TODO: - Refactor the code
    pub fn genPieExe64(allocator: std.mem.Allocator, sections: []const Section, relocations: ?[]const Relocation, out_file_path: []const u8) !void {
        const text_idx: u64 = 0;
        if (sections.len == 0) return error.MissingTextSection;
        if (sections[text_idx].type != .Text) return error.FirstSectionShouldAlwaysBeText;

        if (relocations) |relocs| {
            for (relocs) |reloca| if (reloca.type == RelocType.Abs) return error.AbsoluteRelocationInPIE;
        }

        const start_sym: ?*Symbol = sections[text_idx].findSymbol("_start");
        if (start_sym == null) {
            return error.MissingStartSymbol;
        }
        if (!start_sym.?.*.did_init) {
            return error.StartSymbolNotInitialised;
        }

        const seg_count_and_size: CountAndSizesTuple = determineSegCountAndSize(sections);
        const seg_count = seg_count_and_size[0];
        const ld_cmds_size = (seg_count + 2) * ld_cmd_seg_size + ld_cmd_dyldinfo_size + ld_cmd_symtab_size + ld_cmd_dysymtab_size + ld_cmd_dylinker_size + ld_cmd_dylib_size + ld_cmd_main_size + (seg_count_and_size[3] * sec_hdr_size);
        const no_ld_cmds = 8 + seg_count;
        var sec_ofst: u64 = @sizeOf(Mach64Hdr) + ld_cmds_size;

        var secs = try convCommSecsToMachoSecs(allocator, sections, sec_ofst, seg_count_and_size[1][1], seg_count_and_size[1][0], seg_count_and_size[2][0]);
        defer secs.deinit();
        var segs = try machoSegsFromMachoSecs(allocator, secs.items, sec_ofst);
        defer {
            for (segs.items) |seg| {
                seg.deinit();
            }
            segs.deinit();
        }

        const data_seg_virt_size = seg_count_and_size[2][1];
        const text_seg_size = seg_count_and_size[1][1];
        const data_seg_file_size = seg_count_and_size[2][0];
        const data_seg_start_ofst = page_size - ((secs.items[0].offset + text_seg_size) % page_size);
        var vm_ofst = nextOffset(data_seg_start_ofst, data_seg_virt_size, page_size);
        sec_ofst = nextOffset(data_seg_start_ofst, data_seg_file_size, page_size);
        const text_entry = @sizeOf(Mach64Hdr) + ld_cmds_size + segs.items[0].padding_bytes_size; // Note: section `.text` does not begin with actual instruction, but padding instead. Hence the `padding_bytes_size` in calculation
        // Relocations
        if (relocations) |relocs| {
            for (relocs) |reloca| {
                const reloc_addr_bytes = blk: {
                    const reloc_addr_in_sec = secs.items[reloca.sec.idx].vaddr + reloca.ofst_in_sec;
                    const reloc_used_addr_end = secs.items[text_idx].vaddr + reloca.loc + reloca.size;
                    const reloc_ofst = @bitCast(isize, reloc_addr_in_sec -% reloc_used_addr_end);
                    if (reloca.size == 1) {
                        break :blk try byte.intToLEBytes(u8, allocator, @intCast(u8, @truncate(i8, reloc_ofst)));
                    } else if (reloca.size == 2) {
                        break :blk try byte.intToLEBytes(u16, allocator, @intCast(u16, @truncate(i16, reloc_ofst)));
                    } else if (reloca.size == 4) {
                        break :blk try byte.intToLEBytes(u32, allocator, @bitCast(u32, @truncate(i32, reloc_ofst)));
                    } else if (reloca.size == 8) {
                        break :blk try byte.intToLEBytes(u64, allocator, @intCast(u64, @truncate(i64, reloc_ofst)));
                    }
                    return error.InvalidRelocationSize;
                };
                defer reloc_addr_bytes.deinit();
                errdefer reloc_addr_bytes.deinit();
                std.log.info("Replacing at {d} to {d} with 0x{x}", .{ reloca.loc, reloca.size, secs.items[reloca.sec.idx].vaddr + reloca.ofst_in_sec });
                try secs.items[text_idx].data.?.replaceRange(reloca.loc, reloca.size, reloc_addr_bytes.items);
            }
        }

        const file = try std.fs.cwd().createFile(out_file_path, .{ .mode = 0o755 });

        // MachHeader
        const mach_hdr = Mach64Hdr.init(@intCast(u32, no_ld_cmds), @intCast(u32, ld_cmds_size));
        try file.writer().writeAll(std.mem.asBytes(&mach_hdr));

        // Load Commands
        // Page zero
        const ld_cmd_page_zero = LoadCmdSeg.initPageZero();
        try file.writer().writeAll(std.mem.asBytes(&ld_cmd_page_zero));

        // Section load commands
        for (segs.items) |seg| {
            const ld_cmd_sec = seg.toLoadCmdSeg(page_size);
            try file.writer().writeAll(std.mem.asBytes(&ld_cmd_sec));
            for (seg.secs.items) |sec| {
                const sec_hdr = sec.toHeader();
                try file.writer().writeAll(std.mem.asBytes(&sec_hdr));
            }
        }

        // Linkedit
        const ld_cmd_link_edit = LoadCmdSeg.initLinkEdit(vm_ofst, sec_ofst);
        try file.writer().writeAll(std.mem.asBytes(&ld_cmd_link_edit));

        // DyldInfo
        const ld_cmd_dyld_info = LoadCmdDyldInfo.init(@intCast(u32, sec_ofst));
        try file.writer().writeAll(std.mem.asBytes(&ld_cmd_dyld_info));

        // Symtab
        const ld_cmd_symtab = LoadCmdSymtab.init(@intCast(u32, sec_ofst + 48));
        try file.writer().writeAll(std.mem.asBytes(&ld_cmd_symtab));

        // DySymtab
        const ld_cmd_dysymtab = LoadCmdDySymtab{};
        try file.writer().writeAll(std.mem.asBytes(&ld_cmd_dysymtab));

        // Dylinker
        const ld_cmd_dylinker = LoadCmdDyLinker.init();
        try file.writer().writeAll(std.mem.asBytes(&ld_cmd_dylinker));

        // Dylib
        const ld_cmd_dylib = LoadCmdDyLib.init();
        try file.writer().writeAll(std.mem.asBytes(&ld_cmd_dylib));

        // Main
        const ld_cmd_main = LoadCmdMain.init(text_entry + start_sym.?.*.ofst_in_sec);
        try file.writer().writeAll(std.mem.asBytes(&ld_cmd_main));

        // Sections
        for (segs.items) |seg, i| {
            // Text section is preceded by it's padding bytes
            // Padding bytes
            // For text section, padding byte is 0x90, i.e. nop instruction
            // For all other sections, padding byte is 0x0
            if (i == 0 and seg.padding_bytes_size > 0) try file.writer().writeByteNTimes(0x90, seg.padding_bytes_size);

            for (seg.secs.items) |sec|
                if (sec.data) |sec_data|
                    try file.writer().writeAll(sec_data.items);

            // For section(s) othar than Text, they are followed by their padding bytes
            if (i > 0 and seg.padding_bytes_size > 0) try file.writer().writeByteNTimes(0x0, seg.padding_bytes_size);
        }

        // Export info
        const dyld_exp_info_term0 = DyldExportInfoTerm0.init();
        try file.writer().writeAll(std.mem.asBytes(&dyld_exp_info_term0));

        const dyld_exp_info_term2 = DyldExportInfoTerm2.init();
        try file.writer().writeAll(std.mem.asBytes(&dyld_exp_info_term2));

        // Export info padding
        const padding = 48 - @sizeOf(DyldExportInfoTerm0) - @sizeOf(DyldExportInfoTerm2);
        if (padding > 0) try file.writer().writeByteNTimes(0, padding);

        file.close();
    }
};
