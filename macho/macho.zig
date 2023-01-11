const std = @import("std");
const MachoSec = @import("section.zig").Section;
const Section = @import("common").section.Section;
const SectionType = @import("common").section.SectionType;
const reloc = @import("common").reloc;
const Relocation = reloc.Relocation;
const RelocType = reloc.RelocType;
const byte = @import("common").byte;

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
pub const Macho = struct {
    inline fn nextOffset(start: u64, len: u64, p_align: u16) u64 {
        const curr_end = start + len;
        if (p_align > 1) {
            std.log.info("curr end: {d}, rem: {d} next offset: {d} align_size: {d}", .{ curr_end, p_align - curr_end % p_align, curr_end + (p_align - curr_end % p_align), p_align });
            const rem_size = p_align - (curr_end % p_align);
            return curr_end + rem_size;
        } else return curr_end;
    }

    pub fn genPieExe64(allocator: std.mem.Allocator, sections: []const Section, relocations: ?[]const Relocation, out_file_path: []const u8) !void {
        if (sections.len == 0) return error.MissingTextSection;
        if (sections[0].type != .Text) return error.FirstSectionShouldAlwaysBeText;

        if (relocations) |relocs| {
            for (relocs) |reloca| if (reloca.type == RelocType.Abs) return error.AbsoluteRelocationInPIE;
        }

        const ld_cmds_size = (sections.len + 2) * ld_cmd_seg_size + ld_cmd_dyldinfo_size + ld_cmd_symtab_size + ld_cmd_dysymtab_size + ld_cmd_dylinker_size + ld_cmd_dylib_size + ld_cmd_main_size;
        const no_ld_cmds = 8 + sections.len;

        var secs: std.ArrayList(MachoSec) = std.ArrayList(MachoSec).init(allocator);
        defer secs.deinit();

        var found_text: bool = false;
        var text_idx: u64 = 0;
        var vm_ofst: u64 = 0;
        var sec_ofst: u64 = @sizeOf(Mach64Hdr) + ld_cmds_size;
        for (sections) |comm_sec, i| {
            if (comm_sec.data) |sec_data| {
                switch (comm_sec.type) {
                    .Text => {
                        found_text = true;
                        text_idx = i;

                        try secs.append(MachoSec.initFromText(sec_data, page_size, sec_ofst, vm_ofst, vm_size + vm_ofst));
                        vm_ofst = nextOffset(sec_ofst, sec_data.items.len, page_size);
                        sec_ofst = nextOffset(sec_ofst, sec_data.items.len, page_size);
                    },
                    .Data => {
                        try secs.append(MachoSec.initFromData(sec_data, page_size, vm_ofst, vm_size + vm_ofst));
                        vm_ofst = nextOffset(vm_ofst, sec_data.items.len, page_size);
                        sec_ofst = nextOffset(sec_ofst, sec_data.items.len, page_size);
                    },
                    .Rodata => {
                        try secs.append(MachoSec.initFromRoData(sec_data, page_size, vm_ofst, vm_size + vm_ofst));
                        vm_ofst = nextOffset(vm_ofst, sec_data.items.len, page_size);
                        sec_ofst = nextOffset(sec_ofst, sec_data.items.len, page_size);
                    },
                    else => return error.UnsupportedSection,
                }
            } else if (comm_sec.type == .Text) {
                return error.EmptyTextSection;
            }
        }

        if (!found_text) return error.MissingTextSection;

        const main_entry = @sizeOf(Mach64Hdr) + ld_cmds_size + secs.items[0].padding_bytes_size;
        // Relocations
        if (relocations) |relocs| {
            for (relocs) |reloca| {
                const reloc_addr_bytes = blk: {
                    if (reloca.size == 1) {
                        break :blk try byte.intToLEBytes(u8, allocator, @intCast(u8, secs.items[reloca.sec.idx].vaddr + reloca.ofst_in_sec - secs.items[text_idx].vaddr - main_entry - reloca.loc - reloca.size));
                    } else if (reloca.size == 2) {
                        break :blk try byte.intToLEBytes(u16, allocator, @intCast(u16, secs.items[reloca.sec.idx].vaddr + reloca.ofst_in_sec - secs.items[text_idx].vaddr - main_entry - reloca.loc - reloca.size));
                    } else if (reloca.size == 4) {
                        break :blk try byte.intToLEBytes(u32, allocator, @intCast(u32, secs.items[reloca.sec.idx].vaddr + reloca.ofst_in_sec - secs.items[text_idx].vaddr - main_entry - reloca.loc - reloca.size));
                    } else if (reloca.size == 8) {
                        break :blk try byte.intToLEBytes(u64, allocator, @intCast(u64, secs.items[reloca.sec.idx].vaddr + reloca.ofst_in_sec - secs.items[text_idx].vaddr - main_entry - reloca.loc - reloca.size));
                    }
                    return error.InvalidRelocationSize;
                };
                defer reloc_addr_bytes.deinit();
                errdefer reloc_addr_bytes.deinit();
                std.log.info("Replacing at {d} to {d} with 0x{x}", .{ reloca.loc, reloca.size, secs.items[reloca.sec.idx].vaddr + reloca.ofst_in_sec });
                try secs.items[0].data.replaceRange(reloca.loc, reloca.size, reloc_addr_bytes.items);
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
        for (secs.items) |sec| {
            const ld_cmd_sec = sec.toLoadCmdSeg(page_size);
            try file.writer().writeAll(std.mem.asBytes(&ld_cmd_sec));
        }

        // Linkedit
        const ld_cmd_link_edit = LoadCmdSeg.initLinkEdit(sec_ofst);
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
        const ld_cmd_main = LoadCmdMain.init(main_entry);
        try file.writer().writeAll(std.mem.asBytes(&ld_cmd_main));

        // Sections
        for (secs.items) |sec, i| {
            // Text section is preceded by it's padding bytes
            // Padding bytes
            // For text section, padding byte is 0x90, i.e. nop instruction
            // For all other sections, padding byte is 0x0
            if (i == 0 and sec.padding_bytes_size > 0) try file.writer().writeByteNTimes(0x90, sec.padding_bytes_size);

            try file.writer().writeAll(sec.data.items);

            // For section(s) othar than Text, they are followed by their padding bytes
            if (i > 0 and sec.padding_bytes_size > 0) try file.writer().writeByteNTimes(0x0, sec.padding_bytes_size);
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
