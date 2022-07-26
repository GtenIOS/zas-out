const std = @import("std");
const elfhdr = @import("elfhdr.zig");
const Elf64Header = elfhdr.Elf64Header;
const Elf64PhtEntry = elfhdr.Elf64PhtEntry;
const section = @import("section.zig");
const ElfSection = section.Section;
const Section = @import("common").section.Section;
const SectionType = @import("common").section.SectionType;
const reloc = @import("common").reloc;
const Relocation = reloc.Relocation;
const RelocType = reloc.RelocType;
const byte = @import("common").byte;

const align_size = 0x1000;
const virt_base = 0x400000;
const elf_hdr_size = @sizeOf(Elf64Header);
const elf_pht_size = @sizeOf(Elf64PhtEntry);
pub const Elf = struct {
    inline fn nextOffset(start: u64, len: u64, p_align: u16) u64 {
        const curr_end = start + len;
        if (p_align > 1) {
            std.log.info("curr end: {d}, rem: {d} next offset: {d} align_size: {d}", .{ curr_end, curr_end % p_align, curr_end + (curr_end % p_align), p_align });
            const rem_size = p_align - (curr_end % p_align);
            return curr_end + rem_size;
        } else return curr_end;
    }

    pub fn genPieExe64(allocator: std.mem.Allocator, sections: []const Section, relocations: ?[]const Relocation, out_file_path: []const u8) !void {
        if (sections.len == 0) return error.MissingTextSection;

        if (relocations) |relocs| {
            for (relocs) |reloca| if (reloca.type == RelocType.Abs) return error.AbsoluteRelocationInPIE;
        }

        const headers_size = elf_hdr_size + sections.len * elf_pht_size;
        var secs: std.ArrayList(ElfSection) = std.ArrayList(ElfSection).init(allocator);
        defer secs.deinit();

        var pht_entries: std.ArrayList(Elf64PhtEntry) = std.ArrayList(Elf64PhtEntry).init(allocator);
        defer pht_entries.deinit();

        var found_text: bool = false;
        var offset = headers_size;
        for (sections) |sec, i| {
            if (sec.data) |sec_data| {
                switch (sec.type) {
                    .Text => {
                        if (i != 0) return error.FirstSectionMustBeText;
                        if (sec_data.items.len == 0) return error.EmptyTextSection;
                        const elf_sec = ElfSection.initFromText(sec_data, align_size, offset, virt_base + offset);
                        try secs.append(elf_sec);
                        found_text = true;

                        offset = nextOffset(offset, sec_data.items.len, align_size);
                        try pht_entries.append(elf_sec.toPhtEntry(align_size));
                    },
                    .Data => {
                        const elf_sec = ElfSection.initFromData(sec_data, align_size, offset, virt_base + offset);
                        try secs.append(elf_sec);
                        offset = nextOffset(offset, sec_data.items.len, align_size);
                        try pht_entries.append(elf_sec.toPhtEntry(align_size));
                    },
                    .Rodata => {
                        const elf_sec = ElfSection.initFromRoData(sec_data, align_size, offset, virt_base + offset);
                        try secs.append(elf_sec);
                        offset = nextOffset(offset, sec_data.items.len, align_size);
                        try pht_entries.append(elf_sec.toPhtEntry(align_size));
                    },
                    else => return error.UnsupportedSection,
                }
            } else {
                if (sec.type == SectionType.Text) return error.EmptyTextSection;
            }
        }

        if (!found_text) return error.MissingTextSection;

        // Relocations
        if (relocations) |relocs| {
            for (relocs) |reloca| {
                const reloc_addr_bytes = blk: {
                    if (reloca.size == 1) {
                        break :blk byte.intToLEBytes(u8, @intCast(u8, secs.items[reloca.sec.idx].vaddr + reloca.ofst_in_sec - secs.items[0].vaddr - reloca.loc - reloca.size));
                    } else if (reloca.size == 2) {
                        break :blk byte.intToLEBytes(u16, @intCast(u16, secs.items[reloca.sec.idx].vaddr + reloca.ofst_in_sec - secs.items[0].vaddr - reloca.loc - reloca.size));
                    } else if (reloca.size == 4) {
                        break :blk byte.intToLEBytes(u32, @intCast(u32, secs.items[reloca.sec.idx].vaddr + reloca.ofst_in_sec - secs.items[0].vaddr - reloca.loc - reloca.size));
                    } else if (reloca.size == 8) {
                        break :blk byte.intToLEBytes(u64, @intCast(u64, secs.items[reloca.sec.idx].vaddr + reloca.ofst_in_sec - secs.items[0].vaddr - reloca.loc - reloca.size));
                    }
                    return error.InvalidRelocationSize;
                };
                std.log.info("Replacing at {d} to {d} with 0x{x}", .{ reloca.loc, reloca.size, secs.items[reloca.sec.idx].vaddr + reloca.ofst_in_sec });
                try secs.items[0].data.replaceRange(reloca.loc, reloca.size, try reloc_addr_bytes);
            }
        }

        const file = try std.fs.cwd().createFile(out_file_path, .{ .mode = 0o755 });

        // ElfHeader
        const elf_hdr = Elf64Header.init(virt_base + headers_size, @intCast(u16, pht_entries.items.len));
        try file.writer().writeAll(std.mem.asBytes(&elf_hdr));

        // Pht entries
        for (pht_entries.items) |pht| {
            try file.writer().writeAll(std.mem.asBytes(&pht));
        }

        // Sections
        for (secs.items) |sec, i| {
            try file.writer().writeAll(sec.data.items);
            // Padding bytes
            // For text section, padding byte is 0x90, i.e. nop instruction
            // For all other sections, padding byte is 0x0
            // Last section is exempted from byte padding
            if (sec.padding_bytes_size > 0 and i < secs.items.len - 1) try file.writer().writeByteNTimes(if (i == 0) 0x90 else 0x0, sec.padding_bytes_size);
        }
        file.close();
    }
};
