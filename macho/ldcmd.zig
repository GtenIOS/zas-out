pub const lc_segment_64 = 0x00000019;
pub const seg_page_zero: [16]u8 = [16]u8{ '_', '_', 'P', 'A', 'G', 'E', 'Z', 'E', 'R', 'O', 0, 0, 0, 0, 0, 0 };
pub const seg_text: [16]u8 = [16]u8{ '_', '_', 'T', 'E', 'X', 'T', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
pub const seg_data: [16]u8 = [16]u8{ '_', '_', 'D', 'A', 'T', 'A', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
pub const seg_rodata: [16]u8 = [16]u8{ '_', '_', 'R', 'O', 'D', 'A', 'T', 'A', 0, 0, 0, 0, 0, 0, 0, 0 };
pub const seg_linkedit: [16]u8 = [16]u8{ '_', '_', 'L', 'I', 'N', 'K', 'E', 'D', 'I', 'T', 0, 0, 0, 0, 0, 0 };
pub const vm_size = 0x0000000100000000;
pub const vm_prot_none = 0x00000000;
pub const vm_prot_read = 0x00000001;
pub const vm_prot_write = 0x00000002;
pub const vm_prot_execute = 0x00000004;

pub const ld_cmd_seg_size = 72;
pub const LoadCmdSeg = struct {
    cmd: u32 = lc_segment_64,
    cmd_sz: u32 = ld_cmd_seg_size,
    seg_name: [16]u8,
    vm_addr: u64,
    vm_sz: u64,
    file_ofst: u64,
    file_sz: u64,
    max_vm_prot: u32,
    init_vm_prot: u32,
    no_of_secs: u32 = 0,
    flags: u32 = 0,
    const Self = @This();

    pub fn init(seg_name: [16]u8, vm_addr: u64, vm_sz: u64, file_ofst: u64, file_sz: u64, max_vm_prot: u32, init_vm_prot: u32, no_of_secs: u32, flags: u32) Self {
        return Self{ .seg_name = seg_name, .vm_addr = vm_addr, .vm_sz = vm_sz, .file_ofst = file_ofst, .file_sz = file_sz, .max_vm_prot = max_vm_prot, .init_vm_prot = init_vm_prot, .no_of_secs = no_of_secs, .flags = flags };
    }

    pub fn initPageZero() Self {
        return Self{ .seg_name = seg_page_zero, .vm_addr = 0, .vm_sz = vm_size, .file_ofst = 0, .file_sz = 0, .max_vm_prot = vm_prot_none, .init_vm_prot = vm_prot_none };
    }

    pub fn initText(ofst: u64, size: u64) Self {
        return Self{ .seg_name = seg_text, .vm_addr = vm_size + ofst, .vm_sz = size, .file_ofst = ofst, .file_sz = size, .max_vm_prot = vm_prot_read | vm_prot_execute, .init_vm_prot = vm_prot_read | vm_prot_execute };
    }

    pub fn initData(ofst: u64, size: u64) Self {
        return Self{ .seg_name = seg_data, .vm_addr = vm_size + ofst, .vm_sz = size, .file_ofst = ofst, .file_sz = size, .max_vm_prot = vm_prot_read | vm_prot_write, .init_vm_prot = vm_prot_read | vm_prot_write };
    }

    pub fn initRoData(ofst: u64, size: u64) Self {
        return Self{ .seg_name = seg_rodata, .vm_addr = vm_size + ofst, .vm_sz = size, .file_ofst = ofst, .file_sz = size, .max_vm_prot = vm_prot_read, .init_vm_prot = vm_prot_read };
    }

    pub fn initLinkEdit(ofst: u64) Self {
        return Self{ .seg_name = seg_linkedit, .vm_addr = vm_size + ofst, .vm_sz = 48, .file_ofst = ofst, .file_sz = 48, .max_vm_prot = vm_prot_read, .init_vm_prot = vm_prot_read };
    }
};

pub const lc_dyld_info_only = 0x80000022;
pub const ld_cmd_dyldinfo_size = 48;
pub const LoadCmdDyldInfo = struct {
    cmd: u32 = lc_dyld_info_only,
    cmd_sz: u32 = ld_cmd_dyldinfo_size,
    rebas_info_ofst: u32 = 0,
    rebas_info_sz: u32 = 0,
    bndg_info_ofst: u32 = 0,
    bndg_info_sz: u32 = 0,
    wk_bndg_info_ofst: u32 = 0,
    wk_bndg_info_sz: u32 = 0,
    lazy_bndg_info_ofst: u32 = 0,
    lazy_bndg_info_sz: u32 = 0,
    export_info_ofst: u32,
    export_info_sz: u32 = 48,
    const Self = @This();

    pub fn init(export_info_ofst: u32) Self {
        return Self{ .export_info_ofst = export_info_ofst };
    }
};

pub const DyldExportInfoTerm0 = extern struct {
    term_sz: u8 = 0,
    chld_cnt: u8 = 1,
    nd_lbl: [20]u8 = [20]u8{ '_', '_', 'm', 'h', '_', 'e', 'x', 'e', 'c', 'u', 't', 'e', '_', 'h', 'e', 'a', 'd', 'e', 'r', 0 },
    nxt_nd: u8 = @sizeOf(DyldExportInfoTerm0),
    const Self = @This();

    pub fn init() Self {
        return Self{};
    }
};

pub const DyldExportInfoTerm2 = struct {
    term_sz: u8 = 2,
    flags: u8 = 0,
    sym_ofst: u8 = 0,
    chld_cnt: u8 = 0,
    const Self = @This();

    pub fn init() Self {
        return Self{};
    }
};

pub const lc_symtab = 0x00000002;
pub const ld_cmd_symtab_size = 24;
pub const LoadCmdSymtab = struct {
    cmd: u32 = lc_symtab,
    cmd_sz: u32 = ld_cmd_symtab_size,
    sym_tab_ofst: u32,
    no_of_syms: u32 = 0,
    str_tab_ofst: u32,
    str_tab_sz: u32 = 0,
    const Self = @This();

    pub fn init(ofst: u32) Self {
        return Self{ .sym_tab_ofst = ofst, .str_tab_ofst = ofst };
    }
};

pub const lc_dysymtab = 0x0000000B;
pub const ld_cmd_dysymtab_size = 80;
pub const LoadCmdDySymtab = struct {
    cmd: u32 = lc_dysymtab,
    cmd_sz: u32 = ld_cmd_dysymtab_size,
    loc_sym_idx: u32 = 0,
    loc_sym_num: u32 = 0,
    def_ext_sym_idx: u32 = 0,
    def_ext_sym_num: u32 = 0,
    undef_ext_sym_idx: u32 = 0,
    undef_ext_sym_num: u32 = 0,
    toc_ofst: u32 = 0,
    toc_entries: u32 = 0,
    mod_tbl_ofst: u32 = 0,
    mod_tbl_entrs: u32 = 0,
    extref_tbl_ofst: u32 = 0,
    extref_tbl_entrs: u32 = 0,
    indsym_tbl_ofst: u32 = 0,
    indsym_tbl_entrs: u32 = 0,
    extrelo_tbl_ofst: u32 = 0,
    extrelo_tbl_entrs: u32 = 0,
    locrelo_tbl_ofst: u32 = 0,
    locrelo_tbl_entrs: u32 = 0,
};

pub const lc_load_dylinker = 0x0000000E;
pub const ld_cmd_dylinker_size = 32;
pub const LoadCmdDyLinker = struct {
    cmd: u32 = lc_load_dylinker,
    cmd_sz: u32 = ld_cmd_dylinker_size,
    str_ofst: u32 = 12,
    name: [20]u8 = [20]u8{ '/', 'u', 's', 'r', '/', 'l', 'i', 'b', '/', 'd', 'y', 'l', 'd', 0, 0, 0, 0, 0, 0, 0 },
    const Self = @This();

    pub fn init() Self {
        return Self{};
    }
};

pub const lc_load_dylib = 0x0000000C;
pub const time_stamp = 0x00000002;
pub const ver_1311_0_0 = 0x051F0000;
pub const comp_ver_1_0_0 = 0x00010000;
pub const ld_cmd_dylib_size = 56;
pub const LoadCmdDyLib = struct {
    cmd: u32 = lc_load_dylib,
    cmd_sz: u32 = ld_cmd_dylib_size,
    str_ofst: u32 = 24,
    time_st: u32 = time_stamp,
    curr_ver: u32 = ver_1311_0_0,
    comp_ver: u32 = comp_ver_1_0_0,
    name: [32]u8 = [32]u8{ '/', 'u', 's', 'r', '/', 'l', 'i', 'b', '/', 'l', 'i', 'b', 'S', 'y', 's', 't', 'e', 'm', '.', 'B', '.', 'd', 'y', 'l', 'i', 'b', 0, 0, 0, 0, 0, 0 },
    const Self = @This();

    pub fn init() Self {
        return Self{};
    }
};

pub const lc_main = 0x80000028;
pub const ld_cmd_main_size = 24;
pub const LoadCmdMain = struct {
    cmd: u32 = lc_main,
    cmd_sz: u32 = ld_cmd_main_size,
    entr_ofst: u64,
    stck_sz: u64 = 0,
    const Self = @This();

    pub fn init(entr_ofst: u64) Self {
        return Self{ .entr_ofst = entr_ofst };
    }
};
