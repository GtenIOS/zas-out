pub const mh_magic_64             = 0xFEEDFACF;
pub const cpu_type_x86_64         = 0x01000007;
pub const cpu_sub_type_x86_64_all = 0x00000003;
pub const mh_execute              = 0x00000002;
pub const mh_noundefs             = 0x00000001;
pub const mh_dyldlink             = 0x00000004;
pub const mh_twolevel             = 0x00000080;
pub const mh_pie                  = 0x00200000;

pub const Mach64Hdr = struct {
    magic: u32 = mh_magic_64,
    cpu_t: u32 = cpu_type_x86_64,
    cpu_sub_t: u32 = cpu_sub_type_x86_64_all,
    file_t: u32 = mh_execute,
    no_of_ld_cmds: u32,
    sz_of_ld_cmds: u32,
    flags: u32 = mh_noundefs | mh_pie,
    reserved: u32 = 0,
    const Self = @This();
    
    pub fn init(no_of_ld_cmds: u32, sz_of_ld_cmds: u32) Self {
        return Self{ .no_of_ld_cmds = no_of_ld_cmds, .sz_of_ld_cmds = sz_of_ld_cmds };
    }
};