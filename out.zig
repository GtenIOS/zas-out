pub const elf = @import("elf");
pub const macho = @import("macho");

const builtin = @import("builtin");

pub const ExeType = enum {
    macho,
    elf,
    const Self = @This();
    pub inline fn default() Self {
        return if (builtin.target.isDarwin()) .macho else .elf;
    }
};
