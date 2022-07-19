pub const Elf64Header = struct {
    elf_magic: [4]u8 = [4]u8{ 0x7f, 'E', 'L', 'F'},
    bit_amount: u8 = 2,    // 1: 32-bit, 2: 64-bit
    endian: u8 = 1,    // 1: little endian, 2: big endian
    elf_version1: u8 = 1,    // must be 1
    os_abi: u8 = 0,     // 0: System V, 3: Linux
    abi_version: u8 = 0, // in statically linked executables has no effect. In dynamically linked executables, if OS_ABI==3, defines dynamic linker features
    unused: [7]u8 = [7]u8{ 0, 0, 0, 0, 0, 0, 0 },
    obj_file_type: u16 = 3, // ET_EXEC = 2, ET_DYN = 3
    arch: u16 = 0x3e,    // 0x3e: AMD64
    elf_version2: u32 = 1, // must be 1
    entry_point_offset: u64,    // Entry point from where the process should start executing
    pht_offset: u64 = 64,    // Start of the program header table
    sht_offset: u64 = 0,    // Start of the section header table
    processor_flags: u32 = 0,    // Processor-specific flags
    header_size: u16 = 64,    // Size of this header
    pht_entry_size: u16 = 56,     // Size of one PHT entry
    num_pht_entries: u16,    // Num of PHT entries
    sht_entry_size: u16 = 0,    // Size of one SHT entry,
    num_sht_entries: u16 = 0,    // Num of SHT entries,
    names_sht: u16 = 0,        // The index of the SHT entry that contains the section names
    const Self = @This();
    
    pub fn init(entry_point_offset: u64, num_pht_entries: u16) Self {
        return Self{ .entry_point_offset = entry_point_offset, .num_pht_entries = num_pht_entries };
    }
};

pub const Elf64PhtEntry = struct {
    segment_type: u32,    // 1: loadable segment, 2: dynamic linking info
    flags: u32,        // Segment dependant flags (position for 64-bit structure)
    offset: u64,        // Offset of the segment in the file image
    vaddr: u64,        // Virtual address of the segment in memory
    paddr: u64,        // On systems where the physical address is relevant, reserved for the physical address of the segment
    size_in_file: u64,    // Size of the segment in the file image
    size_in_mem: u64,    // Size of the segment in memory (>= `size_in_file`) 
    p_align: u64,        // 0 and 1 specify no alignment. Otherwise should be a positive, integral power of 2, with 'vaddr' equating 'offset' modulus 'p_align'
};