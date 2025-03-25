const std = @import("std");

const RegisterFlags = enum(u8) {
    FLAG_ZERO = (1 << 7),
    FLAG_SUBTRACT = (1 << 6),
    FLAG_HALF_CARRY = (1 << 5),
    FLAG_CARRY = (1 << 4),
};

const Register = struct {
    const Self = @This();

    value: u16 = 0,

    pub fn get(self: *const Self) u16 {
        return self.value;
    }

    pub fn set(self: *Self, value: u16) void {
        self.value = value;
    }

    pub fn getHi(self: *const Self) u8 {
        return @intCast((self.value & 0xFF00) >> 8);
    }

    pub fn getLow(self: *const Self) u8 {
        return @intCast(self.value & 0x00FF);
    }

    pub fn setHi(self: *Self, value: u8) void {
        const tmp_high: u16 = value;
        const tmp_low: u16 = self.getLow();
        self.value = tmp_low | (tmp_high << 8);
    }

    pub fn setLow(self: *Self, value: u8) void {
        const tmp_high: u16 = self.getHi();
        const tmp_low: u16 = value;
        self.value = tmp_low | (tmp_high << 8);
    }

    pub fn inc(self: *Self) void {
        self.value += 1;
    }

    pub fn dec(self: *Self) void {
        self.value -= 1;
    }

    pub fn incHi(self: *Self) void {
        self.setHi(self.getHi() + 1);
    }

    pub fn decHi(self: *Self) void {
        self.setHi(self.getHi() - 1);
    }

    pub fn incLow(self: *Self) void {
        self.setLow(self.getLow() + 1);
    }

    pub fn decLow(self: *Self) void {
        self.setLow(self.getLow() - 1);
    }

    pub fn calculate_flags(start: u8, flags: u8, state: bool) u8 {
        return if (state) (start | flags) else (start & ~flags);
    }
};

const Memory = struct {
    const Self = @This();

    memory: [65536]u8,

    pub fn init() Self {
        comptime var memory: [65536]u8 = [_]u8{0} ** 65536;
        comptime {
            const boot_rom: [256]u8 = [_]u8{
                0x31, 0xFE, 0xFF, 0xAF, 0x21, 0xFF, 0x9F, 0x32, 0xCB, 0x7C, 0x20, 0xFB, 0x21, 0x26, 0xFF, 0x0E,
                0x11, 0x3E, 0x80, 0x32, 0xE2, 0x0C, 0x3E, 0xF3, 0xE2, 0x32, 0x3E, 0x77, 0x77, 0x3E, 0xFC, 0xE0,
                0x47, 0x11, 0x04, 0x01, 0x21, 0x10, 0x80, 0x1A, 0xCD, 0x95, 0x00, 0xCD, 0x96, 0x00, 0x13, 0x7B,
                0xFE, 0x34, 0x20, 0xF3, 0x11, 0xD8, 0x00, 0x06, 0x08, 0x1A, 0x13, 0x22, 0x23, 0x05, 0x20, 0xF9,
                0x3E, 0x19, 0xEA, 0x10, 0x99, 0x21, 0x2F, 0x99, 0x0E, 0x0C, 0x3D, 0x28, 0x08, 0x32, 0x0D, 0x20,
                0xF9, 0x2E, 0x0F, 0x18, 0xF3, 0x67, 0x3E, 0x64, 0x57, 0xE0, 0x42, 0x3E, 0x91, 0xE0, 0x40, 0x04,
                0x1E, 0x02, 0x0E, 0x0C, 0xF0, 0x44, 0xFE, 0x90, 0x20, 0xFA, 0x0D, 0x20, 0xF7, 0x1D, 0x20, 0xF2,
                0x0E, 0x13, 0x24, 0x7C, 0x1E, 0x83, 0xFE, 0x62, 0x28, 0x06, 0x1E, 0xC1, 0xFE, 0x64, 0x20, 0x06,
                0x7B, 0xE2, 0x0C, 0x3E, 0x87, 0xE2, 0xF0, 0x42, 0x90, 0xE0, 0x42, 0x15, 0x20, 0xD2, 0x05, 0x20,
                0x4F, 0x16, 0x20, 0x18, 0xCB, 0x4F, 0x06, 0x04, 0xC5, 0xCB, 0x11, 0x17, 0xC1, 0xCB, 0x11, 0x17,
                0x05, 0x20, 0xF5, 0x22, 0x23, 0x22, 0x23, 0xC9, 0xCE, 0xED, 0x66, 0x66, 0xCC, 0x0D, 0x00, 0x0B,
                0x03, 0x73, 0x00, 0x83, 0x00, 0x0C, 0x00, 0x0D, 0x00, 0x08, 0x11, 0x1F, 0x88, 0x89, 0x00, 0x0E,
                0xDC, 0xCC, 0x6E, 0xE6, 0xDD, 0xDD, 0xD9, 0x99, 0xBB, 0xBB, 0x67, 0x63, 0x6E, 0x0E, 0xEC, 0xCC,
                0xDD, 0xDC, 0x99, 0x9F, 0xBB, 0xB9, 0x33, 0x3E, 0x3C, 0x42, 0xB9, 0xA5, 0xB9, 0xA5, 0x42, 0x3C,
                0x21, 0x04, 0x01, 0x11, 0xA8, 0x00, 0x1A, 0x13, 0xBE, 0x20, 0xFE, 0x23, 0x7D, 0xFE, 0x34, 0x20,
                0xF5, 0x06, 0x19, 0x78, 0x86, 0x23, 0x05, 0x20, 0xFB, 0x86, 0x20, 0xFE, 0x3E, 0x01, 0xE0, 0x50,
            };

            @memcpy(memory[0..256], &boot_rom);
        }

        return Memory{
            .memory = memory,
        };
    }

    pub fn read_byte(self: *const Self, address: u16) u8 {
        // TODO: other check, joypad, timers, switchable rom banks, ram, ecc
        return self.memory[address];
    }

    pub fn write_byte(self: *Self, address: u16, value: u8) void {
        // TODO: same as read_byte do other checks
        self.memory[address] = value;
    }

    pub fn read_short(self: *const Self, address: u16) u16 {
        return self.read_byte(address) | (@as(u16, self.read_byte(address + 1)) << 8);
    }
};

const Clock = struct {
    t: u32 = 0,
    t_instr: u32 = 0,
};

pub const Cpu = struct {
    const Self = @This();

    const instructionTicks: [256]u8 = [_]u8{
        4, 12, 8, 8, 4, 4, 8, 4, 20, 8, 8, 8, 4, 4, 8, 4, // 0x0_
        4, 12, 8, 8, 4, 4, 8, 4, 12, 8, 8, 8, 4, 4, 8, 4, // 0x1_
        0, 12, 8, 8, 4, 4, 8, 4, 0, 8, 8, 8, 4, 4, 8, 4, // 0x2_
        0, 12, 8, 8, 12, 12, 12, 4, 0, 8, 8, 8, 4, 4, 8, 4, // 0x3_
        4, 4, 4, 4, 4, 4, 8, 4, 4, 4, 4, 4, 4, 4, 8, 4, // 0x4_
        4, 4, 4, 4, 4, 4, 8, 4, 4, 4, 4, 4, 4, 4, 8, 4, // 0x5_
        4, 4, 4, 4, 4, 4, 8, 4, 4, 4, 4, 4, 4, 4, 8, 4, // 0x6_
        8, 8, 8, 8, 8, 8, 4, 8, 4, 4, 4, 4, 4, 4, 8, 4, // 0x7_
        4, 4, 4, 4, 4, 4, 8, 4, 4, 4, 4, 4, 4, 4, 8, 4, // 0x8_
        4, 4, 4, 4, 4, 4, 8, 4, 4, 4, 4, 4, 4, 4, 8, 4, // 0x9_
        4, 4, 4, 4, 4, 4, 8, 4, 4, 4, 4, 4, 4, 4, 8, 4, // 0xa_
        4, 4, 4, 4, 4, 4, 8, 4, 4, 4, 4, 4, 4, 4, 8, 4, // 0xb_
        0, 12, 0, 16, 0, 16, 8, 16, 0, 16, 0, 0, 0, 24, 8, 16, // 0xc_
        0, 12, 0, 0, 0, 16, 8, 16, 0, 16, 0, 0, 0, 0, 8, 16, // 0xd_
        12, 12, 8, 0, 0, 16, 8, 16, 16, 4, 16, 0, 0, 0, 8, 16, // 0xe_
        12, 12, 8, 4, 0, 16, 8, 16, 12, 8, 16, 4, 0, 0, 8, 16, // 0xf_
    };

    const extendedInstructionTicks: [256]u8 = [_]u8{
        8, 8, 8, 8, 8, 8, 16, 8, 8, 8, 8, 8, 8, 8, 16, 8, // 0x0_
        8, 8, 8, 8, 8, 8, 16, 8, 8, 8, 8, 8, 8, 8, 16, 8, // 0x1_
        8, 8, 8, 8, 8, 8, 16, 8, 8, 8, 8, 8, 8, 8, 16, 8, // 0x2_
        8, 8, 8, 8, 8, 8, 16, 8, 8, 8, 8, 8, 8, 8, 16, 8, // 0x3_
        8, 8, 8, 8, 8, 8, 12, 8, 8, 8, 8, 8, 8, 8, 12, 8, // 0x4_
        8, 8, 8, 8, 8, 8, 12, 8, 8, 8, 8, 8, 8, 8, 12, 8, // 0x5_
        8, 8, 8, 8, 8, 8, 12, 8, 8, 8, 8, 8, 8, 8, 12, 8, // 0x6_
        8, 8, 8, 8, 8, 8, 12, 8, 8, 8, 8, 8, 8, 8, 12, 8, // 0x7_
        8, 8, 8, 8, 8, 8, 16, 8, 8, 8, 8, 8, 8, 8, 16, 8, // 0x8_
        8, 8, 8, 8, 8, 8, 16, 8, 8, 8, 8, 8, 8, 8, 16, 8, // 0x9_
        8, 8, 8, 8, 8, 8, 16, 8, 8, 8, 8, 8, 8, 8, 16, 8, // 0xa_
        8, 8, 8, 8, 8, 8, 16, 8, 8, 8, 8, 8, 8, 8, 16, 8, // 0xb_
        8, 8, 8, 8, 8, 8, 16, 8, 8, 8, 8, 8, 8, 8, 16, 8, // 0xc_
        8, 8, 8, 8, 8, 8, 16, 8, 8, 8, 8, 8, 8, 8, 16, 8, // 0xd_
        8, 8, 8, 8, 8, 8, 16, 8, 8, 8, 8, 8, 8, 8, 16, 8, // 0xe_
        8, 8, 8, 8, 8, 8, 16, 8, 8, 8, 8, 8, 8, 8, 16, 8, // 0xf_
    };

    ir_ie: Register,
    // AF splitted in bit: 4=Carry flag, 5=Half Carry Flag, 6=Subtraction Flag,
    // 7=Zero Flag, the high 8 bit is the Accumulator
    af: Register,
    bc: Register,
    de: Register,
    hl: Register,
    pc: u16,
    sp: u16,

    memory: Memory,
    clock: Clock,

    pub fn init() Self {
        return Cpu{
            .ir_ie = Register{},
            .af = Register{},
            .bc = Register{},
            .de = Register{},
            .hl = Register{},
            .pc = 0, // TODO: Start at 0x100 to skip the boot
            .sp = 0,
            .memory = Memory.init(),
            .clock = Clock{},
        };
    }

    fn xor_a(self: *Self, value: u8) void {
        self.af.setHi(self.af.getHi() ^ value);

        const state = if (self.af.getHi() == 0) true else false;
        self.af.setLow(Register.calculate_flags(self.af.getLow(), @intFromEnum(RegisterFlags.FLAG_ZERO), state));
        self.af.setLow(Register.calculate_flags(self.af.getLow(), @intFromEnum(RegisterFlags.FLAG_CARRY) | @intFromEnum(RegisterFlags.FLAG_SUBTRACT) | @intFromEnum(RegisterFlags.FLAG_HALF_CARRY), false));
    }

    fn bit_extended(self: *Self, bit: u8, value: u8) void {
        const state = if ((value & bit) == 0) true else false;
        self.af.setLow(Register.calculate_flags(self.af.getLow(), @intFromEnum(RegisterFlags.FLAG_ZERO), state));
        self.af.setLow(Register.calculate_flags(self.af.getLow(), @intFromEnum(RegisterFlags.FLAG_HALF_CARRY), true));
        self.af.setLow(Register.calculate_flags(self.af.getLow(), @intFromEnum(RegisterFlags.FLAG_SUBTRACT), false));
    }

    fn extended_execute(self: *Self, opcode: u8) void {
        self.clock.t_instr += Cpu.extendedInstructionTicks[opcode];

        switch (opcode) {
            0x7c => {
                self.bit_extended((1 << 7), self.hl.getHi());
            },
            else => {
                std.debug.print("EXTENDED OpCode 0x{x} not implemented\n", .{opcode});
                std.process.exit(1);
            },
        }
    }

    fn execute_instruction(self: *Self, opcode: u8) void {
        self.clock.t_instr += Cpu.instructionTicks[opcode];

        switch (opcode) {
            0x00 => {}, // NOP
            0x01 => { // LD BC, nn
                self.bc.set(self.memory.read_short(self.pc));
                self.pc += 2;
            },
            0x02 => { // LD (BC), A
                self.memory.write_byte(self.bc.get(), self.af.getHi());
            },
            0x03 => { // INC BC
                self.bc.inc();
            },
            0x04 => { // INC B
                self.bc.incHi();
            },
            0x05 => { // DEC B
                self.bc.decHi();
            },
            0x06 => { // LD B, n
                self.bc.setHi(self.memory.read_byte(self.pc));
                self.pc += 1;
            },
            0x21 => {
                self.hl.set(self.memory.read_short(self.pc));
                self.pc += 2;
            },
            0x31 => {
                self.sp = self.memory.read_short(self.pc);
                self.pc += 2;
            },
            0x32 => {
                self.memory.write_byte(self.hl.get(), self.af.getHi());
                self.hl.dec();
            },
            0xAF => {
                self.xor_a(self.af.getHi());
            },
            0xCB => {
                self.pc += 1;
                self.extended_execute(self.memory.read_byte(self.pc - 1));
            },
            else => {
                std.debug.print("OpCode 0x{x} not implemented\n", .{opcode});
                std.process.exit(1);
            },
        }
    }

    pub fn step(self: *Self) void {
        // TODO: Memory is halted then t_instr = 4 then return
        const opcode = self.memory.read_byte(self.pc);
        self.pc += 1;

        // TODO: trigger halt bug
        self.execute_instruction(opcode);
    }
};
