const std = @import("std");

const Cpu = struct {
    const Self = @This();

    ir_ie: u16,
    // AF splitted in bit: 4=Carry flag, 5=Half Carry Flag, 6=Subtraction Flag,
    // 7=Zero Flag, the high 8 bit is the Accumulator
    af: u16,
    bc: u16,
    de: u16,
    hl: u16,
    pc: u16,
    sp: u16,

    pub fn init() Self {
        return Cpu{
            .af = 0,
        };
    }
};
