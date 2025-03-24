const std = @import("std");
const Cpu = @import("cpu.zig").Cpu;

pub fn main() !void {
    var cpu = Cpu.init();
    cpu.af.setLow(20);
    cpu.af.setHi(55);
    std.debug.print("{any}\n", .{cpu.af.get()});
    std.debug.print("{any}\n", .{cpu.af.getLow()});
    std.debug.print("{any}\n", .{cpu.af.getHi()});
    std.debug.print("{any}\n", .{cpu.memory.memory[0..256]});
}
