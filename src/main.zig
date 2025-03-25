const std = @import("std");
const Cpu = @import("cpu.zig").Cpu;
const Gb = @import("gb.zig").Gb;

pub fn main() !void {
    var game_boy = Gb.init();
    game_boy.run();
}
