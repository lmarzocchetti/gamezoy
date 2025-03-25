const Cpu = @import("cpu.zig").Cpu;

const Status = struct {
    debug: bool = false,
    is_running: bool = false,
    is_paused: bool = false,
    do_step: bool = false,
};

pub const Gb = struct {
    const Self = @This();

    cpu: Cpu,
    status: Status,

    pub fn init() Self {
        return Gb{
            .cpu = Cpu.init(),
            .status = Status{ .is_running = true },
        };
    }

    // TODO: Renderer check add bool when ppu can render
    fn run_step(self: *Self) void {
        if (!self.status.is_paused or self.status.do_step) {
            self.cpu.clock.t_instr = 0;
            // TODO: check for interrupts

            self.cpu.step();

            // TODO: ppu step and timer inc
        }

        self.status.do_step = false;

        // TODO: joypad check

        // TODO: Renderer check
    }

    pub fn run(self: *Self) void {
        while (self.status.is_running) {
            self.run_step();
        }
    }
};
