const std = @import("std");

pub fn build(b: *std.Build) !void {
    //const target = b.standardTargetOptions(.{});
    //const optimize = b.standardOptimizeOption(.{});

    _ = b.addModule("zamqp", .{
        .root_source_file = .{ .path = "src/zamqp.zig" },
    });
}
