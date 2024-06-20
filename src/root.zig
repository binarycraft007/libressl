const std = @import("std");
const testing = std.testing;
const c = @cImport(@cInclude("tls.h"));

test "basic add functionality" {
    _ = c.tls_init();
}
