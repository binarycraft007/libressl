const std = @import("std");
const builtin = @import("builtin");
const testing = std.testing;
const c = @cImport(@cInclude("tls.h"));

test "basic add functionality" {
    const rc = c.tls_init();
    switch (std.posix.errno(rc)) {
        .SUCCESS => {},
        else => |err| return std.posix.unexpectedErrno(err),
    }
    const tls_cfg = c.tls_config_new();
    if (tls_cfg == null) {
        switch (std.posix.errno(-1)) {
            .SUCCESS => unreachable,
            else => |err| return std.posix.unexpectedErrno(err),
        }
    }
    defer c.tls_config_free(tls_cfg);

    if (builtin.os.tag == .windows) {
        _ = try std.os.windows.WSAStartup(2, 2);
    }
    defer {
        if (builtin.os.tag == .windows) {
            std.os.windows.WSACleanup() catch unreachable;
        }
    }

    const host = "www.bing.com";
    const stream = try std.net.tcpConnectToHost(
        testing.allocator,
        host,
        443,
    );
    defer stream.close();
    const tls_ctx = c.tls_client();
    if (tls_ctx == null) {
        switch (std.posix.errno(-1)) {
            .SUCCESS => unreachable,
            else => |err| return std.posix.unexpectedErrno(err),
        }
    }
    defer {
        _ = c.tls_close(tls_ctx);
        c.tls_free(tls_ctx);
    }
    switch (std.posix.errno(c.tls_configure(tls_ctx, tls_cfg))) {
        .SUCCESS => {},
        else => {
            std.debug.print("{s}\n", .{c.tls_error(tls_ctx)});
            return error.TlsConfigure;
        },
    }
    const sock_fd = switch (builtin.os.tag) {
        .windows => @intFromPtr(stream.handle),
        else => stream.handle,
    };
    switch (std.posix.errno(c.tls_connect_socket(
        tls_ctx,
        @intCast(sock_fd),
        host,
    ))) {
        .SUCCESS => {},
        else => {
            std.debug.print("{s}\n", .{c.tls_error(tls_ctx)});
            return error.TlsConnect;
        },
    }

    while (true) {
        const res = c.tls_handshake(tls_ctx);
        if (res == -1) {
            std.debug.print("{s}\n", .{c.tls_error(tls_ctx)});
            return error.TlsHandshake;
        }
        if (res != c.TLS_WANT_POLLIN and res != c.TLS_WANT_POLLOUT) {
            break;
        }
    }
}
