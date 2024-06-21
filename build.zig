const std = @import("std");

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const libressl_dep = b.dependency("libressl", .{});

    const t = target.result;
    var flags = std.ArrayList([]const u8).init(b.allocator);
    defer flags.deinit();
    try flags.append("-Wno-pointer-sign");
    if (t.isDarwin()) {
        try flags.append("-fno-common");
    }
    const crypto = b.addStaticLibrary(.{
        .name = "crypto",
        .target = target,
        .optimize = optimize,
    });
    crypto.linkLibC();
    crypto.addCSourceFiles(.{
        .root = libressl_dep.path("crypto"),
        .files = &crypto_src_common,
        .flags = flags.items,
    });
    if (t.os.tag == .linux and t.cpu.arch == .x86_64) {
        crypto.addCSourceFiles(.{
            .root = libressl_dep.path("crypto"),
            .files = &asm_elf_x86_64,
            .flags = flags.items,
        });
        crypto.defineCMacro("endbr64", "");
        crypto.defineCMacro("endbr32", "");
        crypto.defineCMacro("AES_ASM", null);
        crypto.defineCMacro("BSAES_ASM", null);
        crypto.defineCMacro("VPAES_ASM", null);
        crypto.defineCMacro("OPENSSL_IA32_SSE2", null);
        crypto.defineCMacro("OPENSSL_BN_ASM_MONT", null);
        crypto.defineCMacro("OPENSSL_BN_ASM_MONT5", null);
        crypto.defineCMacro("MD5_ASM", null);
        crypto.defineCMacro("GHASH_ASM", null);
        crypto.defineCMacro("RSA_ASM", null);
        crypto.defineCMacro("SHA1_ASM", null);
        crypto.defineCMacro("SHA256_ASM", null);
        crypto.defineCMacro("SHA512_ASM", null);
        crypto.defineCMacro("WHIRLPOOL_ASM", null);
        crypto.defineCMacro("OPENSSL_CPUID_OBJ", null);
    } else if (t.os.tag == .macos and t.cpu.arch == .x86_64) {
        crypto.addCSourceFiles(.{
            .root = libressl_dep.path("crypto"),
            .files = &asm_macos_x86_64,
            .flags = flags.items,
        });
        crypto.defineCMacro("endbr64", "");
        crypto.defineCMacro("endbr32", "");
        crypto.defineCMacro("AES_ASM", null);
        crypto.defineCMacro("BSAES_ASM", null);
        crypto.defineCMacro("VPAES_ASM", null);
        crypto.defineCMacro("OPENSSL_IA32_SSE2", null);
        crypto.defineCMacro("OPENSSL_BN_ASM_MONT", null);
        crypto.defineCMacro("OPENSSL_BN_ASM_MONT5", null);
        crypto.defineCMacro("MD5_ASM", null);
        crypto.defineCMacro("GHASH_ASM", null);
        crypto.defineCMacro("RSA_ASM", null);
        crypto.defineCMacro("SHA1_ASM", null);
        crypto.defineCMacro("SHA256_ASM", null);
        crypto.defineCMacro("SHA512_ASM", null);
        crypto.defineCMacro("WHIRLPOOL_ASM", null);
        crypto.defineCMacro("OPENSSL_CPUID_OBJ", null);
    } else if (t.os.tag == .windows and t.isMinGW() and
        t.cpu.arch == .x86_64)
    {
        crypto.addCSourceFiles(.{
            .root = libressl_dep.path("crypto"),
            .files = &asm_mingw_x86_64,
            .flags = flags.items,
        });
        crypto.defineCMacro("endbr64", "");
        crypto.defineCMacro("endbr32", "");
        crypto.defineCMacro("AES_ASM", null);
        crypto.defineCMacro("BSAES_ASM", null);
        crypto.defineCMacro("VPAES_ASM", null);
        crypto.defineCMacro("OPENSSL_IA32_SSE2", null);
        //crypto.defineCMacro("OPENSSL_BN_ASM_MONT", null);
        //crypto.defineCMacro("OPENSSL_BN_ASM_MONT5", null);
        crypto.defineCMacro("MD5_ASM", null);
        crypto.defineCMacro("GHASH_ASM", null);
        crypto.defineCMacro("RSA_ASM", null);
        crypto.defineCMacro("SHA1_ASM", null);
        crypto.defineCMacro("SHA256_ASM", null);
        crypto.defineCMacro("SHA512_ASM", null);
        crypto.defineCMacro("WHIRLPOOL_ASM", null);
        crypto.defineCMacro("OPENSSL_CPUID_OBJ", null);
    } else {
        crypto.defineCMacro("OPENSSL_NO_ASM", null);
        crypto.addCSourceFiles(.{
            .root = libressl_dep.path("crypto"),
            .files = &crypto_src_common_noasm,
            .flags = flags.items,
        });
    }
    switch (t.os.tag) {
        .linux => {
            crypto.addCSourceFiles(.{
                .root = libressl_dep.path("crypto"),
                .files = &crypto_src_linux,
                .flags = flags.items,
            });
            if (!t.isGnu()) {
                crypto.addCSourceFiles(.{
                    .root = libressl_dep.path("crypto"),
                    .files = &.{
                        "compat/arc4random.c",
                        "compat/arc4random_uniform.c",
                    },
                    .flags = flags.items,
                });
            }
        },
        .macos => {
            crypto.addCSourceFiles(.{
                .root = libressl_dep.path("crypto"),
                .files = &crypto_src_macos,
                .flags = flags.items,
            });
        },
        .windows => {
            crypto.addCSourceFiles(.{
                .root = libressl_dep.path("crypto"),
                .files = &crypto_src_win32,
                .flags = flags.items,
            });
        },
        else => {},
    }
    if (t.os.tag != .windows) {
        crypto.addCSourceFiles(.{
            .root = libressl_dep.path("crypto"),
            .files = &crypto_src_unix,
            .flags = flags.items,
        });
    }
    const openssl_dir = switch (t.os.tag) {
        .windows => "c:\\\\msys64\\\\usr\\\\ssl",
        else => "/etc/ssl",
    };
    const openssl_dir_value = try std.mem.concat(b.allocator, u8, &.{
        "\"",
        openssl_dir,
        "\"",
    });
    crypto.defineCMacro("OPENSSLDIR", openssl_dir_value);
    crypto.addIncludePath(libressl_dep.path("crypto/asn1"));
    crypto.addIncludePath(libressl_dep.path("crypto/bio"));
    crypto.addIncludePath(libressl_dep.path("crypto/bn"));
    crypto.addIncludePath(libressl_dep.path("crypto/bytestring"));
    crypto.addIncludePath(libressl_dep.path("crypto/dh"));
    crypto.addIncludePath(libressl_dep.path("crypto/dsa"));
    crypto.addIncludePath(libressl_dep.path("crypto/curve25519"));
    crypto.addIncludePath(libressl_dep.path("crypto/ec"));
    crypto.addIncludePath(libressl_dep.path("crypto/ecdh"));
    crypto.addIncludePath(libressl_dep.path("crypto/ecdsa"));
    crypto.addIncludePath(libressl_dep.path("crypto/evp"));
    crypto.addIncludePath(libressl_dep.path("crypto/hidden"));
    crypto.addIncludePath(libressl_dep.path("crypto/hmac"));
    crypto.addIncludePath(libressl_dep.path("crypto/lhash"));
    crypto.addIncludePath(libressl_dep.path("crypto/modes"));
    crypto.addIncludePath(libressl_dep.path("crypto/ocsp"));
    crypto.addIncludePath(libressl_dep.path("crypto/pkcs12"));
    crypto.addIncludePath(libressl_dep.path("crypto/rsa"));
    crypto.addIncludePath(libressl_dep.path("crypto/sha"));
    crypto.addIncludePath(libressl_dep.path("crypto/stack"));
    crypto.addIncludePath(libressl_dep.path("crypto/x509"));
    crypto.addIncludePath(libressl_dep.path("crypto"));
    crypto.addIncludePath(libressl_dep.path("include/compat/"));
    crypto.addIncludePath(libressl_dep.path("include"));
    switch (t.cpu.arch) {
        .x86_64 => {
            crypto.addIncludePath(
                libressl_dep.path("crypto/bn/arch/amd64"),
            );
        },
        .aarch64 => {
            crypto.addIncludePath(
                libressl_dep.path("crypto/bn/arch/aarch64"),
            );
        },
        .arm => {
            crypto.addIncludePath(
                libressl_dep.path("crypto/bn/arch/arm"),
            );
        },
        else => {},
    }
    addCommonBuildOptions(crypto, &t);
    b.installArtifact(crypto);

    const ssl = b.addStaticLibrary(.{
        .name = "ssl",
        .target = target,
        .optimize = optimize,
    });
    ssl.linkLibC();
    ssl.linkLibrary(crypto);
    ssl.addCSourceFiles(.{
        .root = libressl_dep.path("ssl"),
        .files = &ssl_src,
        .flags = flags.items,
    });
    ssl.addIncludePath(libressl_dep.path("include/compat"));
    ssl.addIncludePath(libressl_dep.path("crypto/bio"));
    ssl.addIncludePath(libressl_dep.path("ssl/hidden"));
    ssl.addIncludePath(libressl_dep.path("include"));
    addCommonBuildOptions(ssl, &t);
    b.installArtifact(ssl);

    const tls = b.addStaticLibrary(.{
        .name = "tls",
        .target = target,
        .optimize = optimize,
    });
    tls.linkLibC();
    tls.linkLibrary(ssl);
    tls.addCSourceFiles(.{
        .root = libressl_dep.path("tls"),
        .files = &tls_src,
        .flags = flags.items,
    });
    if (t.os.tag == .windows) {
        tls.addCSourceFiles(.{
            .root = libressl_dep.path("tls"),
            .files = &tls_win32_src,
            .flags = flags.items,
        });
    }
    tls.addIncludePath(libressl_dep.path("include"));
    tls.addIncludePath(libressl_dep.path("include/compat"));
    tls.installHeadersDirectory(libressl_dep.path("include"), "", .{
        .include_extensions = &.{".h"},
    });
    const ca_path_value = try std.mem.concat(b.allocator, u8, &.{
        "\"",
        openssl_dir,
        if (t.os.tag == .windows) "\\\\" else "/",
        "cert.pem",
        "\"",
    });
    tls.defineCMacro("TLS_DEFAULT_CA_FILE", ca_path_value);
    addCommonBuildOptions(tls, &t);
    b.installArtifact(tls);

    const lib_unit_tests = b.addTest(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    lib_unit_tests.linkLibrary(tls);

    const run_lib_unit_tests = b.addRunArtifact(lib_unit_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_lib_unit_tests.step);
}

fn addCommonBuildOptions(
    compile: *std.Build.Step.Compile,
    t: *const std.Target,
) void {
    switch (t.os.tag) {
        .linux => {
            compile.linkSystemLibrary("pthread");
            compile.defineCMacro("_DEFAULT_SOURCE", null);
            compile.defineCMacro("_BSD_SOURCE", null);
            compile.defineCMacro("_POSIX_SOURCE", null);
            compile.defineCMacro("_GNU_SOURCE", null);
            if (t.isGnu()) {
                compile.defineCMacro("HAVE_ARC4RANDOM_BUF", null);
            }
            compile.defineCMacro("HAVE_REALLOCARRAY", null);
            compile.defineCMacro("HAVE_ENDIAN_H", null);
            compile.defineCMacro("HAVE_EXPLICIT_BZERO", null);
            compile.defineCMacro("HAVE_GETENTROPY", null);
        },
        .macos => {
            compile.defineCMacro("HAVE_GETPROGNAME", null);
            compile.defineCMacro("HAVE_STRTONUM", null);
            compile.defineCMacro("HAVE_ARC4RANDOM_BUF", null);
            compile.defineCMacro("HAVE_GETENTROPY", null);
        },
        .windows => {
            compile.defineCMacro("_GNU_SOURCE", null);
            compile.defineCMacro("_POSIX", null);
            compile.defineCMacro("_POSIX_SOURCE", null);
            compile.defineCMacro("__USE_MINGW_ANSI_STDIO", null);
            compile.defineCMacro("_CRT_SECURE_NO_WARNINGS", null);
            compile.defineCMacro("_CRT_DEPRECATED_NO_WARNINGS", null);
            compile.defineCMacro("_REENTRANT", null);
            compile.defineCMacro("_POSIX_THREAD_SAFE_FUNCTIONS", null);
            compile.defineCMacro("NO_SYSLOG", null);
            compile.defineCMacro("WIN32_LEAN_AND_MEAN", null);
            //compile.defineCMacro("_WIN32_WINNT", "0x0600");
            compile.linkSystemLibrary("ws2_32");
            compile.linkSystemLibrary("ntdll");
            compile.linkSystemLibrary("bcrypt");
        },
        else => {
            compile.defineCMacro("HAVE_GETPROGNAME", null);
            compile.defineCMacro("HAVE_STRTONUM", null);
            compile.defineCMacro("HAVE_TIMINGSAFE_MEMCMP", null);
            compile.defineCMacro("HAVE_SYSLOG_R", null);
            compile.defineCMacro("HAVE_TIMINGSAFE_BCMP", null);
            compile.defineCMacro("HAVE_ARC4RANDOM_BUF", null);
        },
    }
    if (t.os.tag != .windows) {
        compile.defineCMacro("HAVE_SYSLOG", null);
        compile.defineCMacro("HAVE_GETPAGESIZE", null);
        compile.defineCMacro("HAVE_TIMEGM", null);
        compile.defineCMacro("HAVE_STRSEP", null);
        compile.defineCMacro("HAVE_STRLCPY", null);
        compile.defineCMacro("HAVE_STRNDUP", null);
        compile.defineCMacro("HAVE_STRLCAT", null);
    }
    compile.defineCMacro("HAVE_ATTRIBUTE__BOUNDED__", null);
    compile.defineCMacro("HAVE_ATTRIBUTE__DEAD__", null);
    compile.defineCMacro("HAVE_BIG_ENDIAN", null);
    compile.defineCMacro("HAVE_LITTLE_ENDIAN", null);
    compile.defineCMacro("HAVE_ASPRINTF", null);
    compile.defineCMacro("HAVE_GETOPT", null);
    compile.defineCMacro("HAVE_STRCASECMP", null);
    compile.defineCMacro("HAVE_STRNLEN", null);
    compile.defineCMacro("HAVE_STRNLEN", null);
    compile.defineCMacro("HAVE_ARC4RANDOM_UNIFORM", null);
    compile.defineCMacro("HAVE_GETAUXVAL", null);
    compile.defineCMacro("HAVE_TIMESPECSUB", null);
    compile.defineCMacro("HAVE_MEMMEM", null);
    compile.defineCMacro("HAVE_MACHINE_ENDIAN_H", null);
    compile.defineCMacro("HAVE_ERR_H", null);
    compile.defineCMacro("HAVE_NETINET_IP_H", null);
    compile.defineCMacro("HAVE_GNU_STACK", null);
    compile.defineCMacro("HAVE_CLOCK_GETTIME", null);

    compile.defineCMacro("LIBRESSL_INTERNAL", null);
    compile.defineCMacro("OPENSSL_NO_HW_PADLOCK", null);
    compile.defineCMacro("__BEGIN_HIDDEN_DECLS", "");
    compile.defineCMacro("__END_HIDDEN_DECLS", "");
}

const crypto_src_common = [_][]const u8{
    "cpt_err.c",
    "cryptlib.c",
    "crypto_init.c",
    "cversion.c",
    "ex_data.c",
    "malloc-wrapper.c",
    "mem_clr.c",
    "mem_dbg.c",
    "o_fips.c",
    "o_init.c",
    "o_str.c",
    "aes/aes_cfb.c",
    "aes/aes_ctr.c",
    "aes/aes_ecb.c",
    "aes/aes_ige.c",
    "aes/aes_ofb.c",
    "aes/aes_wrap.c",
    "asn1/a_bitstr.c",
    "asn1/a_enum.c",
    "asn1/a_int.c",
    "asn1/a_mbstr.c",
    "asn1/a_object.c",
    "asn1/a_octet.c",
    "asn1/a_pkey.c",
    "asn1/a_print.c",
    "asn1/a_pubkey.c",
    "asn1/a_strex.c",
    "asn1/a_string.c",
    "asn1/a_strnid.c",
    "asn1/a_time.c",
    "asn1/a_time_posix.c",
    "asn1/a_time_tm.c",
    "asn1/a_type.c",
    "asn1/a_utf8.c",
    "asn1/asn1_err.c",
    "asn1/asn1_gen.c",
    "asn1/asn1_item.c",
    "asn1/asn1_lib.c",
    "asn1/asn1_old.c",
    "asn1/asn1_old_lib.c",
    "asn1/asn1_par.c",
    "asn1/asn1_types.c",
    "asn1/asn_mime.c",
    "asn1/asn_moid.c",
    "asn1/bio_asn1.c",
    "asn1/bio_ndef.c",
    "asn1/p5_pbe.c",
    "asn1/p5_pbev2.c",
    "asn1/p8_pkey.c",
    "asn1/t_crl.c",
    "asn1/t_req.c",
    "asn1/t_spki.c",
    "asn1/t_x509.c",
    "asn1/t_x509a.c",
    "asn1/tasn_dec.c",
    "asn1/tasn_enc.c",
    "asn1/tasn_fre.c",
    "asn1/tasn_new.c",
    "asn1/tasn_prn.c",
    "asn1/tasn_typ.c",
    "asn1/tasn_utl.c",
    "asn1/x_algor.c",
    "asn1/x_attrib.c",
    "asn1/x_bignum.c",
    "asn1/x_crl.c",
    "asn1/x_exten.c",
    "asn1/x_info.c",
    "asn1/x_long.c",
    "asn1/x_name.c",
    "asn1/x_pkey.c",
    "asn1/x_pubkey.c",
    "asn1/x_req.c",
    "asn1/x_sig.c",
    "asn1/x_spki.c",
    "asn1/x_val.c",
    "asn1/x_x509.c",
    "asn1/x_x509a.c",
    "bf/bf_cfb64.c",
    "bf/bf_ecb.c",
    "bf/bf_enc.c",
    "bf/bf_ofb64.c",
    "bf/bf_skey.c",
    "bio/b_dump.c",
    "bio/b_print.c",
    "bio/b_sock.c",
    "bio/bf_buff.c",
    "bio/bf_nbio.c",
    "bio/bf_null.c",
    "bio/bio_cb.c",
    "bio/bio_err.c",
    "bio/bio_lib.c",
    "bio/bio_meth.c",
    "bio/bss_acpt.c",
    "bio/bss_bio.c",
    "bio/bss_conn.c",
    "bio/bss_dgram.c",
    "bio/bss_fd.c",
    "bio/bss_file.c",
    "bio/bss_mem.c",
    "bio/bss_null.c",
    "bio/bss_sock.c",
    "bn/bn_add.c",
    "bn/bn_bpsw.c",
    "bn/bn_const.c",
    "bn/bn_convert.c",
    "bn/bn_ctx.c",
    "bn/bn_div.c",
    "bn/bn_err.c",
    "bn/bn_exp.c",
    "bn/bn_gcd.c",
    "bn/bn_isqrt.c",
    "bn/bn_kron.c",
    "bn/bn_lib.c",
    "bn/bn_mod.c",
    "bn/bn_mod_sqrt.c",
    "bn/bn_mont.c",
    "bn/bn_mul.c",
    "bn/bn_prime.c",
    "bn/bn_primitives.c",
    "bn/bn_print.c",
    "bn/bn_rand.c",
    "bn/bn_recp.c",
    "bn/bn_shift.c",
    "bn/bn_small_primes.c",
    "bn/bn_sqr.c",
    "bn/bn_word.c",
    "buffer/buf_err.c",
    "buffer/buffer.c",
    "bytestring/bs_ber.c",
    "bytestring/bs_cbb.c",
    "bytestring/bs_cbs.c",
    "camellia/cmll_cfb.c",
    "camellia/cmll_ctr.c",
    "camellia/cmll_ecb.c",
    "camellia/cmll_misc.c",
    "camellia/cmll_ofb.c",
    "cast/c_cfb64.c",
    "cast/c_ecb.c",
    "cast/c_enc.c",
    "cast/c_ofb64.c",
    "cast/c_skey.c",
    "chacha/chacha.c",
    "cmac/cm_ameth.c",
    "cmac/cm_pmeth.c",
    "cmac/cmac.c",
    "cms/cms_asn1.c",
    "cms/cms_att.c",
    "cms/cms_dd.c",
    "cms/cms_enc.c",
    "cms/cms_env.c",
    "cms/cms_err.c",
    "cms/cms_ess.c",
    "cms/cms_io.c",
    "cms/cms_kari.c",
    "cms/cms_lib.c",
    "cms/cms_pwri.c",
    "cms/cms_sd.c",
    "cms/cms_smime.c",
    "conf/conf_api.c",
    "conf/conf_def.c",
    "conf/conf_err.c",
    "conf/conf_lib.c",
    "conf/conf_mall.c",
    "conf/conf_mod.c",
    "conf/conf_sap.c",
    "ct/ct_b64.c",
    "ct/ct_err.c",
    "ct/ct_log.c",
    "ct/ct_oct.c",
    "ct/ct_policy.c",
    "ct/ct_prn.c",
    "ct/ct_sct.c",
    "ct/ct_sct_ctx.c",
    "ct/ct_vfy.c",
    "ct/ct_x509v3.c",
    "curve25519/curve25519-generic.c",
    "curve25519/curve25519.c",
    "des/cbc_cksm.c",
    "des/cbc_enc.c",
    "des/cfb64ede.c",
    "des/cfb64enc.c",
    "des/cfb_enc.c",
    "des/des_enc.c",
    "des/ecb3_enc.c",
    "des/ecb_enc.c",
    "des/ede_cbcm_enc.c",
    "des/enc_read.c",
    "des/enc_writ.c",
    "des/fcrypt.c",
    "des/fcrypt_b.c",
    "des/ofb64ede.c",
    "des/ofb64enc.c",
    "des/ofb_enc.c",
    "des/pcbc_enc.c",
    "des/qud_cksm.c",
    "des/set_key.c",
    "des/str2key.c",
    "des/xcbc_enc.c",
    "dh/dh_ameth.c",
    "dh/dh_asn1.c",
    "dh/dh_check.c",
    "dh/dh_err.c",
    "dh/dh_gen.c",
    "dh/dh_key.c",
    "dh/dh_lib.c",
    "dh/dh_pmeth.c",
    "dsa/dsa_ameth.c",
    "dsa/dsa_asn1.c",
    "dsa/dsa_err.c",
    "dsa/dsa_gen.c",
    "dsa/dsa_key.c",
    "dsa/dsa_lib.c",
    "dsa/dsa_meth.c",
    "dsa/dsa_ossl.c",
    "dsa/dsa_pmeth.c",
    "dsa/dsa_prn.c",
    "ec/ec_ameth.c",
    "ec/ec_asn1.c",
    "ec/ec_check.c",
    "ec/ec_curve.c",
    "ec/ec_cvt.c",
    "ec/ec_err.c",
    "ec/ec_key.c",
    "ec/ec_kmeth.c",
    "ec/ec_lib.c",
    "ec/ec_mult.c",
    "ec/ec_oct.c",
    "ec/ec_pmeth.c",
    "ec/ec_print.c",
    "ec/eck_prn.c",
    "ec/ecp_mont.c",
    "ec/ecp_oct.c",
    "ec/ecp_smpl.c",
    "ec/ecx_methods.c",
    "ecdh/ecdh.c",
    "ecdsa/ecdsa.c",
    "engine/engine_stubs.c",
    "err/err.c",
    "err/err_all.c",
    "err/err_prn.c",
    "evp/bio_b64.c",
    "evp/bio_enc.c",
    "evp/bio_md.c",
    "evp/e_aes.c",
    "evp/e_bf.c",
    "evp/e_camellia.c",
    "evp/e_cast.c",
    "evp/e_chacha.c",
    "evp/e_chacha20poly1305.c",
    "evp/e_des.c",
    "evp/e_des3.c",
    "evp/e_idea.c",
    "evp/e_null.c",
    "evp/e_rc2.c",
    "evp/e_rc4.c",
    "evp/e_sm4.c",
    "evp/e_xcbc_d.c",
    "evp/evp_aead.c",
    "evp/evp_cipher.c",
    "evp/evp_digest.c",
    "evp/evp_encode.c",
    "evp/evp_err.c",
    "evp/evp_key.c",
    "evp/evp_names.c",
    "evp/evp_pbe.c",
    "evp/evp_pkey.c",
    "evp/m_md4.c",
    "evp/m_md5.c",
    "evp/m_md5_sha1.c",
    "evp/m_null.c",
    "evp/m_ripemd.c",
    "evp/m_sha1.c",
    "evp/m_sha3.c",
    "evp/m_sigver.c",
    "evp/m_sm3.c",
    "evp/m_wp.c",
    "evp/p_legacy.c",
    "evp/p_lib.c",
    "evp/p_sign.c",
    "evp/p_verify.c",
    "evp/pmeth_fn.c",
    "evp/pmeth_gn.c",
    "evp/pmeth_lib.c",
    "hkdf/hkdf.c",
    "hmac/hm_ameth.c",
    "hmac/hm_pmeth.c",
    "hmac/hmac.c",
    "idea/i_cbc.c",
    "idea/i_cfb64.c",
    "idea/i_ecb.c",
    "idea/i_ofb64.c",
    "idea/i_skey.c",
    "kdf/hkdf_evp.c",
    "kdf/kdf_err.c",
    "lhash/lhash.c",
    "md4/md4.c",
    "md5/md5.c",
    "modes/cbc128.c",
    "modes/ccm128.c",
    "modes/cfb128.c",
    "modes/ctr128.c",
    "modes/gcm128.c",
    "modes/ofb128.c",
    "modes/xts128.c",
    "objects/obj_dat.c",
    "objects/obj_err.c",
    "objects/obj_lib.c",
    "objects/obj_xref.c",
    "ocsp/ocsp_asn.c",
    "ocsp/ocsp_cl.c",
    "ocsp/ocsp_err.c",
    "ocsp/ocsp_ext.c",
    "ocsp/ocsp_ht.c",
    "ocsp/ocsp_lib.c",
    "ocsp/ocsp_prn.c",
    "ocsp/ocsp_srv.c",
    "ocsp/ocsp_vfy.c",
    "pem/pem_all.c",
    "pem/pem_err.c",
    "pem/pem_info.c",
    "pem/pem_lib.c",
    "pem/pem_oth.c",
    "pem/pem_pk8.c",
    "pem/pem_pkey.c",
    "pem/pem_sign.c",
    "pem/pem_x509.c",
    "pem/pem_xaux.c",
    "pem/pvkfmt.c",
    "pkcs12/p12_add.c",
    "pkcs12/p12_asn.c",
    "pkcs12/p12_attr.c",
    "pkcs12/p12_crt.c",
    "pkcs12/p12_decr.c",
    "pkcs12/p12_init.c",
    "pkcs12/p12_key.c",
    "pkcs12/p12_kiss.c",
    "pkcs12/p12_mutl.c",
    "pkcs12/p12_npas.c",
    "pkcs12/p12_p8d.c",
    "pkcs12/p12_p8e.c",
    "pkcs12/p12_sbag.c",
    "pkcs12/p12_utl.c",
    "pkcs12/pk12err.c",
    "pkcs7/pk7_asn1.c",
    "pkcs7/pk7_attr.c",
    "pkcs7/pk7_doit.c",
    "pkcs7/pk7_lib.c",
    "pkcs7/pk7_mime.c",
    "pkcs7/pk7_smime.c",
    "pkcs7/pkcs7err.c",
    "poly1305/poly1305.c",
    "rand/rand_err.c",
    "rand/rand_lib.c",
    "rand/randfile.c",
    "rc2/rc2_cbc.c",
    "rc2/rc2_ecb.c",
    "rc2/rc2_skey.c",
    "rc2/rc2cfb64.c",
    "rc2/rc2ofb64.c",
    "ripemd/ripemd.c",
    "rsa/rsa_ameth.c",
    "rsa/rsa_asn1.c",
    "rsa/rsa_blinding.c",
    "rsa/rsa_chk.c",
    "rsa/rsa_eay.c",
    "rsa/rsa_err.c",
    "rsa/rsa_gen.c",
    "rsa/rsa_lib.c",
    "rsa/rsa_meth.c",
    "rsa/rsa_none.c",
    "rsa/rsa_oaep.c",
    "rsa/rsa_pk1.c",
    "rsa/rsa_pmeth.c",
    "rsa/rsa_prn.c",
    "rsa/rsa_pss.c",
    "rsa/rsa_saos.c",
    "rsa/rsa_sign.c",
    "rsa/rsa_x931.c",
    "sha/sha1.c",
    "sha/sha256.c",
    "sha/sha3.c",
    "sha/sha512.c",
    "sm3/sm3.c",
    "sm4/sm4.c",
    "stack/stack.c",
    "ts/ts_asn1.c",
    "ts/ts_conf.c",
    "ts/ts_err.c",
    "ts/ts_lib.c",
    "ts/ts_req_print.c",
    "ts/ts_req_utils.c",
    "ts/ts_rsp_print.c",
    "ts/ts_rsp_sign.c",
    "ts/ts_rsp_utils.c",
    "ts/ts_rsp_verify.c",
    "ts/ts_verify_ctx.c",
    "txt_db/txt_db.c",
    "ui/ui_err.c",
    "ui/ui_lib.c",
    "ui/ui_null.c",
    "ui/ui_util.c",
    "whrlpool/wp_dgst.c",
    "x509/by_dir.c",
    "x509/by_file.c",
    "x509/by_mem.c",
    "x509/x509_addr.c",
    "x509/x509_akey.c",
    "x509/x509_akeya.c",
    "x509/x509_alt.c",
    "x509/x509_asid.c",
    "x509/x509_att.c",
    "x509/x509_bcons.c",
    "x509/x509_bitst.c",
    "x509/x509_cmp.c",
    "x509/x509_conf.c",
    "x509/x509_constraints.c",
    "x509/x509_cpols.c",
    "x509/x509_crld.c",
    "x509/x509_d2.c",
    "x509/x509_def.c",
    "x509/x509_err.c",
    "x509/x509_ext.c",
    "x509/x509_extku.c",
    "x509/x509_genn.c",
    "x509/x509_ia5.c",
    "x509/x509_info.c",
    "x509/x509_int.c",
    "x509/x509_issuer_cache.c",
    "x509/x509_lib.c",
    "x509/x509_lu.c",
    "x509/x509_ncons.c",
    "x509/x509_obj.c",
    "x509/x509_ocsp.c",
    "x509/x509_pcons.c",
    "x509/x509_pku.c",
    "x509/x509_pmaps.c",
    "x509/x509_policy.c",
    "x509/x509_prn.c",
    "x509/x509_purp.c",
    "x509/x509_r2x.c",
    "x509/x509_req.c",
    "x509/x509_set.c",
    "x509/x509_skey.c",
    "x509/x509_trs.c",
    "x509/x509_txt.c",
    "x509/x509_utl.c",
    "x509/x509_v3.c",
    "x509/x509_verify.c",
    "x509/x509_vfy.c",
    "x509/x509_vpm.c",
    "x509/x509cset.c",
    "x509/x509name.c",
    "x509/x509rset.c",
    "x509/x509spki.c",
    "x509/x509type.c",
    "x509/x_all.c",

    "empty.c",
};

const asm_elf_x86_64 = [_][]const u8{
    "aes/aes-elf-x86_64.S",
    "aes/bsaes-elf-x86_64.S",
    "aes/vpaes-elf-x86_64.S",
    "aes/aesni-elf-x86_64.S",
    "aes/aesni-sha1-elf-x86_64.S",
    "bn/modexp512-elf-x86_64.S",
    "bn/mont-elf-x86_64.S",
    "bn/mont5-elf-x86_64.S",
    "camellia/cmll-elf-x86_64.S",
    "md5/md5-elf-x86_64.S",
    "modes/ghash-elf-x86_64.S",
    "rc4/rc4-elf-x86_64.S",
    "rc4/rc4-md5-elf-x86_64.S",
    "sha/sha1-elf-x86_64.S",
    "sha/sha256-elf-x86_64.S",
    "sha/sha512-elf-x86_64.S",
    "whrlpool/wp-elf-x86_64.S",
    "cpuid-elf-x86_64.S",
    "bn/arch/amd64/bignum_add.S",
    "bn/arch/amd64/bignum_cmadd.S",
    "bn/arch/amd64/bignum_cmul.S",
    "bn/arch/amd64/bignum_mul.S",
    "bn/arch/amd64/bignum_mul_4_8_alt.S",
    "bn/arch/amd64/bignum_mul_8_16_alt.S",
    "bn/arch/amd64/bignum_sqr.S",
    "bn/arch/amd64/bignum_sqr_4_8_alt.S",
    "bn/arch/amd64/bignum_sqr_8_16_alt.S",
    "bn/arch/amd64/bignum_sub.S",
    "bn/arch/amd64/word_clz.S",
    "bn/arch/amd64/bn_arch.c",
};

const asm_macos_x86_64 = [_][]const u8{
    "aes/aes-macosx-x86_64.S",
    "aes/bsaes-macosx-x86_64.S",
    "aes/vpaes-macosx-x86_64.S",
    "aes/aesni-macosx-x86_64.S",
    "aes/aesni-sha1-macosx-x86_64.S",
    "bn/modexp512-macosx-x86_64.S",
    "bn/mont-macosx-x86_64.S",
    "bn/mont5-macosx-x86_64.S",
    "camellia/cmll-macosx-x86_64.S",
    "md5/md5-macosx-x86_64.S",
    "modes/ghash-macosx-x86_64.S",
    "rc4/rc4-macosx-x86_64.S",
    "rc4/rc4-md5-macosx-x86_64.S",
    "sha/sha1-macosx-x86_64.S",
    "sha/sha256-macosx-x86_64.S",
    "sha/sha512-macosx-x86_64.S",
    "whrlpool/wp-macosx-x86_64.S",
    "cpuid-macosx-x86_64.S",
    "bn/arch/amd64/bignum_add.S",
    "bn/arch/amd64/bignum_cmadd.S",
    "bn/arch/amd64/bignum_cmul.S",
    "bn/arch/amd64/bignum_mul.S",
    "bn/arch/amd64/bignum_mul_4_8_alt.S",
    "bn/arch/amd64/bignum_mul_8_16_alt.S",
    "bn/arch/amd64/bignum_sqr.S",
    "bn/arch/amd64/bignum_sqr_4_8_alt.S",
    "bn/arch/amd64/bignum_sqr_8_16_alt.S",
    "bn/arch/amd64/bignum_sub.S",
    "bn/arch/amd64/word_clz.S",
    "bn/arch/amd64/bn_arch.c",
};

const asm_mingw_x86_64 = [_][]const u8{
    "aes/aes-mingw64-x86_64.S",
    "aes/bsaes-mingw64-x86_64.S",
    "aes/vpaes-mingw64-x86_64.S",
    "aes/aesni-mingw64-x86_64.S",
    "aes/aesni-sha1-mingw64-x86_64.S",
    //"bn/modexp512-mingw64-x86_64.S",
    //"bn/mont-mingw64-x86_64.S",
    //"bn/mont5-mingw64-x86_64.S",
    "camellia/cmll-mingw64-x86_64.S",
    "md5/md5-mingw64-x86_64.S",
    "modes/ghash-mingw64-x86_64.S",
    "rc4/rc4-mingw64-x86_64.S",
    "rc4/rc4-md5-mingw64-x86_64.S",
    "sha/sha1-mingw64-x86_64.S",
    "sha/sha256-mingw64-x86_64.S",
    "sha/sha512-mingw64-x86_64.S",
    "whrlpool/wp-mingw64-x86_64.S",
    "cpuid-mingw64-x86_64.S",
};

const crypto_src_common_noasm = [_][]const u8{
    "aes/aes_core.c",
    "aes/aes_cbc.c",
    "camellia/camellia.c",
    "camellia/cmll_cbc.c",
    "rc4/rc4_enc.c",
    "rc4/rc4_skey.c",
    "whrlpool/wp_block.c",
};

const crypto_src_unix = [_][]const u8{
    "crypto_lock.c",
    "bio/b_posix.c",
    "bio/bss_log.c",
    "ui/ui_openssl.c",
};

const crypto_src_linux = [_][]const u8{
    "compat/getprogname_linux.c",
    "compat/strtonum.c",
    "compat/freezero.c",
    "compat/syslog_r.c",
    "compat/recallocarray.c",
    "compat/timingsafe_bcmp.c",
    "compat/timingsafe_memcmp.c",
};

const crypto_src_macos = [_][]const u8{
    "compat/freezero.c",
    "compat/syslog_r.c",
    "compat/strtonum.c",
    "compat/recallocarray.c",
    "compat/timingsafe_bcmp.c",
    "compat/timingsafe_memcmp.c",
    "compat/explicit_bzero.c",
    "compat/reallocarray.c",
};

const crypto_src_win32 = [_][]const u8{
    "compat/crypto_lock_win.c",
    "bio/b_win.c",
    "ui/ui_openssl_win.c",
    "compat/posix_win.c",

    "compat/getprogname_windows.c",
    "compat/arc4random.c",
    "compat/arc4random_uniform.c",
    "compat/explicit_bzero_win.c",
    "compat/strlcpy.c",
    "compat/strlcat.c",
    "compat/strndup.c",
    "compat/strsep.c",
    "compat/timegm.c",
    "compat/strtonum.c",
    "compat/freezero.c",
    "compat/syslog_r.c",
    "compat/recallocarray.c",
    "compat/reallocarray.c",
    "compat/timingsafe_bcmp.c",
    "compat/timingsafe_memcmp.c",
    "compat/getpagesize.c",
    "compat/getentropy_win.c",
};

const ssl_src = [_][]const u8{
    "bio_ssl.c",
    "d1_both.c",
    "d1_lib.c",
    "d1_pkt.c",
    "d1_srtp.c",
    "pqueue.c",
    "s3_cbc.c",
    "s3_lib.c",
    "ssl_asn1.c",
    "ssl_both.c",
    "ssl_cert.c",
    "ssl_ciph.c",
    "ssl_ciphers.c",
    "ssl_clnt.c",
    "ssl_err.c",
    "ssl_init.c",
    "ssl_kex.c",
    "ssl_lib.c",
    "ssl_methods.c",
    "ssl_packet.c",
    "ssl_pkt.c",
    "ssl_rsa.c",
    "ssl_seclevel.c",
    "ssl_sess.c",
    "ssl_sigalgs.c",
    "ssl_srvr.c",
    "ssl_stat.c",
    "ssl_tlsext.c",
    "ssl_transcript.c",
    "ssl_txt.c",
    "ssl_versions.c",
    "t1_enc.c",
    "t1_lib.c",
    "tls_buffer.c",
    "tls_content.c",
    "tls_key_share.c",
    "tls_lib.c",
    "tls12_key_schedule.c",
    "tls12_lib.c",
    "tls12_record_layer.c",
    "tls13_client.c",
    "tls13_error.c",
    "tls13_handshake.c",
    "tls13_handshake_msg.c",
    "tls13_key_schedule.c",
    "tls13_legacy.c",
    "tls13_lib.c",
    "tls13_quic.c",
    "tls13_record.c",
    "tls13_record_layer.c",
    "tls13_server.c",

    "empty.c",
};

const tls_src = [_][]const u8{
    "tls.c",
    "tls_bio_cb.c",
    "tls_client.c",
    "tls_config.c",
    "tls_conninfo.c",
    "tls_keypair.c",
    "tls_server.c",
    "tls_signer.c",
    "tls_ocsp.c",
    "tls_peer.c",
    "tls_util.c",
    "tls_verify.c",

    "empty.c",
};

const tls_win32_src = [_][]const u8{
    "compat/ftruncate.c",
    "compat/pread.c",
    "compat/pwrite.c",
};
