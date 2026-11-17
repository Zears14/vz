#include "vz.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

typedef struct VisitCtx {
    size_t count;
    int saw_mesh;
} VisitCtx;

static bool visit_cb(const VzStatViewC* st, const char* name, size_t name_len, void* ud) {
    VisitCtx* ctx = (VisitCtx*)ud;
    (void)st;
    ctx->count++;
    if (name_len == 8 && memcmp(name, "mesh.bin", 8) == 0) {
        ctx->saw_mesh = 1;
    }
    return true;
}

int main(int argc, char** argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <archive.vz> <compacted.vz>\n", argv[0]);
        return 2;
    }
    assert(vz_abi_version() == VZ_ABI_VERSION);

    const char* arc_path = argv[1];
    const char* comp_path = argv[2];

    VzWriterConfigC wcfg = vz_writer_config_default();
    wcfg.default_codec = VZ_CODEC_ZSTD;
    wcfg.target_cluster_size = 4096;
    VzWriterHandle* w = NULL;
    assert(vz_writer_create(arc_path, &wcfg, &w) == VZ_OK);

    assert(vz_writer_add_dir(w, "/assets", 0755, 1700000000000000000LL) == VZ_OK);
    const char* small = "inline C greeting";
    VzEntryOptionsC meta = vz_entry_options_default();
    meta.has_owner = true;
    meta.uid = 1000;
    meta.gid = 1000;
    meta.has_btime = true;
    meta.mtime_ns = 1700000001000000000LL;
    meta.btime_ns = 1699000000000000555LL;
    assert(vz_writer_add_file(w, "/assets/hello.txt", (const uint8_t*)small, strlen(small), &meta) == VZ_OK);

    /* Chunked streaming write */
    uint8_t big[10000];
    for (size_t i = 0; i < sizeof(big); ++i) {
        big[i] = (uint8_t)((i * 7) & 0xFF);
    }
    VzStreamFileHandle* sf = NULL;
    assert(vz_writer_file_begin(w, "/assets/mesh.bin", NULL, &sf) == VZ_OK);
    assert(vz_writer_file_write(w, sf, big, 3000) == VZ_OK);
    assert(vz_writer_file_write(w, sf, big + 3000, 7000) == VZ_OK);
    assert(vz_writer_file_end(w, sf) == VZ_OK);

    assert(vz_writer_add_special(w, "/assets/pipe0", VZ_KIND_FIFO, NULL) == VZ_OK);
    assert(vz_writer_add_file(w, "/assets/old.txt", (const uint8_t*)"obsolete", 8, NULL) == VZ_OK);
    assert(vz_writer_add_hardlink(w, "/assets/hello_hl.txt", "/assets/hello.txt") == VZ_OK);
    assert(vz_writer_finish(w) == VZ_OK);

    /* Apply an LSM overlay deleting /assets/old.txt, adding /assets/patch.txt, symlink, hardlink */
    VzAppendHandle* app = NULL;
    assert(vz_append_open(arc_path, NULL, &app) == VZ_OK);
    assert(vz_append_delete(app, "/assets/old.txt") == VZ_OK);
    assert(vz_append_add_file(app, "/assets/patch.txt", (const uint8_t*)"v2", 2, NULL) == VZ_OK);
    assert(vz_append_add_symlink(app, "/assets/latest.txt", "patch.txt", 0777, 0) == VZ_OK);
    assert(vz_append_add_hardlink(app, "/assets/patch_hl.txt", "/assets/patch.txt") == VZ_OK);
    assert(vz_append_finish(app) == VZ_OK);

    VzArchive* arc = NULL;
    assert(vz_archive_open(arc_path, NULL, &arc) == VZ_OK);
    assert(vz_archive_lsm_runs(arc) == 2);

    bool ex = true;
    assert(vz_archive_exists(arc, "/assets/old.txt", &ex) == VZ_OK);
    assert(!ex);

    /* Zero-copy range read into stack buffer */
    uint8_t stack_buf[128];
    size_t got_n = 0;
    assert(vz_archive_read_range_into(arc, "/assets/mesh.bin", 4096, 128, stack_buf, sizeof(stack_buf), &got_n) == VZ_OK);
    assert(got_n == 128);
    assert(memcmp(stack_buf, big + 4096, 128) == 0);

    /* Zero-alloc readdir_visit */
    VisitCtx vctx = {0, 0};
    assert(vz_archive_readdir_visit(arc, "/assets", visit_cb, &vctx) == VZ_OK);
    assert(vctx.saw_mesh == 1);

    /* FUSE3 VFS check including zero-copy _into, readlink, owner/btime */
    VzFuseVol* vol = NULL;
    assert(vz_fuse_mount(arc, &vol) == VZ_OK);
    VzFuseAttrC dir_attr = {0};
    assert(vz_fuse_lookup(vol, VZ_FUSE_ROOT_ID, "assets", &dir_attr) == VZ_OK);

    VzFuseAttrC hello_attr = {0};
    assert(vz_fuse_lookup(vol, dir_attr.ino, "hello.txt", &hello_attr) == VZ_OK);
    assert(hello_attr.uid == 1000 && hello_attr.gid == 1000);
    assert(hello_attr.crtime_sec == 1699000000 && hello_attr.crtime_nsec == 555);

    VzFuseAttrC sym_attr = {0};
    assert(vz_fuse_lookup(vol, dir_attr.ino, "latest.txt", &sym_attr) == VZ_OK);
    VzBytes sym_target = {0};
    assert(vz_fuse_readlink(vol, sym_attr.ino, &sym_target) == VZ_OK);
    assert(sym_target.len == 9 && memcmp(sym_target.data, "patch.txt", 9) == 0);
    vz_bytes_free(&sym_target);

    VzFuseAttrC mesh_attr = {0};
    assert(vz_fuse_lookup(vol, dir_attr.ino, "mesh.bin", &mesh_attr) == VZ_OK);
    assert(mesh_attr.size == sizeof(big));
    VzFuseFh* fh = NULL;
    assert(vz_fuse_open(vol, mesh_attr.ino, &fh) == VZ_OK);

    uint8_t page_buf[256];
    size_t fuse_n = 0;
    assert(vz_fuse_read_into(vol, fh, 100, 256, page_buf, sizeof(page_buf), &fuse_n) == VZ_OK);
    assert(fuse_n == 256 && memcmp(page_buf, big + 100, 256) == 0);

    vz_fuse_close(fh);
    vz_fuse_unmount(vol);

    /* Compact back to 1 run with RS(4,2) enabled and verify */
    VzCompactOptionsC copts = vz_compact_options_default();
    copts.rs_parity_k = 4;
    copts.rs_parity_m = 2;
    assert(vz_archive_compact(arc, comp_path, &copts) == VZ_OK);
    vz_archive_close(arc);

    VzVerifyReportC rep = {0};
    assert(vz_verify_file(comp_path, NULL, &rep) == VZ_OK);
    assert(rep.boot_ecc_ok && rep.error_count == 0);

    printf("c_example OK (abi=%u clusters=%zu)\n", vz_abi_version(), rep.clusters_checked);
    return 0;
}
