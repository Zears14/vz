#include "vz.hpp"

#include <cassert>
#include <iostream>
#include <string>
#include <vector>

int main(int argc, char** argv) {
    if (argc < 3) {
        std::cerr << "usage: " << argv[0] << " <archive.vz> <compacted.vz>\n";
        return 2;
    }
    assert(vz::abi_version() == VZ_ABI_VERSION);

    const std::string arc_path = argv[1];
    const std::string comp_path = argv[2];

    {
        auto cfg = vz_writer_config_default();
        cfg.default_codec = VZ_CODEC_ZSTD;
        cfg.target_cluster_size = 4096;
        auto w = vz::Writer::create(arc_path, cfg);
        w.add_dir("/pak", 0755);
        w.add_file("/pak/config.ini", "[render]\nvsync=1\n");
        w.add_file("/pak/remove.me", "temporary");
        w.add_symlink("/pak/latest.ini", "config.ini");

        auto sf = w.begin_file("/pak/stream.bin");
        std::vector<uint8_t> part(5000, 0xAB);
        sf.write(part.data(), part.size());
        sf.write("END");
        sf.finish();

        w.finish();
    }

    {
        auto app = vz::AppendWriter::open(arc_path);
        app.remove("/pak/remove.me");
        app.add_file("/pak/hotfix.txt", "patched-v2");
        app.add_symlink("/pak/hot_link.txt", "hotfix.txt");
        app.finish();
    }

    auto arc = vz::Archive::open(arc_path);
    assert(arc.lsm_runs() == 2);
    assert(!arc.exists("/pak/remove.me"));
    assert(arc.get("/pak/hotfix.txt").as_string_view() == "patched-v2");

    uint8_t dst[16];
    size_t n = arc.get_range_into("/pak/stream.bin", 4998, 5, dst, sizeof(dst));
    assert(n == 5 && dst[0] == 0xAB && dst[1] == 0xAB && dst[2] == 'E');

    size_t visited = 0;
    arc.readdir_visit("/pak", [&](const VzStatViewC&, std::string_view) {
        ++visited;
        return true;
    });
    assert(visited >= 1);

    auto vol = vz::FuseVolume::mount(arc);
    auto pak = vol.lookup(VZ_FUSE_ROOT_ID, "pak");
    auto sym_attr = vol.lookup(pak.ino, "hot_link.txt");
    assert(vol.readlink(sym_attr.ino).as_string_view() == "hotfix.txt");

    auto stream_attr = vol.lookup(pak.ino, "stream.bin");
    auto fh = vol.open(stream_attr.ino);
    uint8_t fbuf[8];
    assert(vol.read_into(fh, 5000, 3, fbuf, sizeof(fbuf)) == 3);
    assert(fbuf[0] == 'E' && fbuf[1] == 'N' && fbuf[2] == 'D');

    auto entries = vol.readdirplus(pak.ino, 0, 16);
    assert(entries.size() == 7); // ., .., config.ini, hot_link.txt, hotfix.txt, latest.ini, stream.bin

    arc.compact(comp_path);
    auto arc2 = vz::Archive::open(comp_path);
    assert(arc2.lsm_runs() == 1);
    auto rep = vz::Archive::verify(comp_path);
    assert(rep.boot_ecc_ok && rep.error_count == 0);

    std::cout << "cpp_example OK (entries=" << arc2.total_entries() << ")\n";
    return 0;
}
