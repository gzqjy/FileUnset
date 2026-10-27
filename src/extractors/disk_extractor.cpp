#include "fileunnest/extractor.h"
#include "fileunnest/utils.h"
#include <string>
#include <vector>

namespace unnest {

namespace {

class DiskExtractor : public IExtractor {
public:
    std::string name() const override { return "DiskImageExtractor(SquashFS/VMDK/VHDX/DMG)"; }

    bool can_handle(const std::string& file_path,
                    const std::string& fmt,
                    const std::vector<uint8_t>&) const override {
        if (fmt == "squashfs" || fmt == "vmdk" || fmt == "vhdx" || fmt == "vhd" || fmt == "dmg" || fmt == "img" ||
            fmt == "fat" || fmt == "ntfs" || fmt == "ext2" || fmt == "ext3" || fmt == "ext4" || fmt == "hfs") {
            return true;
        }
        std::string ext = utils::get_extension(file_path);
        return (ext == ".squashfs" || ext == ".sqsh" || ext == ".vmdk" ||
                ext == ".vhdx" || ext == ".vhd" || ext == ".dmg" || ext == ".img" ||
                ext == ".fat" || ext == ".ntfs" || ext == ".ext2" || ext == ".ext3" || ext == ".ext4" || ext == ".hfs");
    }

    bool extract(const std::string& file_path,
                 const std::string& output_dir,
                 const UnnestConfig& config,
                 std::vector<ExtractedItem>& out_items) override {
        std::vector<uint8_t> hdr;
        utils::read_file_header(file_path, hdr, 512);
        std::string fmt = utils::detect_format(file_path, hdr);
        utils::make_dirs(output_dir);

        bool ok = false;
        if (fmt == "squashfs") {
            std::string sq_dest = utils::join_path(output_dir, "squashfs_root");
            ok = utils::run_external_cmd({"unsquashfs", "-f", "-d", sq_dest, file_path});
        }
        if (!ok) {
            ok = utils::run_external_cmd({"7z", "x", "-y", "-o" + output_dir, file_path});
        }
        if (!ok) return false;

        std::vector<std::string> files = utils::list_files_recursive(output_dir);
        uint64_t total_written = 0;
        for (const auto& f : files) {
            std::string rel = f.substr(output_dir.size());
            if (!rel.empty() && rel[0] == '/') rel = rel.substr(1);
            uint64_t fsz = utils::file_size(f);
            if (fsz > config.max_file_size || total_written + fsz > config.max_total_size) continue;
            total_written += fsz;
            ExtractedItem item;
            item.name = rel;
            item.saved_path = f;
            item.size = fsz;
            item.extractor_name = name();
            out_items.push_back(item);
        }
        return !out_items.empty();
    }
};

} // namespace

std::unique_ptr<IExtractor> create_disk_extractor() {
    return std::unique_ptr<IExtractor>(new DiskExtractor());
}

} // namespace unnest
