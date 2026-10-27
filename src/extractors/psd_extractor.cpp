#include "fileunnest/extractor.h"
#include "fileunnest/utils.h"
#include <cstdint>
#include <cstring>

namespace unnest {

namespace {

inline uint32_t read_u32_be(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24) |
           (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) |
           static_cast<uint32_t>(p[3]);
}

inline uint64_t read_u64_be(const uint8_t* p) {
    return (static_cast<uint64_t>(read_u32_be(p)) << 32) |
           static_cast<uint64_t>(read_u32_be(p + 4));
}

class PsdExtractor : public IExtractor {
public:
    std::string name() const override { return "PsdExtractor(SmartObjects)"; }

    bool can_handle(const std::string& file_path,
                    const std::string& fmt,
                    const std::vector<uint8_t>& header) const override {
        if (fmt == "psd" || fmt == "psb" ||
            utils::get_extension(file_path) == ".psd" || utils::get_extension(file_path) == ".psb") {
            return true;
        }
        return header.size() >= 4 && std::memcmp(header.data(), "8BPS", 4) == 0;
    }

    bool extract(const std::string& file_path,
                 const std::string& output_dir,
                 const UnnestConfig& config,
                 std::vector<ExtractedItem>& out_items) override {
        std::vector<uint8_t> data;
        if (!utils::read_entire_file(file_path, data, config.max_file_size)) return false;
        if (data.size() < 26 || std::memcmp(data.data(), "8BPS", 4) != 0) return false;
        uint16_t version = (static_cast<uint16_t>(data[4]) << 8) | static_cast<uint16_t>(data[5]);
        if (version != 1 && version != 2) return false;

        // Scan for Additional Layer Information blocks with signature "8BIM" or "8B64" and key "lnk2" / "lnkD" / "lnkE"
        int obj_idx = 0;
        for (size_t pos = 26; pos + 12 < data.size(); ++pos) {
            bool is_8bim = (std::memcmp(data.data() + pos, "8BIM", 4) == 0);
            bool is_8b64 = (std::memcmp(data.data() + pos, "8B64", 4) == 0);
            if (!is_8bim && !is_8b64) continue;

            const uint8_t* key = data.data() + pos + 4;
            if (std::memcmp(key, "lnk2", 4) != 0 && std::memcmp(key, "lnkD", 4) != 0 && std::memcmp(key, "lnkE", 4) != 0) continue;

            // In PSB (version 2), lnk2/lnkD/lnkE or 8B64 blocks use 64-bit length
            bool use_64bit_len = is_8b64 || (version == 2);
            if (use_64bit_len && pos + 16 > data.size()) continue;

            uint64_t block_len = use_64bit_len ? read_u64_be(data.data() + pos + 8)
                                               : static_cast<uint64_t>(read_u32_be(data.data() + pos + 8));
            size_t block_start = pos + (use_64bit_len ? 16 : 12);
            if (block_start + block_len > data.size()) continue;

            // Inside lnk2/lnkD, each linked/embedded layer record starts with uint64_be rec_len and "liFD"
            size_t rpos = block_start;
            while (rpos + 24 < block_start + block_len) {
                if (std::memcmp(data.data() + rpos, "liFD", 4) == 0) {
                    // Version (4 bytes) + Pascal/Unicode filename + file type + uint64_be size + raw file bytes
                    // We can locate the embedded file header or parse liFD fields:
                    // After "liFD" (4) + version (4) + ID pascal string (1+len) + Unicode filename (4 + 2*chars) + filetype (4) + creator (4) + datasize (8) + has_open_desc (1)
                    size_t p = rpos + 8;
                    if (p >= block_start + block_len) break;
                    uint8_t id_len = data[p];
                    p += 1 + id_len;
                    if (p + 4 > block_start + block_len) break;
                    uint32_t u_chars = read_u32_be(data.data() + p);
                    p += 4;
                    if (p + u_chars * 2 > block_start + block_len) break;
                    std::string orig_name = utils::utf16be_to_utf8(data.data() + p, u_chars * 2);
                    p += u_chars * 2;
                    if (p + 16 > block_start + block_len) break;
                    p += 8; // skip filetype(4) + creator(4)
                    uint64_t fsize = read_u64_be(data.data() + p);
                    p += 8;
                    if (p < block_start + block_len) {
                        uint8_t has_desc = data[p++];
                        if (has_desc != 0) {
                            // Skip descriptor if present, or scan forward for known magic within record
                        }
                        if (fsize > 0 && p + fsize <= block_start + block_len && fsize <= config.max_file_size) {
                            if (orig_name.empty()) orig_name = "smart_object_" + std::to_string(obj_idx++) + ".bin";
                            orig_name = utils::sanitize_relpath(orig_name);
                            std::string out_path = utils::join_path(output_dir, orig_name);
                            if (utils::write_file(out_path, data.data() + p, static_cast<size_t>(fsize))) {
                                ExtractedItem item;
                                item.name = orig_name;
                                item.saved_path = out_path;
                                item.offset = p;
                                item.size = fsize;
                                item.extractor_name = name();
                                out_items.push_back(item);
                            }
                            rpos = p + static_cast<size_t>(fsize);
                            continue;
                        }
                    }
                }
                rpos++;
            }
            pos = block_start + static_cast<size_t>(block_len) - 1;
        }

        return !out_items.empty();
    }
};

} // namespace

std::unique_ptr<IExtractor> create_psd_extractor() {
    return std::unique_ptr<IExtractor>(new PsdExtractor());
}

} // namespace unnest
