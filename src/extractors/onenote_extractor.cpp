#include "fileunnest/extractor.h"
#include "fileunnest/utils.h"
#include <cstdint>
#include <cstring>

namespace unnest {

namespace {

inline uint32_t read_u32_le(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) |
           (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) |
           (static_cast<uint32_t>(p[3]) << 24);
}

inline uint64_t read_u64_le(const uint8_t* p) {
    return static_cast<uint64_t>(read_u32_le(p)) |
           (static_cast<uint64_t>(read_u32_le(p + 4)) << 32);
}

// MS-ONESTORE Header GUID: {7B5C52E4-D88C-4DA7-AEB1-5378D02996D3}
static const uint8_t kOneNoteHeaderGuid[16] = {
    0xE4, 0x52, 0x5C, 0x7B, 0x8C, 0xD8, 0xA7, 0x4D,
    0xAE, 0xB1, 0x53, 0x78, 0xD0, 0x29, 0x96, 0xD3
};

// MS-ONESTORE FileDataStoreObject Header GUID: {BDE316E7-2665-4511-A4C4-8D4D0B7A9EAC}
static const uint8_t kFileDataStoreHeaderGuid[16] = {
    0xE7, 0x16, 0xE3, 0xBD, 0x65, 0x26, 0x11, 0x45,
    0xA4, 0xC4, 0x8D, 0x4D, 0x0B, 0x7A, 0x9E, 0xAC
};

std::string ext_from_detected(const std::string& fmt) {
    if (fmt == "zip") return ".zip";
    if (fmt == "7z") return ".7z";
    if (fmt == "rar") return ".rar";
    if (fmt == "pdf") return ".pdf";
    if (fmt == "png") return ".png";
    if (fmt == "jpeg") return ".jpg";
    if (fmt == "gif") return ".gif";
    if (fmt == "bmp") return ".bmp";
    if (fmt == "ole2") return ".doc";
    if (fmt == "rtf") return ".rtf";
    return ".bin";
}

class OneNoteExtractor : public IExtractor {
public:
    std::string name() const override { return "OneNoteExtractor(MS-ONESTORE)"; }

    bool can_handle(const std::string& file_path,
                    const std::string& fmt,
                    const std::vector<uint8_t>& header) const override {
        if (fmt == "onenote" || utils::get_extension(file_path) == ".one") return true;
        return header.size() >= 16 && std::memcmp(header.data(), kOneNoteHeaderGuid, 16) == 0;
    }

    bool extract(const std::string& file_path,
                 const std::string& output_dir,
                 const UnnestConfig& config,
                 std::vector<ExtractedItem>& out_items) override {
        std::vector<uint8_t> data;
        if (!utils::read_entire_file(file_path, data, config.max_file_size)) return false;
        if (data.size() < 36) return false;

        // Scan for FileDataStoreObject structure:
        // [16B guidHeader = kFileDataStoreHeaderGuid]
        // [8B  uint64_le cbLength]
        // [4B  uint32_le unused]
        // [8B  uint64_le reserved]
        // [cbLength bytes of FileData]
        // [padding to 8-byte alignment]
        // [16B guidFooter = {71FBA722-0F79-4A0B-BB13-899256426B24}]
        int obj_idx = 0;
        size_t pos = 0;
        while (pos + 36 <= data.size()) {
            if (std::memcmp(data.data() + pos, kFileDataStoreHeaderGuid, 16) == 0) {
                uint64_t cb_length = read_u64_le(data.data() + pos + 16);
                size_t data_start = pos + 36;
                if (cb_length > 0 && cb_length <= config.max_file_size && data_start + cb_length <= data.size()) {
                    std::vector<uint8_t> hdr(data.data() + data_start,
                                             data.data() + data_start + std::min<size_t>(static_cast<size_t>(cb_length), 512));
                    std::string fmt = utils::detect_format("", hdr);
                    std::string ext = ext_from_detected(fmt);
                    std::string fname = "onenote_object_" + std::to_string(obj_idx++) + ext;
                    std::string out_path = utils::join_path(output_dir, fname);
                    if (utils::write_file(out_path, data.data() + data_start, static_cast<size_t>(cb_length))) {
                        ExtractedItem item;
                        item.name = fname;
                        item.saved_path = out_path;
                        item.offset = data_start;
                        item.size = cb_length;
                        item.extractor_name = name();
                        out_items.push_back(item);
                    }
                    pos = data_start + static_cast<size_t>(cb_length);
                    continue;
                }
            }
            pos++;
        }

        return !out_items.empty();
    }
};

} // namespace

std::unique_ptr<IExtractor> create_onenote_extractor() {
    return std::unique_ptr<IExtractor>(new OneNoteExtractor());
}

} // namespace unnest
