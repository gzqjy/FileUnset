#include "fileunnest/extractor.h"
#include "fileunnest/utils.h"
#include <cstdint>
#include <cstring>

namespace unnest {

namespace {

inline uint16_t read_u16_le(const uint8_t* p) {
    return static_cast<uint16_t>(p[0]) | (static_cast<uint16_t>(p[1]) << 8);
}

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

class CarveExtractor : public IExtractor {
public:
    std::string name() const override { return "CarveExtractor(SizeAware/Polyglot)"; }

    bool can_handle(const std::string&,
                    const std::string& fmt,
                    const std::vector<uint8_t>&) const override {
        return (fmt == "jpeg" || fmt == "png" || fmt == "gif" || fmt == "bmp" ||
                fmt == "shell-script" || fmt == "elf" || fmt == "pe-executable" ||
                fmt == "onenote" || fmt == "binary");
    }

    bool extract(const std::string& file_path,
                 const std::string& output_dir,
                 const UnnestConfig& config,
                 std::vector<ExtractedItem>& out_items) override {
        if (!config.enable_carving) return false;
        std::vector<uint8_t> data;
        if (!utils::read_entire_file(file_path, data, config.max_file_size)) return false;
        if (data.size() < 24) return false;

        int carved_idx = 0;
        size_t pos = 1; // Strictly > 0 so we only carve embedded/appended payloads

        while (pos + 16 < data.size()) {
            // 1. Embedded PNG: \x89PNG\r\n\x1A\n ... IEND + 4-byte CRC
            if (std::memcmp(data.data() + pos, "\x89PNG\r\n\x1A\n", 8) == 0) {
                size_t png_end = 0;
                for (size_t e = pos + 8; e + 8 <= data.size(); ++e) {
                    if (std::memcmp(data.data() + e, "IEND", 4) == 0) {
                        png_end = e + 8;
                        break;
                    }
                }
                if (png_end > pos) {
                    uint64_t len = png_end - pos;
                    std::string fname = "carved_" + std::to_string(carved_idx++) + "_0x" + std::to_string(pos) + ".png";
                    std::string out_path = utils::join_path(output_dir, fname);
                    if (utils::write_file(out_path, data.data() + pos, static_cast<size_t>(len))) {
                        ExtractedItem item;
                        item.name = fname;
                        item.saved_path = out_path;
                        item.offset = pos;
                        item.size = len;
                        item.extractor_name = name();
                        out_items.push_back(item);
                    }
                    pos = png_end;
                    continue;
                }
            }

            // 2. Embedded JPEG: \xFF\xD8\xFF(\xE0|\xE1|\xDB) ... \xFF\xD9
            if (data[pos] == 0xFF && data[pos + 1] == 0xD8 && data[pos + 2] == 0xFF &&
                (data[pos + 3] == 0xE0 || data[pos + 3] == 0xE1 || data[pos + 3] == 0xDB)) {
                size_t jpg_end = 0;
                for (size_t e = pos + 4; e + 2 <= data.size(); ++e) {
                    if (data[e] == 0xFF && data[e + 1] == 0xD9) {
                        jpg_end = e + 2;
                        break;
                    }
                }
                if (jpg_end > pos) {
                    uint64_t len = jpg_end - pos;
                    std::string fname = "carved_" + std::to_string(carved_idx++) + "_0x" + std::to_string(pos) + ".jpg";
                    std::string out_path = utils::join_path(output_dir, fname);
                    if (utils::write_file(out_path, data.data() + pos, static_cast<size_t>(len))) {
                        ExtractedItem item;
                        item.name = fname;
                        item.saved_path = out_path;
                        item.offset = pos;
                        item.size = len;
                        item.extractor_name = name();
                        out_items.push_back(item);
                    }
                    pos = jpg_end;
                    continue;
                }
            }

            // 3. Embedded BMP: "BM" + uint32_le bfSize + 4 zero reserved bytes + valid biSize (40, 108, 124)
            if (pos + 26 <= data.size() && data[pos] == 'B' && data[pos + 1] == 'M' &&
                read_u32_le(data.data() + pos + 6) == 0) {
                uint32_t bf_size = read_u32_le(data.data() + pos + 2);
                uint32_t bi_size = read_u32_le(data.data() + pos + 14);
                if (bf_size >= 54 && pos + bf_size <= data.size() &&
                    (bi_size == 40 || bi_size == 108 || bi_size == 124)) {
                    std::string fname = "carved_" + std::to_string(carved_idx++) + "_0x" + std::to_string(pos) + ".bmp";
                    std::string out_path = utils::join_path(output_dir, fname);
                    if (utils::write_file(out_path, data.data() + pos, bf_size)) {
                        ExtractedItem item;
                        item.name = fname;
                        item.saved_path = out_path;
                        item.offset = pos;
                        item.size = bf_size;
                        item.extractor_name = name();
                        out_items.push_back(item);
                    }
                    pos += bf_size;
                    continue;
                }
            }

            // 4. Size-Aware ZIP Local File Header: PK\x03\x04 -> scan for matching EOCD PK\x05\x06
            // EOCD layout: [4B PK\x05\x06][2B disk][2B cd_disk][2B entries_disk][2B entries_total][4B cd_size][4B cd_offset][2B comment_len]
            // Note: cd_offset is relative to the start of the ZIP archive (pos)!
            if (pos + 30 <= data.size() && std::memcmp(data.data() + pos, "PK\x03\x04", 4) == 0) {
                uint16_t ver = read_u16_le(data.data() + pos + 4);
                uint16_t method = read_u16_le(data.data() + pos + 8);
                uint16_t fn_len = read_u16_le(data.data() + pos + 26);
                if (ver >= 10 && ver <= 63 && fn_len > 0 && fn_len < 512 &&
                    (method == 0 || method == 8 || method == 9 || method == 12 || method == 14 || method == 93)) {
                    size_t zip_end = 0;
                    for (size_t e = pos + 30; e + 22 <= data.size(); ++e) {
                        if (std::memcmp(data.data() + e, "PK\x05\x06", 4) == 0) {
                            uint32_t cd_size = read_u32_le(data.data() + e + 12);
                            uint32_t cd_offset = read_u32_le(data.data() + e + 16);
                            uint16_t comment_len = read_u16_le(data.data() + e + 20);
                            if (e + 22 + comment_len <= data.size()) {
                                // Exact match if pos + cd_offset + cd_size == e
                                if (pos + cd_offset + cd_size == e) {
                                    zip_end = e + 22 + comment_len;
                                    break; // Found exact EOCD for this specific ZIP!
                                }
                                if (zip_end == 0) zip_end = e + 22 + comment_len;
                            }
                        }
                    }
                    if (zip_end == 0) zip_end = data.size();
                    uint64_t len = zip_end - pos;
                    std::string fname = "carved_" + std::to_string(carved_idx++) + "_0x" + std::to_string(pos) + ".zip";
                    std::string out_path = utils::join_path(output_dir, fname);
                    if (utils::write_file(out_path, data.data() + pos, static_cast<size_t>(len))) {
                        ExtractedItem item;
                        item.name = fname;
                        item.saved_path = out_path;
                        item.offset = pos;
                        item.size = len;
                        item.extractor_name = name();
                        out_items.push_back(item);
                    }
                    pos = zip_end;
                    continue;
                }
            }

            // 5. Size-Aware 7z Header: 37 7A BC AF 27 1C 00 (32-byte header: NextHeaderOffset at +12, NextHeaderSize at +20)
            // Exact 7z archive size = 32 + NextHeaderOffset + NextHeaderSize!
            if (pos + 32 <= data.size() && std::memcmp(data.data() + pos, "\x37\x7A\xBC\xAF\x27\x1C\x00", 7) == 0) {
                uint64_t next_hdr_off = read_u64_le(data.data() + pos + 12);
                uint64_t next_hdr_sz = read_u64_le(data.data() + pos + 20);
                uint64_t exact_len = 32ULL + next_hdr_off + next_hdr_sz;
                if (exact_len < 32 || pos + exact_len > data.size()) {
                    exact_len = data.size() - pos;
                }
                std::string fname = "carved_" + std::to_string(carved_idx++) + "_0x" + std::to_string(pos) + ".7z";
                std::string out_path = utils::join_path(output_dir, fname);
                if (utils::write_file(out_path, data.data() + pos, static_cast<size_t>(exact_len))) {
                    ExtractedItem item;
                    item.name = fname;
                    item.saved_path = out_path;
                    item.offset = pos;
                    item.size = exact_len;
                    item.extractor_name = name();
                    out_items.push_back(item);
                }
                pos += static_cast<size_t>(exact_len);
                continue;
            }

            // 6. Size-Aware XZ signature: FD 37 7A 58 5A 00 ... ends at 12-byte Stream Footer ending with "YZ" (0x59 0x5A)
            if (pos + 24 <= data.size() && std::memcmp(data.data() + pos, "\xFD\x37\x7A\x58\x5A\x00", 6) == 0) {
                size_t xz_end = data.size();
                for (size_t e = pos + 12; e + 2 <= data.size(); ++e) {
                    if (data[e] == 'Y' && data[e + 1] == 'Z') {
                        xz_end = e + 2;
                        break;
                    }
                }
                uint64_t len = xz_end - pos;
                std::string fname = "carved_" + std::to_string(carved_idx++) + "_0x" + std::to_string(pos) + ".tar.xz";
                std::string out_path = utils::join_path(output_dir, fname);
                if (utils::write_file(out_path, data.data() + pos, static_cast<size_t>(len))) {
                    ExtractedItem item;
                    item.name = fname;
                    item.saved_path = out_path;
                    item.offset = pos;
                    item.size = len;
                    item.extractor_name = name();
                    out_items.push_back(item);
                }
                pos = xz_end;
                continue;
            }

            // 7. RAR signature: Rar!\x1A\x07
            if (std::memcmp(data.data() + pos, "Rar!\x1A\x07", 6) == 0) {
                uint64_t len = data.size() - pos;
                std::string fname = "carved_" + std::to_string(carved_idx++) + "_0x" + std::to_string(pos) + ".rar";
                std::string out_path = utils::join_path(output_dir, fname);
                if (utils::write_file(out_path, data.data() + pos, static_cast<size_t>(len))) {
                    ExtractedItem item;
                    item.name = fname;
                    item.saved_path = out_path;
                    item.offset = pos;
                    item.size = len;
                    item.extractor_name = name();
                    out_items.push_back(item);
                }
                break;
            }

            // 8. GZIP signature: 1F 8B 08 (deflate) with valid flags (flags & 0xE0 == 0)
            if (data[pos] == 0x1F && data[pos + 1] == 0x8B && data[pos + 2] == 0x08 && (data[pos + 3] & 0xE0) == 0) {
                uint64_t len = data.size() - pos;
                std::string fname = "carved_" + std::to_string(carved_idx++) + "_0x" + std::to_string(pos) + ".tar.gz";
                std::string out_path = utils::join_path(output_dir, fname);
                if (utils::write_file(out_path, data.data() + pos, static_cast<size_t>(len))) {
                    ExtractedItem item;
                    item.name = fname;
                    item.saved_path = out_path;
                    item.offset = pos;
                    item.size = len;
                    item.extractor_name = name();
                    out_items.push_back(item);
                }
                break;
            }

            // 9. BZip2 signature: BZh[1-9]1AY&SY
            if (pos + 10 < data.size() && data[pos] == 'B' && data[pos + 1] == 'Z' && data[pos + 2] == 'h' &&
                data[pos + 3] >= '1' && data[pos + 3] <= '9' &&
                std::memcmp(data.data() + pos + 4, "\x31\x41\x59\x26\x53\x59", 6) == 0) {
                uint64_t len = data.size() - pos;
                std::string fname = "carved_" + std::to_string(carved_idx++) + "_0x" + std::to_string(pos) + ".tar.bz2";
                std::string out_path = utils::join_path(output_dir, fname);
                if (utils::write_file(out_path, data.data() + pos, static_cast<size_t>(len))) {
                    ExtractedItem item;
                    item.name = fname;
                    item.saved_path = out_path;
                    item.offset = pos;
                    item.size = len;
                    item.extractor_name = name();
                    out_items.push_back(item);
                }
                break;
            }

            // 10. Embedded PDF: %PDF-1. ... %%EOF
            if (std::memcmp(data.data() + pos, "%PDF-1.", 7) == 0) {
                size_t pdf_end = data.size();
                for (size_t e = pos + 16; e + 5 <= data.size(); ++e) {
                    if (std::memcmp(data.data() + e, "%%EOF", 5) == 0) {
                        pdf_end = e + 5;
                        if (pdf_end < data.size() && data[pdf_end] == '\r') pdf_end++;
                        if (pdf_end < data.size() && data[pdf_end] == '\n') pdf_end++;
                        break;
                    }
                }
                uint64_t len = pdf_end - pos;
                std::string fname = "carved_" + std::to_string(carved_idx++) + "_0x" + std::to_string(pos) + ".pdf";
                std::string out_path = utils::join_path(output_dir, fname);
                if (utils::write_file(out_path, data.data() + pos, static_cast<size_t>(len))) {
                    ExtractedItem item;
                    item.name = fname;
                    item.saved_path = out_path;
                    item.offset = pos;
                    item.size = len;
                    item.extractor_name = name();
                    out_items.push_back(item);
                }
                pos = pdf_end;
                continue;
            }

            // 11. PyInstaller CArchive Cookie ("MEI\014\013\012\013\016")
            if (std::memcmp(data.data() + pos, "MEI\x0C\x0B\x0A\x0B\x0E", 8) == 0 && pos + 24 <= data.size()) {
                uint32_t pkg_len = (static_cast<uint32_t>(data[pos + 8]) << 24) |
                                   (static_cast<uint32_t>(data[pos + 9]) << 16) |
                                   (static_cast<uint32_t>(data[pos + 10]) << 8) |
                                   static_cast<uint32_t>(data[pos + 11]);
                size_t cookie_end = pos + 24;
                if (pos + 88 <= data.size() && data[pos + 24] == 'p' && data[pos + 25] == 'y') {
                    cookie_end = pos + 88;
                }
                if (pkg_len > 0 && pkg_len <= cookie_end) {
                    size_t pkg_start = cookie_end - pkg_len;
                    std::string fname = "carved_pyinstaller_pkg_" + std::to_string(carved_idx++) + ".pkg";
                    std::string out_path = utils::join_path(output_dir, fname);
                    if (utils::write_file(out_path, data.data() + pkg_start, pkg_len)) {
                        ExtractedItem item;
                        item.name = fname;
                        item.saved_path = out_path;
                        item.offset = pkg_start;
                        item.size = pkg_len;
                        item.extractor_name = "CarveExtractor(PyInstaller)";
                        out_items.push_back(item);
                    }
                    pos = cookie_end;
                    continue;
                }
            }

            pos++;
        }

        return !out_items.empty();
    }
};

} // namespace

std::unique_ptr<IExtractor> create_carve_extractor() {
    return std::unique_ptr<IExtractor>(new CarveExtractor());
}

} // namespace unnest
