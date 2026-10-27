#include "fileunnest/extractor.h"
#include "fileunnest/utils.h"
#include <cstdint>
#include <cstring>
#include <zlib.h>

namespace unnest {

namespace {

inline uint32_t read_u32_be(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24) |
           (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) |
           static_cast<uint32_t>(p[3]);
}

bool zlib_decompress_buf(const uint8_t* src, size_t src_len, std::vector<uint8_t>& out, size_t max_out) {
    z_stream strm;
    std::memset(&strm, 0, sizeof(strm));
    if (inflateInit(&strm) != Z_OK) return false;
    strm.next_in = const_cast<Bytef*>(src);
    strm.avail_in = static_cast<uInt>(src_len);
    uint8_t buf[16384];
    int ret = Z_OK;
    while (ret == Z_OK) {
        strm.next_out = buf;
        strm.avail_out = sizeof(buf);
        ret = inflate(&strm, Z_NO_FLUSH);
        if (ret != Z_OK && ret != Z_STREAM_END) {
            inflateEnd(&strm);
            return false;
        }
        size_t have = sizeof(buf) - strm.avail_out;
        if (out.size() + have > max_out) {
            inflateEnd(&strm);
            return false;
        }
        out.insert(out.end(), buf, buf + have);
    }
    inflateEnd(&strm);
    return !out.empty();
}

static const uint8_t kMeiMagic[8] = {'M', 'E', 'I', 0x0C, 0x0B, 0x0A, 0x0B, 0x0E};

class PyInstallerExtractor : public IExtractor {
public:
    std::string name() const override { return "PyInstallerExtractor(CArchive/TOC)"; }

    bool can_handle(const std::string& file_path,
                    const std::string& fmt,
                    const std::vector<uint8_t>&) const override {
        if (fmt == "pyinstaller-pkg") return true;
        if (fmt == "elf" || fmt == "pe-executable") {
            // Check if file contains MEI\x0c\x0b\x0a\x0b\x0e cookie in its last 64KB
            uint64_t fsz = utils::file_size(file_path);
            if (fsz < 24 || fsz > 512ULL * 1024 * 1024) return false;
            std::vector<uint8_t> data;
            if (!utils::read_entire_file(file_path, data)) return false;
            size_t scan_start = (data.size() > 65536) ? (data.size() - 65536) : 0;
            for (size_t i = scan_start; i + 24 <= data.size(); ++i) {
                if (std::memcmp(data.data() + i, kMeiMagic, 8) == 0) return true;
            }
        }
        return false;
    }

    bool extract(const std::string& file_path,
                 const std::string& output_dir,
                 const UnnestConfig& config,
                 std::vector<ExtractedItem>& out_items) override {
        std::vector<uint8_t> data;
        if (!utils::read_entire_file(file_path, data, config.max_file_size)) return false;
        if (data.size() < 24) return false;

        // Locate MEI cookie from the tail
        size_t cookie_pos = std::string::npos;
        for (size_t i = data.size() - 24; ; --i) {
            if (std::memcmp(data.data() + i, kMeiMagic, 8) == 0) {
                cookie_pos = i;
                break;
            }
            if (i == 0) break;
        }
        if (cookie_pos == std::string::npos) return false;

        // PyInstaller CArchive Cookie:
        // [8B magic] [4B BE pkg_len] [4B BE toc_offset] [4B BE toc_len] [4B BE pyvers] ([64B py_libname] in v2.1+)
        uint32_t pkg_len = read_u32_be(data.data() + cookie_pos + 8);
        uint32_t toc_offset = read_u32_be(data.data() + cookie_pos + 12);
        uint32_t toc_len = read_u32_be(data.data() + cookie_pos + 16);

        size_t cookie_size = 24;
        if (cookie_pos + 88 <= data.size() &&
            (std::memcmp(data.data() + cookie_pos + 24, "python", 6) == 0 ||
             std::memcmp(data.data() + cookie_pos + 24, "libpython", 9) == 0)) {
            cookie_size = 88;
        }

        size_t archive_end = cookie_pos + cookie_size;
        if (pkg_len == 0 || pkg_len > archive_end) return false;
        size_t pkg_start = archive_end - pkg_len;

        // If toc_len > 0, parse TOC entries and extract each file
        if (toc_len > 0 && pkg_start + toc_offset + toc_len <= archive_end) {
            size_t tpos = pkg_start + toc_offset;
            size_t tend = tpos + toc_len;
            int idx = 0;

            while (tpos + 18 <= tend) {
                // TOC Entry:
                // [4B BE entry_size] [4B BE data_offset] [4B BE comp_len] [4B BE uncomp_len]
                // [1B comp_flag] [1B type_code] [null-terminated utf8 name]
                uint32_t entry_len = read_u32_be(data.data() + tpos);
                if (entry_len < 18 || tpos + entry_len > tend) break;

                uint32_t d_off = read_u32_be(data.data() + tpos + 4);
                uint32_t c_len = read_u32_be(data.data() + tpos + 8);
                uint32_t u_len = read_u32_be(data.data() + tpos + 12);
                uint8_t c_flag = data[tpos + 16];
                char type_code = static_cast<char>(data[tpos + 17]);

                size_t name_max = entry_len - 18;
                const char* raw_nm = reinterpret_cast<const char*>(data.data() + tpos + 18);
                size_t nm_len = 0;
                while (nm_len < name_max && raw_nm[nm_len] != '\0') nm_len++;
                std::string item_name(raw_nm, nm_len);
                if (item_name.empty()) item_name = "pyi_entry_" + std::to_string(idx++);

                // Append standard extension if missing for known PyInstaller type codes
                if (item_name.find('.') == std::string::npos) {
                    if (type_code == 's' || type_code == 'M' || type_code == 'm') item_name += ".pyc";
                    else if (type_code == 'z' || type_code == 'Z') item_name += ".pyz";
                }

                if (!utils::should_extract_item(item_name, config)) {
                    tpos += entry_len;
                    continue;
                }

                size_t abs_data_off = pkg_start + d_off;
                if (abs_data_off + c_len <= archive_end && u_len <= config.max_file_size) {
                    std::vector<uint8_t> payload;
                    if (c_flag == 1) {
                        zlib_decompress_buf(data.data() + abs_data_off, c_len, payload, static_cast<size_t>(config.max_file_size));
                    } else {
                        payload.assign(data.data() + abs_data_off, data.data() + abs_data_off + c_len);
                    }
                    if (!payload.empty()) {
                        std::string safe_rel = utils::sanitize_relpath(item_name);
                        std::string out_path = utils::join_path(output_dir, safe_rel);
                        if (utils::write_file(out_path, payload.data(), payload.size())) {
                            ExtractedItem item;
                            item.name = safe_rel;
                            item.saved_path = out_path;
                            item.offset = abs_data_off;
                            item.size = payload.size();
                            item.extractor_name = name();
                            out_items.push_back(item);
                        }
                    }
                }
                tpos += entry_len;
            }
            if (!out_items.empty()) return true;
        }

        // If TOC is empty (minimal cookie-only package), extract the raw .pkg slice
        std::string fname = "carved_pyinstaller_pkg_0.pkg";
        std::string out_path = utils::join_path(output_dir, fname);
        if (utils::write_file(out_path, data.data() + pkg_start, pkg_len)) {
            ExtractedItem item;
            item.name = fname;
            item.saved_path = out_path;
            item.offset = pkg_start;
            item.size = pkg_len;
            item.extractor_name = name();
            out_items.push_back(item);
            return true;
        }
        return false;
    }
};

} // namespace

std::unique_ptr<IExtractor> create_pyinstaller_extractor() {
    return std::unique_ptr<IExtractor>(new PyInstallerExtractor());
}

} // namespace unnest
