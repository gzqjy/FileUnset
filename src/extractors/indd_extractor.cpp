#include "fileunnest/extractor.h"
#include "fileunnest/utils.h"
#include <cstdint>
#include <cstring>

namespace unnest {

namespace {

// Adobe InDesign Master Page GUID: 06 06 ED F5 D8 1D 46 E5 BD 31 EF E7 FE 74 B7 1D
static const uint8_t kInDesignGuid[16] = {
    0x06, 0x06, 0xED, 0xF5, 0xD8, 0x1D, 0x46, 0xE5,
    0xBD, 0x31, 0xEF, 0xE7, 0xFE, 0x74, 0xB7, 0x1D
};

inline uint16_t read_u16_le(const uint8_t* p) {
    return static_cast<uint16_t>(p[0]) | (static_cast<uint16_t>(p[1]) << 8);
}

inline uint32_t read_u32_le(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) |
           (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) |
           (static_cast<uint32_t>(p[3]) << 24);
}

class InddExtractor : public IExtractor {
public:
    std::string name() const override { return "InddExtractor(AdobeInDesign)"; }

    bool can_handle(const std::string& file_path,
                    const std::string& fmt,
                    const std::vector<uint8_t>& header) const override {
        if (fmt == "indd" || utils::get_extension(file_path) == ".indd") return true;
        return header.size() >= 16 && std::memcmp(header.data(), kInDesignGuid, 16) == 0;
    }

    bool extract(const std::string& file_path,
                 const std::string& output_dir,
                 const UnnestConfig& config,
                 std::vector<ExtractedItem>& out_items) override {
        std::vector<uint8_t> data;
        if (!utils::read_entire_file(file_path, data, config.max_file_size)) return false;
        if (data.size() < 64 || std::memcmp(data.data(), kInDesignGuid, 16) != 0) return false;

        int item_idx = 0;

        // 1. Extract embedded XMP Metadata Packet (<x:xmpmeta ... </x:xmpmeta>) and any <xmpGImg:image> Base64 preview
        std::string raw_str(reinterpret_cast<const char*>(data.data()), data.size());
        size_t xmp_start = raw_str.find("<x:xmpmeta");
        if (xmp_start != std::string::npos) {
            size_t xmp_end = raw_str.find("</x:xmpmeta>", xmp_start);
            if (xmp_end != std::string::npos) {
                std::string xmp_xml = raw_str.substr(xmp_start, xmp_end + 12 - xmp_start);
                // Check for <xmpGImg:image>...</xmpGImg:image> Base64 thumbnail
                size_t img_s = xmp_xml.find("<xmpGImg:image>");
                size_t img_e = xmp_xml.find("</xmpGImg:image>", img_s);
                if (img_s != std::string::npos && img_e != std::string::npos) {
                    std::string b64 = xmp_xml.substr(img_s + 15, img_e - (img_s + 15));
                    // Replace &#xA; with newline before base64 decoding
                    std::string clean_b64;
                    clean_b64.reserve(b64.size());
                    for (size_t i = 0; i < b64.size(); ++i) {
                        if (b64.compare(i, 5, "&#xA;") == 0 || b64.compare(i, 5, "&#xa;") == 0) {
                            i += 4;
                        } else {
                            clean_b64.push_back(b64[i]);
                        }
                    }
                    std::vector<uint8_t> thumb = utils::base64_decode(clean_b64);
                    if (!thumb.empty()) {
                        std::string fname = "indd_xmp_preview_" + std::to_string(item_idx++) + ".jpg";
                        std::string out_path = utils::join_path(output_dir, fname);
                        if (utils::write_file(out_path, thumb.data(), thumb.size())) {
                            ExtractedItem item;
                            item.name = fname;
                            item.saved_path = out_path;
                            item.offset = xmp_start + img_s;
                            item.size = thumb.size();
                            item.extractor_name = name();
                            out_items.push_back(item);
                        }
                    }
                }
            }
        }

        // 2. Scan Contiguous Object Streams (past 4096-byte Master Pages) for embedded PNG, JPEG, PDF/AI, or ZIP/IDML objects
        size_t pos = 16;
        while (pos + 16 < data.size()) {
            // Embedded PNG
            if (std::memcmp(data.data() + pos, "\x89PNG\r\n\x1A\n", 8) == 0) {
                size_t png_end = 0;
                for (size_t e = pos + 8; e + 8 <= data.size(); ++e) {
                    if (std::memcmp(data.data() + e, "IEND", 4) == 0) {
                        png_end = e + 8;
                        break;
                    }
                }
                if (png_end > pos) {
                    std::string fname = "indd_embedded_" + std::to_string(item_idx++) + ".png";
                    std::string out_path = utils::join_path(output_dir, fname);
                    if (utils::write_file(out_path, data.data() + pos, png_end - pos)) {
                        ExtractedItem item;
                        item.name = fname;
                        item.saved_path = out_path;
                        item.offset = pos;
                        item.size = png_end - pos;
                        item.extractor_name = name();
                        out_items.push_back(item);
                    }
                    pos = png_end;
                    continue;
                }
            }

            // Embedded PDF / AI vector art
            if (std::memcmp(data.data() + pos, "%PDF-1.", 7) == 0) {
                size_t pdf_end = 0;
                for (size_t e = pos + 16; e + 5 <= data.size(); ++e) {
                    if (std::memcmp(data.data() + e, "%%EOF", 5) == 0) {
                        pdf_end = e + 5;
                        if (pdf_end < data.size() && data[pdf_end] == '\r') pdf_end++;
                        if (pdf_end < data.size() && data[pdf_end] == '\n') pdf_end++;
                        break;
                    }
                }
                if (pdf_end > pos) {
                    std::string fname = "indd_embedded_vector_" + std::to_string(item_idx++) + ".pdf";
                    std::string out_path = utils::join_path(output_dir, fname);
                    if (utils::write_file(out_path, data.data() + pos, pdf_end - pos)) {
                        ExtractedItem item;
                        item.name = fname;
                        item.saved_path = out_path;
                        item.offset = pos;
                        item.size = pdf_end - pos;
                        item.extractor_name = name();
                        out_items.push_back(item);
                    }
                    pos = pdf_end;
                    continue;
                }
            }

            // Embedded ZIP / IDML package
            if (pos + 30 <= data.size() && std::memcmp(data.data() + pos, "PK\x03\x04", 4) == 0) {
                uint16_t ver = read_u16_le(data.data() + pos + 4);
                uint16_t fn_len = read_u16_le(data.data() + pos + 26);
                if (ver >= 10 && ver <= 63 && fn_len > 0 && fn_len < 512) {
                    size_t zip_end = 0;
                    for (size_t e = pos + 30; e + 22 <= data.size(); ++e) {
                        if (std::memcmp(data.data() + e, "PK\x05\x06", 4) == 0) {
                            uint32_t cd_size = read_u32_le(data.data() + e + 12);
                            uint32_t cd_off = read_u32_le(data.data() + e + 16);
                            uint16_t c_len = read_u16_le(data.data() + e + 20);
                            if (pos + cd_off + cd_size == e && e + 22 + c_len <= data.size()) {
                                zip_end = e + 22 + c_len;
                                break;
                            }
                        }
                    }
                    if (zip_end > pos) {
                        std::string fname = "indd_embedded_package_" + std::to_string(item_idx++) + ".zip";
                        std::string out_path = utils::join_path(output_dir, fname);
                        if (utils::write_file(out_path, data.data() + pos, zip_end - pos)) {
                            ExtractedItem item;
                            item.name = fname;
                            item.saved_path = out_path;
                            item.offset = pos;
                            item.size = zip_end - pos;
                            item.extractor_name = name();
                            out_items.push_back(item);
                        }
                        pos = zip_end;
                        continue;
                    }
                }
            }

            pos++;
        }

        return !out_items.empty();
    }
};

} // namespace

std::unique_ptr<IExtractor> create_indd_extractor() {
    return std::unique_ptr<IExtractor>(new InddExtractor());
}

} // namespace unnest
