#include "fileunnest/extractor.h"
#include "fileunnest/utils.h"
#include <cctype>
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

inline int hex_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

std::vector<uint8_t> decode_rtf_hex(const char* data, size_t len) {
    std::vector<uint8_t> out;
    out.reserve(len / 2);
    int hi = -1;
    for (size_t i = 0; i < len; ++i) {
        int v = hex_val(data[i]);
        if (v < 0) continue;
        if (hi < 0) {
            hi = v;
        } else {
            out.push_back(static_cast<uint8_t>((hi << 4) | v));
            hi = -1;
        }
    }
    return out;
}

// Parse OLE 1.0 object header from RTF \objdata and extract NativeData
bool unwrap_ole1_object(const std::vector<uint8_t>& raw,
                        std::string& out_class_name,
                        std::vector<uint8_t>& out_native) {
    // OLE 1.0 header:
    // [uint32_le OleVersion (typically 0x00000501)]
    // [uint32_le FormatID (1=Link, 2=Embedded, 3=Static, 5=Presentation)]
    // [uint32_le ClassNameLen] [ClassName bytes...]
    // [uint32_le TopicNameLen] [TopicName bytes...]
    // [uint32_le ItemNameLen]  [ItemName bytes...]
    // [uint32_le NativeDataSize] [NativeData...]
    if (raw.size() < 24) return false;
    uint32_t format_id = read_u32_le(raw.data() + 4);
    if (format_id != 1 && format_id != 2) return false;

    size_t pos = 8;
    for (int i = 0; i < 3; ++i) {
        if (pos + 4 > raw.size()) return false;
        uint32_t slen = read_u32_le(raw.data() + pos);
        pos += 4;
        if (slen > 1024 || pos + slen > raw.size()) return false;
        if (i == 0 && slen > 0) {
            out_class_name.assign(reinterpret_cast<const char*>(raw.data() + pos), slen - 1);
            out_class_name = utils::ensure_utf8(out_class_name);
        }
        pos += slen;
    }

    if (pos + 4 > raw.size()) return false;
    uint32_t native_sz = read_u32_le(raw.data() + pos);
    pos += 4;
    if (native_sz == 0 || pos + native_sz > raw.size()) return false;

    out_native.assign(raw.data() + pos, raw.data() + pos + native_sz);
    return true;
}

class RtfExtractor : public IExtractor {
public:
    std::string name() const override { return "RtfExtractor(OLE1.0/Pict)"; }

    bool can_handle(const std::string& file_path,
                    const std::string& fmt,
                    const std::vector<uint8_t>& header) const override {
        if (fmt == "rtf" || utils::get_extension(file_path) == ".rtf") return true;
        return header.size() >= 5 && std::memcmp(header.data(), "{\\rtf", 5) == 0;
    }

    bool extract(const std::string& file_path,
                 const std::string& output_dir,
                 const UnnestConfig& config,
                 std::vector<ExtractedItem>& out_items) override {
        std::vector<uint8_t> data;
        if (!utils::read_entire_file(file_path, data, config.max_file_size)) return false;
        if (data.size() < 7 || std::memcmp(data.data(), "{\\rtf", 5) != 0) return false;

        std::string text(reinterpret_cast<const char*>(data.data()), data.size());
        int pict_idx = 0;
        int obj_idx = 0;

        // 1. Scan for {\pict ... } blocks
        size_t pos = 0;
        while ((pos = text.find("\\pict", pos)) != std::string::npos) {
            // Find matching closing '}' for the {\pict group
            size_t cur = pos + 5;
            int depth = 1;
            size_t last_ctrl_end = cur;
            std::string blip_ext = ".bin";

            while (cur < text.size() && depth > 0) {
                if (text[cur] == '{') depth++;
                else if (text[cur] == '}') depth--;
                cur++;
            }
            if (depth == 0 && cur > pos + 6) {
                std::string group = text.substr(pos, cur - pos - 1);
                if (group.find("\\pngblip") != std::string::npos) blip_ext = ".png";
                else if (group.find("\\jpegblip") != std::string::npos) blip_ext = ".jpg";
                else if (group.find("\\emfblip") != std::string::npos) blip_ext = ".emf";
                else if (group.find("\\wmetafile") != std::string::npos) blip_ext = ".wmf";
                else if (group.find("\\dibitmap") != std::string::npos) blip_ext = ".dib";

                // Locate start of hex payload after the last control word + space in \pict header
                size_t last_space = group.find_last_of(" \t\r\n");
                if (last_space != std::string::npos && last_space + 1 < group.size()) {
                    size_t hex_start = last_space + 1;
                    std::vector<uint8_t> decoded = decode_rtf_hex(group.data() + hex_start, group.size() - hex_start);
                    if (!decoded.empty() && decoded.size() <= config.max_file_size) {
                        std::string fname = "rtf_pict_" + std::to_string(pict_idx++) + blip_ext;
                        std::string out_path = utils::join_path(output_dir, fname);
                        if (utils::write_file(out_path, decoded.data(), decoded.size())) {
                            ExtractedItem item;
                            item.name = fname;
                            item.saved_path = out_path;
                            item.offset = pos + hex_start;
                            item.size = decoded.size();
                            item.extractor_name = name();
                            out_items.push_back(item);
                        }
                    }
                }
                (void)last_ctrl_end;
                pos = cur;
                continue;
            }
            pos += 5;
        }

        // 2. Scan for \objdata blocks (OLE 1.0 embedded objects / packages)
        pos = 0;
        while ((pos = text.find("\\objdata", pos)) != std::string::npos) {
            size_t cur = pos + 8;
            while (cur < text.size() && (std::isalnum(static_cast<unsigned char>(text[cur])))) cur++; // skip any digits
            size_t hex_start = cur;
            int depth = 1;
            while (cur < text.size() && depth > 0) {
                if (text[cur] == '{') depth++;
                else if (text[cur] == '}') depth--;
                cur++;
            }
            if (depth == 0 && cur > hex_start + 1) {
                std::vector<uint8_t> raw_ole1 = decode_rtf_hex(text.data() + hex_start, (cur - 1) - hex_start);
                std::string class_name;
                std::vector<uint8_t> native_data;
                if (unwrap_ole1_object(raw_ole1, class_name, native_data) && !native_data.empty()) {
                    std::string det = utils::detect_format("", native_data);
                    std::string ext = ".ole";
                    if (det == "ole2") {
                        if (class_name.find("Excel") != std::string::npos) ext = ".xls";
                        else if (class_name.find("Word") != std::string::npos) ext = ".doc";
                        else ext = ".ole";
                    } else if (det == "zip") ext = ".zip";
                    else if (det == "png") ext = ".png";

                    // If ClassName is "Package" and native_data is an OLE10Native stream (not full CFB), wrap or unwrap it directly
                    if (det != "ole2" && class_name == "Package" && native_data.size() >= 20) {
                        uint16_t flags = static_cast<uint16_t>(native_data[4]) | (static_cast<uint16_t>(native_data[5]) << 8);
                        if (flags == 2) {
                            size_t p = 6;
                            while (p < native_data.size() && native_data[p] != 0) p++;
                            p++;
                            size_t fn_s = p;
                            while (p < native_data.size() && native_data[p] != 0) p++;
                            if (p < native_data.size()) {
                                std::string orig_fn(reinterpret_cast<const char*>(native_data.data() + fn_s), p - fn_s);
                                p++;
                                if (p + 8 <= native_data.size()) {
                                    p += 4; // skip flags2 + unknown
                                    uint32_t tlen = read_u32_le(native_data.data() + p);
                                    p += 4 + tlen;
                                    if (p + 4 <= native_data.size()) {
                                        uint32_t dlen = read_u32_le(native_data.data() + p);
                                        p += 4;
                                        if (p + dlen <= native_data.size()) {
                                            std::string clean_fn = utils::sanitize_relpath(utils::base_name(utils::ensure_utf8(orig_fn)));
                                            std::string out_p = utils::join_path(output_dir, clean_fn);
                                            if (utils::write_file(out_p, native_data.data() + p, dlen)) {
                                                ExtractedItem item;
                                                item.name = clean_fn;
                                                item.saved_path = out_p;
                                                item.offset = pos;
                                                item.size = dlen;
                                                item.extractor_name = "RtfExtractor(OLE1.0-Package)";
                                                out_items.push_back(item);
                                                pos = cur;
                                                continue;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    std::string safe_cls = class_name.empty() ? "object" : utils::sanitize_relpath(class_name);
                    std::string fname = "rtf_obj_" + std::to_string(obj_idx++) + "_" + safe_cls + ext;
                    std::string out_path = utils::join_path(output_dir, fname);
                    if (utils::write_file(out_path, native_data.data(), native_data.size())) {
                        ExtractedItem item;
                        item.name = fname;
                        item.saved_path = out_path;
                        item.offset = pos;
                        item.size = native_data.size();
                        item.extractor_name = name();
                        out_items.push_back(item);
                    }
                }
                pos = cur;
                continue;
            }
            pos += 8;
        }

        return !out_items.empty();
    }
};

} // namespace

std::unique_ptr<IExtractor> create_rtf_extractor() {
    return std::unique_ptr<IExtractor>(new RtfExtractor());
}

} // namespace unnest
