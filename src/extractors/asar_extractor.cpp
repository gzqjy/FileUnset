#include "fileunnest/extractor.h"
#include "fileunnest/utils.h"
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>

namespace unnest {

namespace {

inline uint32_t read_u32_le(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) |
           (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) |
           (static_cast<uint32_t>(p[3]) << 24);
}

void skip_ws(const std::string& s, size_t& i) {
    while (i < s.size() && std::isspace(static_cast<unsigned char>(s[i]))) ++i;
}

int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

void append_utf8_cp(std::string& out, uint32_t cp) {
    if (cp <= 0x7F) {
        out.push_back(static_cast<char>(cp));
    } else if (cp <= 0x7FF) {
        out.push_back(static_cast<char>(0xC0 | ((cp >> 6) & 0x1F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else if (cp <= 0xFFFF) {
        out.push_back(static_cast<char>(0xE0 | ((cp >> 12) & 0x0F)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else if (cp <= 0x10FFFF) {
        out.push_back(static_cast<char>(0xF0 | ((cp >> 18) & 0x07)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    }
}

std::string parse_json_string(const std::string& s, size_t& i) {
    skip_ws(s, i);
    if (i >= s.size() || s[i] != '"') return "";
    ++i;
    std::string out;
    while (i < s.size()) {
        char c = s[i++];
        if (c == '"') break;
        if (c == '\\' && i < s.size()) {
            char esc = s[i++];
            if (esc == 'n') out.push_back('\n');
            else if (esc == 't') out.push_back('\t');
            else if (esc == 'r') out.push_back('\r');
            else if (esc == 'u' && i + 4 <= s.size()) {
                int h0 = hex_nibble(s[i]), h1 = hex_nibble(s[i+1]), h2 = hex_nibble(s[i+2]), h3 = hex_nibble(s[i+3]);
                if (h0 >= 0 && h1 >= 0 && h2 >= 0 && h3 >= 0) {
                    uint32_t cp = static_cast<uint32_t>((h0 << 12) | (h1 << 8) | (h2 << 4) | h3);
                    i += 4;
                    append_utf8_cp(out, cp);
                }
            } else {
                out.push_back(esc);
            }
        } else {
            out.push_back(c);
        }
    }
    return utils::ensure_utf8(out);
}

uint64_t parse_json_number_or_str(const std::string& s, size_t& i) {
    skip_ws(s, i);
    if (i < s.size() && s[i] == '"') {
        std::string num_s = parse_json_string(s, i);
        return std::strtoull(num_s.c_str(), nullptr, 10);
    }
    size_t start = i;
    while (i < s.size() && (std::isdigit(static_cast<unsigned char>(s[i])) || s[i] == '-')) ++i;
    return std::strtoull(s.substr(start, i - start).c_str(), nullptr, 10);
}

void skip_json_value(const std::string& s, size_t& i) {
    skip_ws(s, i);
    if (i >= s.size()) return;
    if (s[i] == '"') {
        parse_json_string(s, i);
    } else if (s[i] == '{' || s[i] == '[') {
        char open = s[i], close = (open == '{') ? '}' : ']';
        int depth = 1;
        ++i;
        while (i < s.size() && depth > 0) {
            if (s[i] == '"') {
                parse_json_string(s, i);
            } else {
                if (s[i] == open) depth++;
                else if (s[i] == close) depth--;
                ++i;
            }
        }
    } else {
        while (i < s.size() && s[i] != ',' && s[i] != '}' && s[i] != ']') ++i;
    }
}

struct AsarFileEntry {
    std::string rel_path;
    uint64_t offset = 0;
    uint64_t size = 0;
    bool unpacked = false;
};

void parse_asar_node(const std::string& json, size_t& i, const std::string& prefix, std::vector<AsarFileEntry>& entries) {
    skip_ws(json, i);
    if (i >= json.size() || json[i] != '{') {
        skip_json_value(json, i);
        return;
    }
    ++i; // skip '{'

    bool has_files = false;
    bool has_size = false;
    uint64_t file_size = 0;
    uint64_t file_offset = 0;
    bool unpacked = false;

    while (i < json.size()) {
        skip_ws(json, i);
        if (i < json.size() && json[i] == '}') { ++i; break; }
        std::string key = parse_json_string(json, i);
        skip_ws(json, i);
        if (i < json.size() && json[i] == ':') ++i;
        skip_ws(json, i);

        if (key == "files" && i < json.size() && json[i] == '{') {
            has_files = true;
            ++i; // skip '{' of "files"
            while (i < json.size()) {
                skip_ws(json, i);
                if (i < json.size() && json[i] == '}') { ++i; break; }
                std::string child_name = parse_json_string(json, i);
                skip_ws(json, i);
                if (i < json.size() && json[i] == ':') ++i;
                std::string child_path = prefix.empty() ? child_name : (prefix + "/" + child_name);
                parse_asar_node(json, i, child_path, entries);
                skip_ws(json, i);
                if (i < json.size() && json[i] == ',') ++i;
            }
        } else if (key == "size") {
            has_size = true;
            file_size = parse_json_number_or_str(json, i);
        } else if (key == "offset") {
            file_offset = parse_json_number_or_str(json, i);
        } else if (key == "unpacked") {
            if (json.compare(i, 4, "true") == 0) { unpacked = true; i += 4; }
            else skip_json_value(json, i);
        } else {
            skip_json_value(json, i);
        }
        skip_ws(json, i);
        if (i < json.size() && json[i] == ',') ++i;
    }

    if (!has_files && has_size && !unpacked && !prefix.empty()) {
        AsarFileEntry e;
        e.rel_path = prefix;
        e.offset = file_offset;
        e.size = file_size;
        entries.push_back(e);
    }
}

class AsarExtractor : public IExtractor {
public:
    std::string name() const override { return "AsarExtractor(Electron)"; }

    bool can_handle(const std::string& file_path,
                    const std::string& fmt,
                    const std::vector<uint8_t>& header) const override {
        if (fmt == "asar" || utils::get_extension(file_path) == ".asar") return true;
        return header.size() >= 24 &&
               read_u32_le(header.data()) == 4 &&
               std::memcmp(header.data() + 16, "{\"files\"", 8) == 0;
    }

    bool extract(const std::string& file_path,
                 const std::string& output_dir,
                 const UnnestConfig& config,
                 std::vector<ExtractedItem>& out_items) override {
        std::ifstream ifs(file_path, std::ios::binary);
        if (!ifs) return false;
        uint8_t pickle_hdr[16];
        if (!ifs.read(reinterpret_cast<char*>(pickle_hdr), 16)) return false;

        uint32_t data_size = read_u32_le(pickle_hdr + 0);
        uint32_t header_size = read_u32_le(pickle_hdr + 4);
        uint32_t str_size = read_u32_le(pickle_hdr + 12);
        if (data_size != 4 || str_size == 0 || str_size > 64 * 1024 * 1024) return false;

        std::string json_str(str_size, '\0');
        if (!ifs.read(&json_str[0], str_size)) return false;

        uint64_t payload_base = 8ULL + header_size;
        uint64_t total_fsize = utils::file_size(file_path);

        std::vector<AsarFileEntry> entries;
        size_t pos = 0;
        parse_asar_node(json_str, pos, "", entries);

        for (const auto& e : entries) {
            std::string safe_rel = utils::sanitize_relpath(e.rel_path);
            if (!utils::should_extract_item(safe_rel, config)) {
                continue;
            }

            uint64_t abs_offset = payload_base + e.offset;
            if (abs_offset + e.size > total_fsize || e.size > config.max_file_size) continue;

            std::vector<uint8_t> buf(static_cast<size_t>(e.size));
            ifs.seekg(static_cast<std::streamoff>(abs_offset), std::ios::beg);
            if (e.size > 0 && !ifs.read(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(e.size))) {
                continue;
            }

            std::string out_path = utils::join_path(output_dir, safe_rel);
            if (utils::write_file(out_path, buf.data(), buf.size())) {
                ExtractedItem item;
                item.name = safe_rel;
                item.saved_path = out_path;
                item.offset = abs_offset;
                item.size = e.size;
                item.extractor_name = name();
                out_items.push_back(item);
            }
        }

        return !out_items.empty();
    }
};

} // namespace

std::unique_ptr<IExtractor> create_asar_extractor() {
    return std::unique_ptr<IExtractor>(new AsarExtractor());
}

} // namespace unnest
