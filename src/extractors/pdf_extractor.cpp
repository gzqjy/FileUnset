#include "fileunnest/extractor.h"
#include "fileunnest/utils.h"
#include <cctype>
#include <cstdio>
#include <cstring>
#include <zlib.h>

namespace unnest {

namespace {

bool zlib_decompress(const uint8_t* src, size_t src_len, std::vector<uint8_t>& out, size_t max_out) {
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

int hex_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

std::string decode_pdf_filename(const std::string& dict) {
    // 1. Prefer /UF over /F for Unicode filenames
    const char* keys[] = {"/UF", "/F", nullptr};
    for (int k = 0; keys[k]; ++k) {
        size_t klen = std::strlen(keys[k]);
        size_t pos = 0;
        while ((pos = dict.find(keys[k], pos)) != std::string::npos) {
            char next_c = (pos + klen < dict.size()) ? dict[pos + klen] : '\0';
            if (next_c == ' ' || next_c == '(' || next_c == '<') {
                size_t p = pos + klen;
                while (p < dict.size() && dict[p] == ' ') p++;
                if (p < dict.size() && dict[p] == '(') {
                    size_t end_p = dict.find(')', p + 1);
                    if (end_p != std::string::npos) {
                        std::string raw = dict.substr(p + 1, end_p - p - 1);
                        if (raw.size() >= 2 && static_cast<uint8_t>(raw[0]) == 0xFE && static_cast<uint8_t>(raw[1]) == 0xFF) {
                            return utils::utf16be_to_utf8(reinterpret_cast<const uint8_t*>(raw.data() + 2), raw.size() - 2);
                        }
                        return utils::ensure_utf8(raw);
                    }
                } else if (p < dict.size() && dict[p] == '<') {
                    size_t end_p = dict.find('>', p + 1);
                    if (end_p != std::string::npos) {
                        std::vector<uint8_t> bytes;
                        for (size_t i = p + 1; i + 1 < end_p; ) {
                            if (std::isspace(static_cast<unsigned char>(dict[i]))) { i++; continue; }
                            int hi = hex_val(dict[i]);
                            int lo = hex_val(dict[i + 1]);
                            if (hi >= 0 && lo >= 0) bytes.push_back(static_cast<uint8_t>((hi << 4) | lo));
                            i += 2;
                        }
                        if (bytes.size() >= 2 && bytes[0] == 0xFE && bytes[1] == 0xFF) {
                            return utils::utf16be_to_utf8(bytes.data() + 2, bytes.size() - 2);
                        }
                        std::string s(reinterpret_cast<const char*>(bytes.data()), bytes.size());
                        return utils::ensure_utf8(s);
                    }
                }
            }
            pos += klen;
        }
    }
    return "";
}

class PdfExtractor : public IExtractor {
public:
    std::string name() const override { return "PdfExtractor(pdfdetach/native)"; }

    bool can_handle(const std::string& file_path,
                    const std::string& fmt,
                    const std::vector<uint8_t>& header) const override {
        if (fmt == "pdf" || fmt == "ai") return true;
        if (header.size() >= 5 && std::memcmp(header.data(), "%PDF-", 5) == 0) return true;
        std::string ext = utils::get_extension(file_path);
        return ext == ".pdf" || ext == ".ai";
    }

    bool extract(const std::string& file_path,
                 const std::string& output_dir,
                 const UnnestConfig& config,
                 std::vector<ExtractedItem>& out_items) override {
        utils::make_dirs(output_dir);

        // 1. Try Poppler tools: pdfdetach for attachments + pdfimages for scanned page images
        bool poppler_invoked = false;
        if (utils::run_external_cmd({"pdfdetach", "-saveall", "-o", output_dir, file_path})) {
            poppler_invoked = true;
        }
        std::string img_prefix = utils::join_path(output_dir, "page");
        if (utils::run_external_cmd({"pdfimages", "-png", "-p", file_path, img_prefix})) {
            poppler_invoked = true;
        }

        if (poppler_invoked) {
            std::vector<std::string> files = utils::list_files_recursive(output_dir);
            for (const auto& f : files) {
                std::string rel = f.substr(output_dir.size());
                if (!rel.empty() && rel[0] == '/') rel = rel.substr(1);
                if (!utils::should_extract_item(rel, config)) {
                    std::remove(f.c_str());
                    continue;
                }
                ExtractedItem item;
                item.name = rel;
                item.saved_path = f;
                item.size = utils::file_size(f);
                item.extractor_name = "PdfExtractor(poppler)";
                out_items.push_back(item);
            }
            if (!out_items.empty()) return true;
        }

        // 2. If no attachments or XObjects found and image filtering is active, render pages via pdftoppm
        if (config.filter_image && utils::run_external_cmd({"pdftoppm", "-png", "-r", "150", file_path, img_prefix})) {
            std::vector<std::string> files = utils::list_files_recursive(output_dir);
            for (const auto& f : files) {
                std::string rel = f.substr(output_dir.size());
                if (!rel.empty() && rel[0] == '/') rel = rel.substr(1);
                ExtractedItem item;
                item.name = rel;
                item.saved_path = f;
                item.size = utils::file_size(f);
                item.extractor_name = "PdfExtractor(pdftoppm)";
                out_items.push_back(item);
            }
            if (!out_items.empty()) return true;
        }

        // 3. Native C++ parser for /EmbeddedFiles, /Subtype /EmbeddedFile, and image/object streams
        std::vector<uint8_t> data;
        if (!utils::read_entire_file(file_path, data, config.max_file_size)) return false;

        std::string raw(reinterpret_cast<const char*>(data.data()), data.size());
        size_t pos = 0;
        int stream_idx = 0;

        while ((pos = raw.find("stream", pos)) != std::string::npos) {
            // Check boundary: "stream" must be preceded by whitespace/delimiter and followed by \r\n or \n
            if (pos > 0 && std::isalpha(static_cast<unsigned char>(raw[pos - 1]))) {
                pos += 6;
                continue;
            }
            size_t data_start = pos + 6;
            if (data_start < raw.size() && raw[data_start] == '\r') data_start++;
            if (data_start >= raw.size() || raw[data_start] != '\n') {
                pos += 6;
                continue;
            }
            data_start++;

            size_t end_pos = raw.find("endstream", data_start);
            if (end_pos == std::string::npos) break;

            // Inspect dictionary before "stream" (up to 512 bytes back)
            size_t dict_start = (pos > 512) ? (pos - 512) : 0;
            std::string dict = raw.substr(dict_start, pos - dict_start);

            bool is_embedded = (dict.find("/EmbeddedFile") != std::string::npos);
            bool is_dct = (dict.find("/DCTDecode") != std::string::npos);
            bool is_image = (dict.find("/Subtype /Image") != std::string::npos || dict.find("/Subtype/Image") != std::string::npos);
            bool is_flate = (dict.find("/FlateDecode") != std::string::npos);

            size_t stream_len = end_pos - data_start;
            if (stream_len > 0 && raw[data_start + stream_len - 1] == '\n') {
                stream_len--;
                if (stream_len > 0 && raw[data_start + stream_len - 1] == '\r') {
                    stream_len--;
                }
            } else if (stream_len > 0 && raw[data_start + stream_len - 1] == '\r') {
                stream_len--;
            }

            if ((is_embedded || is_dct || is_image) && stream_len > 0) {
                std::vector<uint8_t> payload;
                if (is_flate) {
                    zlib_decompress(data.data() + data_start, stream_len, payload, static_cast<size_t>(config.max_file_size));
                } else {
                    payload.assign(data.data() + data_start, data.data() + data_start + stream_len);
                }

                if (!payload.empty()) {
                    // Try to find /UF or /F (filename) near this object
                    std::string fname = decode_pdf_filename(dict);
                    if (fname.empty()) {
                        std::string ext = is_dct ? ".jpg" : ".bin";
                        std::string det = utils::detect_format("", payload);
                        if (det == "zip") ext = ".zip";
                        else if (det == "pdf") ext = ".pdf";
                        else if (det == "png") ext = ".png";
                        else if (det == "ole2") ext = ".doc";
                        else if (det.find("opc") != std::string::npos) ext = ".docx";
                        fname = "pdf_object_" + std::to_string(stream_idx) + ext;
                    }
                    fname = utils::sanitize_relpath(fname);
                    if (!utils::should_extract_item(fname, config)) {
                        pos = end_pos + 9;
                        continue;
                    }
                    std::string out_path = utils::join_path(output_dir, fname);
                    if (utils::write_file(out_path, payload.data(), payload.size())) {
                        ExtractedItem item;
                        item.name = fname;
                        item.saved_path = out_path;
                        item.offset = data_start;
                        item.size = payload.size();
                        item.extractor_name = "PdfExtractor(native)";
                        out_items.push_back(item);
                        stream_idx++;
                    }
                }
            }
            pos = end_pos + 9;
        }

        return !out_items.empty();
    }
};

} // namespace

std::unique_ptr<IExtractor> create_pdf_extractor() {
    return std::unique_ptr<IExtractor>(new PdfExtractor());
}

} // namespace unnest
