#include "fileunnest/extractor.h"
#include "fileunnest/utils.h"
#include <string>
#include <vector>

namespace unnest {

namespace {

std::string mime_to_ext(const std::string& mime) {
    if (mime.find("png") != std::string::npos) return ".png";
    if (mime.find("jpeg") != std::string::npos || mime.find("jpg") != std::string::npos) return ".jpg";
    if (mime.find("gif") != std::string::npos) return ".gif";
    if (mime.find("webp") != std::string::npos) return ".webp";
    if (mime.find("svg") != std::string::npos) return ".svg";
    if (mime.find("mp3") != std::string::npos || mime.find("mpeg") != std::string::npos) return ".mp3";
    if (mime.find("wav") != std::string::npos) return ".wav";
    if (mime.find("ogg") != std::string::npos) return ".ogg";
    if (mime.find("zip") != std::string::npos) return ".zip";
    if (mime.find("pdf") != std::string::npos) return ".pdf";
    return ".bin";
}

class SvgExtractor : public IExtractor {
public:
    std::string name() const override { return "SvgExtractor(DataURI/Base64)"; }

    bool can_handle(const std::string& file_path,
                    const std::string& fmt,
                    const std::vector<uint8_t>&) const override {
        return fmt == "svg" || utils::get_extension(file_path) == ".svg";
    }

    bool extract(const std::string& file_path,
                 const std::string& output_dir,
                 const UnnestConfig& config,
                 std::vector<ExtractedItem>& out_items) override {
        std::vector<uint8_t> raw_bytes;
        if (!utils::read_entire_file(file_path, raw_bytes, config.max_file_size)) return false;
        std::string content(reinterpret_cast<const char*>(raw_bytes.data()), raw_bytes.size());

        size_t pos = 0;
        int idx = 0;
        while ((pos = content.find("data:", pos)) != std::string::npos) {
            // Ensure preceded by quote or '('
            if (pos > 0 && content[pos - 1] != '"' && content[pos - 1] != '\'' && content[pos - 1] != '(') {
                pos += 5;
                continue;
            }
            char delim = (pos > 0) ? content[pos - 1] : '"';
            char end_delim = (delim == '(') ? ')' : delim;

            size_t b64_marker = content.find(";base64,", pos);
            size_t end_pos = content.find(end_delim, pos);
            if (b64_marker == std::string::npos || end_pos == std::string::npos || b64_marker >= end_pos) {
                pos += 5;
                continue;
            }

            std::string mime = content.substr(pos + 5, b64_marker - (pos + 5));
            std::string b64_payload = content.substr(b64_marker + 8, end_pos - (b64_marker + 8));
            std::vector<uint8_t> decoded = utils::base64_decode(b64_payload);

            if (!decoded.empty() && decoded.size() <= config.max_file_size) {
                std::string ext = mime_to_ext(mime);
                std::string fname = "embedded_" + std::to_string(idx) + ext;
                std::string out_path = utils::join_path(output_dir, fname);
                if (utils::write_file(out_path, decoded.data(), decoded.size())) {
                    ExtractedItem item;
                    item.name = fname;
                    item.saved_path = out_path;
                    item.offset = pos;
                    item.size = decoded.size();
                    item.extractor_name = name();
                    out_items.push_back(item);
                    idx++;
                }
            }
            pos = end_pos + 1;
        }
        return !out_items.empty();
    }
};

} // namespace

std::unique_ptr<IExtractor> create_svg_extractor() {
    return std::unique_ptr<IExtractor>(new SvgExtractor());
}

} // namespace unnest
