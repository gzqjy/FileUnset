#include "fileunnest/engine.h"
#include "fileunnest/utils.h"
#include <clocale>

namespace unnest {

UnnestEngine::UnnestEngine(const UnnestConfig& config) : config_(config) {
    std::setlocale(LC_ALL, "");
    register_extractor(create_archive_extractor());
    register_extractor(create_ole2_extractor());
    register_extractor(create_rtf_extractor());
    register_extractor(create_onenote_extractor());
    register_extractor(create_pdf_extractor());
    register_extractor(create_asar_extractor());
    register_extractor(create_svg_extractor());
    register_extractor(create_psd_extractor());
    register_extractor(create_indd_extractor());
    register_extractor(create_pyinstaller_extractor());
    register_extractor(create_disk_extractor());
    carve_extractor_ = create_carve_extractor();
}

void UnnestEngine::register_extractor(std::unique_ptr<IExtractor> extractor) {
    if (extractor) {
        extractors_.push_back(std::move(extractor));
    }
}

ExtractedItem UnnestEngine::process(const std::string& input_file, const std::string& output_dir) {
    ExtractedItem root;
    root.name = utils::base_name(input_file);
    root.saved_path = input_file;
    root.size = utils::file_size(input_file);
    root.sha256 = utils::sha256_file(input_file);
    root.depth = 0;

    std::vector<uint8_t> hdr;
    utils::read_file_header(input_file, hdr, 36864);
    ftype::FileType ft_root = utils::detect_file_type(input_file, hdr);
    root.real_ext = ft_root.ext ? ft_root.ext : "";
    root.mime_type = ft_root.mime ? ft_root.mime : "";
    root.format = utils::detect_format(input_file, hdr);
    root.extractor_name = "root";

    utils::make_dirs(output_dir);
    uint64_t total_bytes = 0;
    process_recursive(root, output_dir, total_bytes);
    return root;
}

void UnnestEngine::process_recursive(ExtractedItem& item, const std::string& base_out_dir, uint64_t& total_extracted_bytes) {
    if (item.depth >= config_.max_depth) return;
    if (total_extracted_bytes >= config_.max_total_size) return;

    std::vector<uint8_t> hdr;
    if (!utils::read_file_header(item.saved_path, hdr, 36864) || hdr.empty()) return;
    if (item.format.empty()) {
        item.format = utils::detect_format(item.saved_path, hdr);
    }

    std::string sub_out_dir = (item.depth == 0)
                                  ? utils::join_path(base_out_dir, item.name + ".unnested")
                                  : (item.saved_path + ".unnested");

    std::vector<ExtractedItem> children;
    bool handled = false;

    for (const auto& ext : extractors_) {
        if (ext->can_handle(item.saved_path, item.format, hdr)) {
            if (ext->extract(item.saved_path, sub_out_dir, config_, children) && !children.empty()) {
                handled = true;
                break;
            }
        }
    }

    if (!handled && config_.enable_carving && carve_extractor_ &&
        carve_extractor_->can_handle(item.saved_path, item.format, hdr)) {
        carve_extractor_->extract(item.saved_path, sub_out_dir, config_, children);
    }

    for (auto& child : children) {
        child.depth = item.depth + 1;
        if (child.size == 0) child.size = utils::file_size(child.saved_path);
        total_extracted_bytes += child.size;
        child.sha256 = utils::sha256_file(child.saved_path);
        std::vector<uint8_t> ch_hdr;
        utils::read_file_header(child.saved_path, ch_hdr, 36864);
        ftype::FileType ft_ch = utils::detect_file_type(child.saved_path, ch_hdr);
        child.real_ext = ft_ch.ext ? ft_ch.ext : "";
        child.mime_type = ft_ch.mime ? ft_ch.mime : "";
        child.format = utils::detect_format(child.saved_path, ch_hdr);

        // Avoid infinite self-carving loop if child has identical hash to parent
        if (!child.sha256.empty() && child.sha256 == item.sha256) {
            continue;
        }
        process_recursive(child, sub_out_dir, total_extracted_bytes);
        item.children.push_back(std::move(child));
    }
}

} // namespace unnest
