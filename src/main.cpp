#include "fileunnest/engine.h"
#include "fileunnest/utils.h"
#include <clocale>
#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

namespace {

void print_usage(const char* prog) {
    std::cout << "Usage: " << prog << " <input_file> <output_dir> [options]\n"
              << "Default: Extracts Office docs, Images, Text files, and PDFs (skips irrelevant binaries like .so, .dll, .pak)\n\n"
              << "Options:\n"
              << "  --all, --extract-all Extract all files unconditionally (disables default filtering)\n"
              << "  --filter <types>     Filter by types: 'office', 'image', 'text', 'pdf', 'all'\n"
              << "  --images-only        Only extract images (and parent containers)\n"
              << "  --text-only          Only extract text files (and parent containers)\n"
              << "  --office-only        Only extract office docs (and parent containers)\n"
              << "  --pdf-only           Only extract PDF files (and parent containers)\n"
              << "  --max-depth <N>      Maximum recursion depth (default: 8)\n"
              << "  --max-size <MB>      Max single file size in MB (default: 512)\n"
              << "  --no-carve           Disable polyglot / self-extracting carving\n"
              << "  --opc-all            Extract all XML/rels inside DOCX/XLSX/PPTX\n"
              << "  --manifest <path>    Custom path for JSON manifest (default: <output_dir>/manifest.json)\n";
}

void print_tree(const unnest::ExtractedItem& item, const std::string& prefix = "", bool is_last = true) {
    if (item.depth == 0) {
        std::cout << "[ROOT] " << item.name << " (" << item.format;
        if (!item.mime_type.empty()) std::cout << " | " << item.mime_type;
        std::cout << ", " << item.size << " bytes)\n";
    } else {
        std::cout << prefix << (is_last ? "└── " : "├── ")
                  << item.name << " [" << item.format;
        if (!item.mime_type.empty()) std::cout << " | " << item.mime_type;
        std::cout << " | " << item.size << " B | via " << item.extractor_name << "]";
        if (!item.associated_icon_path.empty()) {
            std::cout << " (icon: " << unnest::utils::base_name(item.associated_icon_path) << ")";
        }
        std::cout << "\n";
    }
    std::string next_prefix = (item.depth == 0) ? "" : (prefix + (is_last ? "    " : "│   "));
    for (size_t i = 0; i < item.children.size(); ++i) {
        print_tree(item.children[i], next_prefix, i + 1 == item.children.size());
    }
}

} // namespace

int main(int argc, char* argv[]) {
    std::vector<std::string> positional;
    std::string manifest_path;
    unnest::UnnestConfig cfg;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-h" || arg == "--help") {
            print_usage(argv[0]);
            return 0;
        }

        if (arg.size() > 0 && arg[0] == '-') {
            std::string key = arg;
            std::string val;
            size_t eq_pos = arg.find('=');
            if (eq_pos != std::string::npos) {
                key = arg.substr(0, eq_pos);
                val = arg.substr(eq_pos + 1);
            }

            if (key == "--max-depth") {
                if (eq_pos == std::string::npos && i + 1 < argc) val = argv[++i];
                if (!val.empty()) cfg.max_depth = std::atoi(val.c_str());
            } else if (key == "--max-size") {
                if (eq_pos == std::string::npos && i + 1 < argc) val = argv[++i];
                if (!val.empty()) cfg.max_file_size = static_cast<uint64_t>(std::atoll(val.c_str())) * 1024ULL * 1024ULL;
            } else if (key == "--no-carve") {
                cfg.enable_carving = false;
            } else if (key == "--opc-all") {
                cfg.extract_opc_raw = true;
            } else if (key == "--manifest") {
                if (eq_pos == std::string::npos && i + 1 < argc) val = argv[++i];
                manifest_path = val;
            } else if (key == "--all" || key == "--extract-all") {
                cfg.extract_all = true;
            } else if (key == "--filter") {
                if (eq_pos == std::string::npos && i + 1 < argc) val = argv[++i];
                std::string lval = unnest::utils::to_lower(val);
                if (lval.find("all") != std::string::npos) {
                    cfg.extract_all = true;
                } else {
                    cfg.extract_all = false;
                    cfg.filter_office = (lval.find("office") != std::string::npos);
                    cfg.filter_image = (lval.find("image") != std::string::npos || lval.find("img") != std::string::npos || lval.find("pic") != std::string::npos);
                    cfg.filter_text = (lval.find("text") != std::string::npos || lval.find("txt") != std::string::npos);
                    cfg.filter_pdf = (lval.find("pdf") != std::string::npos);
                }
            } else if (key == "--images-only" || key == "--image-only") {
                cfg.extract_all = false;
                cfg.filter_office = false;
                cfg.filter_text = false;
                cfg.filter_pdf = false;
                cfg.filter_image = true;
            } else if (key == "--text-only") {
                cfg.extract_all = false;
                cfg.filter_office = false;
                cfg.filter_image = false;
                cfg.filter_pdf = false;
                cfg.filter_text = true;
            } else if (key == "--office-only") {
                cfg.extract_all = false;
                cfg.filter_image = false;
                cfg.filter_text = false;
                cfg.filter_pdf = false;
                cfg.filter_office = true;
            } else if (key == "--pdf-only") {
                cfg.extract_all = false;
                cfg.filter_office = false;
                cfg.filter_image = false;
                cfg.filter_text = false;
                cfg.filter_pdf = true;
            } else {
                std::cerr << "Unknown option: " << arg << "\n";
            }
        } else {
            positional.push_back(arg);
        }
    }

    if (positional.size() < 2) {
        print_usage(argv[0]);
        return 1;
    }

    std::string input_file = positional[0];
    std::string output_dir = positional[1];

    if (!unnest::utils::file_exists(input_file)) {
        std::cerr << "Error: input file not found: " << input_file << "\n";
        return 1;
    }

    if (manifest_path.empty()) {
        manifest_path = unnest::utils::join_path(output_dir, "manifest.json");
    }

    unnest::UnnestEngine engine(cfg);
    unnest::ExtractedItem result = engine.process(input_file, output_dir);

    std::string json = unnest::utils::to_json(result);
    unnest::utils::write_file(manifest_path, reinterpret_cast<const uint8_t*>(json.data()), json.size());

    print_tree(result);
    std::cout << "\nManifest written to: " << manifest_path << "\n";
    return 0;
}
