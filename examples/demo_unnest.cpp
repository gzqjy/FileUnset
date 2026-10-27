#include "fileunnest/engine.h"
#include "fileunnest/utils.h"
#include "../tests/test_fixtures.h"
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

using namespace unnest;

namespace {

void print_tree(const ExtractedItem& item, const std::string& prefix = "", bool is_last = true) {
    if (item.depth == 0) {
        std::cout << "  [ROOT] " << item.name << " (" << item.format << ", " << item.size
                  << " B, sha256=" << item.sha256.substr(0, 12) << "...)\n";
    } else {
        std::cout << "  " << prefix << (is_last ? "└── " : "├── ")
                  << item.name << " [" << item.format << " | " << item.size << " B | offset=" << item.offset
                  << " | " << item.extractor_name << "]";
        if (!item.associated_icon_path.empty()) {
            std::cout << " (icon: " << utils::base_name(item.associated_icon_path) << ")";
        }
        std::cout << "\n";
    }
    std::string next_prefix = (item.depth == 0) ? "" : (prefix + (is_last ? "    " : "│   "));
    for (size_t i = 0; i < item.children.size(); ++i) {
        print_tree(item.children[i], next_prefix, i + 1 == item.children.size());
    }
}

size_t count_extracted_nodes(const ExtractedItem& item) {
    size_t n = item.children.size();
    for (const auto& c : item.children) n += count_extracted_nodes(c);
    return n;
}

} // namespace

int main(int argc, char* argv[]) {
    std::string samples_dir = (argc > 1) ? argv[1] : "/home/zkjs-test/develop/FileUnnest/test_samples";
    std::string demo_out_dir = (argc > 2) ? argv[2] : "/home/zkjs-test/develop/FileUnnest/demo_output";

    std::cout << "====================================================================\n";
    std::cout << "  FileUnnest Demo: Generating Test Samples & Running Full Showcase  \n";
    std::cout << "====================================================================\n";

    test_fixtures::generate_all_samples(samples_dir);
    std::cout << "[1/2] Generated 10 test sample files in: " << samples_dir << "\n\n";

    struct CaseInfo {
        std::string filename;
        std::string category_desc;
    };

    std::vector<CaseInfo> cases = {
        {"01_pdf_with_attachment.pdf", "1. PDF Document with FlateDecode Compressed Embedded ZIP"},
        {"02_office_opc.docx",         "1. MS Office Word (.docx) with Embedded OLE2 + Media"},
        {"03_legacy_ole2.doc",         "1. Legacy OLE2 Compound Document (.doc) with Ole10Native ZIP"},
        {"04_nested_archive.7z",       "2. Multi-Layer Archive (7z -> tar.gz -> zip -> txt)"},
        {"05_photoshop_smartobj.psd",  "3. Photoshop (.psd) with Embedded Smart Object Layer"},
        {"06_vector_base64.svg",       "3. SVG Vector Graphic with Base64 Embedded Image"},
        {"07_electron_bundle.asar",    "4. Electron Runtime Bundle (.asar) with Nested SVG/PNG"},
        {"08_polyglot_image.jpg",      "5. Polyglot Image ('TuZhong' JPEG + Appended ZIP)"},
        {"09_self_extracting.run",     "6. Linux Self-Extracting Shell Script (.run + tar.gz)"},
        {"10_rtf_embedded.rtf",        "7. RTF Rich Text (.rtf) with Hex Pict + OLE1.0 Package"},
        {"11_onenote_section.one",     "8. OneNote (.one) MS-ONESTORE FileDataStoreObject Attachments"},
        {"12_multi_carve_bundle.bin",  "9. Size-Aware Multi-Payload Carving (Shell + 7z + PNG + ZIP)"},
        {"13_pyinstaller_bundle.elf",  "10. PyInstaller Executable (.elf) with CArchive TOC Decompression"},
        {"14_indesign_document.indd",  "11. Adobe InDesign (.indd) with XMP Preview + Embedded PNG/ZIP"},
        {"15_photoshop_large.psb",     "12. Photoshop Large Document (.psb v2, 64-bit) Smart Object"},
        {"16_docker_oci_image.tar",    "13. Docker / OCI Container Image (.tar + blobs/sha256/* layers)"},
        {"17_linux_rootfs.squashfs",   "14. Linux SquashFS Filesystem Image (.squashfs)"},
        {"18_optical_disc.iso",        "15. ISO 9660 Optical Disc Image (.iso)"},
        {"19_master_showcase.7z",      "ALL-IN-ONE: Master 7z Archive Containing All 18 Samples Above"}
    };

    UnnestConfig cfg;
    cfg.max_depth = 10;
    UnnestEngine engine(cfg);

    std::cout << "[2/2] Executing UnnestEngine across all 10 sample cases:\n";
    std::cout << "--------------------------------------------------------------------\n";

    for (const auto& c : cases) {
        std::string in_path = utils::join_path(samples_dir, c.filename);
        std::string out_path = utils::join_path(demo_out_dir, c.filename + "_out");
        ExtractedItem root = engine.process(in_path, out_path);

        std::string manifest_file = utils::join_path(out_path, "manifest.json");
        std::string json = utils::to_json(root);
        utils::write_file(manifest_file, reinterpret_cast<const uint8_t*>(json.data()), json.size());

        std::cout << "\n>>> Case: " << c.category_desc << "\n";
        std::cout << "    Input : " << in_path << "\n";
        std::cout << "    Output: " << out_path << " (extracted " << count_extracted_nodes(root) << " items)\n";
        print_tree(root);
    }

    std::cout << "\n====================================================================\n";
    std::cout << "  Demo complete! All manifests saved under: " << demo_out_dir << "\n";
    std::cout << "====================================================================\n";
    return 0;
}
