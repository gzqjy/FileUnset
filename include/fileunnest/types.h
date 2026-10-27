#ifndef FILEUNNEST_TYPES_H
#define FILEUNNEST_TYPES_H

#include <cstdint>
#include <string>
#include <vector>

namespace unnest {

struct UnnestConfig {
    int max_depth = 8;
    uint64_t max_file_size = 512ULL * 1024 * 1024;   // 512 MB single file cap
    uint64_t max_total_size = 2048ULL * 1024 * 1024; // 2 GB total extraction cap
    bool enable_carving = true;                      // Polyglot / self-extracting shell carving
    bool extract_opc_raw = false;                    // If false, only extract media/embeddings from docx/xlsx/pptx unless all requested

    // In-Process VFS Filtering:
    // Default: extract Office documents, Images, Text files, and PDFs (skipping irrelevant binaries like .so, .dll, .pak)
    bool extract_all = false;                        // When true, extract all files unconditionally
    bool filter_office = true;                       // Extract office docs (.docx, .doc, .xlsx, .xls, .pptx, .ppt, .rtf, .one, etc.)
    bool filter_image = true;                        // Extract image files (.png, .jpg, .svg, .bmp, .gif, .webp, .psd, etc.)
    bool filter_text = true;                         // Extract text files (.txt, .md, .json, .xml, .html, .csv, code, etc.)
    bool filter_pdf = true;                          // Extract PDF files (.pdf)

    bool is_filter_active() const { return !extract_all; }
};

struct ExtractedItem {
    std::string name;           // Logical name or relative path inside container
    std::string saved_path;     // Actual path on disk
    std::string format;         // Detected format / container type
    std::string real_ext;       // True file extension identified by ftype
    std::string mime_type;      // MIME type identified by ftype
    std::string extractor_name; // Extractor that produced this item
    uint64_t offset = 0;        // Byte offset in parent file (if applicable)
    uint64_t size = 0;          // Extracted byte size
    std::string sha256;         // SHA-256 hex digest
    int depth = 0;              // Nesting depth
    std::string associated_icon_path; // Associated presentation icon path if embedded as icon
    std::vector<ExtractedItem> children;
};

} // namespace unnest

#endif // FILEUNNEST_TYPES_H
