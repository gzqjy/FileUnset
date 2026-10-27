#ifndef FILEUNNEST_EXTRACTOR_H
#define FILEUNNEST_EXTRACTOR_H

#include "fileunnest/types.h"
#include <memory>
#include <string>
#include <vector>

namespace unnest {

class IExtractor {
public:
    virtual ~IExtractor() {}
    virtual std::string name() const = 0;
    virtual bool can_handle(const std::string& file_path,
                            const std::string& detected_format,
                            const std::vector<uint8_t>& header) const = 0;
    virtual bool extract(const std::string& file_path,
                         const std::string& output_dir,
                         const UnnestConfig& config,
                         std::vector<ExtractedItem>& out_items) = 0;
};

// Factory functions for built-in extractors
std::unique_ptr<IExtractor> create_archive_extractor();
std::unique_ptr<IExtractor> create_ole2_extractor();
std::unique_ptr<IExtractor> create_rtf_extractor();
std::unique_ptr<IExtractor> create_onenote_extractor();
std::unique_ptr<IExtractor> create_pdf_extractor();
std::unique_ptr<IExtractor> create_asar_extractor();
std::unique_ptr<IExtractor> create_svg_extractor();
std::unique_ptr<IExtractor> create_psd_extractor();
std::unique_ptr<IExtractor> create_indd_extractor();
std::unique_ptr<IExtractor> create_pyinstaller_extractor();
std::unique_ptr<IExtractor> create_disk_extractor();
std::unique_ptr<IExtractor> create_carve_extractor();

} // namespace unnest

#endif // FILEUNNEST_EXTRACTOR_H
