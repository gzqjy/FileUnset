#ifndef FILEUNNEST_ENGINE_H
#define FILEUNNEST_ENGINE_H

#include "fileunnest/extractor.h"
#include "fileunnest/types.h"
#include <memory>
#include <string>
#include <vector>

namespace unnest {

class UnnestEngine {
public:
    explicit UnnestEngine(const UnnestConfig& config = UnnestConfig());
    ~UnnestEngine() {}

    void register_extractor(std::unique_ptr<IExtractor> extractor);
    ExtractedItem process(const std::string& input_file, const std::string& output_dir);

private:
    void process_recursive(ExtractedItem& item, const std::string& base_out_dir, uint64_t& total_extracted_bytes);

    UnnestConfig config_;
    std::vector<std::unique_ptr<IExtractor>> extractors_;
    std::unique_ptr<IExtractor> carve_extractor_;
};

} // namespace unnest

#endif // FILEUNNEST_ENGINE_H
