#ifndef FILEUNNEST_UTILS_H
#define FILEUNNEST_UTILS_H

#include "fileunnest/types.h"
#include "ftype/ftype.hpp"
#include <cstdint>
#include <string>
#include <vector>

namespace unnest {
namespace utils {

bool read_file_header(const std::string& path, std::vector<uint8_t>& out, size_t max_bytes = 4096);
bool read_entire_file(const std::string& path, std::vector<uint8_t>& out, uint64_t max_size = 512ULL * 1024 * 1024);
bool write_file(const std::string& path, const uint8_t* data, size_t size);
uint64_t file_size(const std::string& path);
bool file_exists(const std::string& path);
bool is_directory(const std::string& path);
bool make_dirs(const std::string& path);
std::string sanitize_relpath(const std::string& raw_path);
std::string base_name(const std::string& path);
std::string to_lower(const std::string& s);
std::string get_extension(const std::string& path);
std::string join_path(const std::string& a, const std::string& b);

std::string sha256_file(const std::string& path);
std::string sha256_bytes(const uint8_t* data, size_t len);
std::vector<uint8_t> base64_decode(const std::string& input);

bool is_valid_utf8(const std::string& s);
std::string ensure_utf8(const std::string& raw);
std::string utf16le_to_utf8(const uint8_t* data, size_t byte_len);
std::string utf16be_to_utf8(const uint8_t* data, size_t byte_len);

std::string detect_format(const std::string& path, const std::vector<uint8_t>& header);
ftype::FileType detect_file_type(const std::string& path, const std::vector<uint8_t>& header = {});
std::string to_json(const ExtractedItem& root, int indent = 0);

bool is_office_extension(const std::string& ext);
bool is_image_extension(const std::string& ext);
bool is_text_extension(const std::string& ext);
bool is_pdf_extension(const std::string& ext);
bool is_container_extension(const std::string& ext);
bool should_extract_item(const std::string& path_or_name, const UnnestConfig& config, const std::string& fmt = "");

std::vector<std::string> list_files_recursive(const std::string& root_dir);
bool run_external_cmd(const std::vector<std::string>& args);

} // namespace utils
} // namespace unnest

#endif // FILEUNNEST_UTILS_H
