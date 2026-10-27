#ifndef FTYPE_HPP
#define FTYPE_HPP

#include <cstddef>
#include <cstdint>
#include <string>

namespace ftype {

struct FileType {
    const char* ext;
    const char* mime;
};

// 从内存字节流判定文件格式（建议至少传入前 4096 字节）
FileType detect_bytes(const uint8_t* buf, size_t len);

// 从文件路径判定真实格式（自动处理 >4KB 的 ZIP 尾部中央目录跳读）
FileType detect_file(const std::string& path);

} // namespace ftype

#endif // FTYPE_HPP
