#include "fileunnest/utils.h"
#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <dirent.h>
#include <fstream>
#include <iconv.h>
#include <iomanip>
#include <sstream>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

namespace unnest {
namespace utils {

bool read_file_header(const std::string& path, std::vector<uint8_t>& out, size_t max_bytes) {
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs) return false;
    out.resize(max_bytes);
    ifs.read(reinterpret_cast<char*>(out.data()), static_cast<std::streamsize>(max_bytes));
    out.resize(static_cast<size_t>(ifs.gcount()));
    return true;
}

bool read_entire_file(const std::string& path, std::vector<uint8_t>& out, uint64_t max_size) {
    uint64_t sz = file_size(path);
    if (sz > max_size) return false;
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs) return false;
    out.resize(static_cast<size_t>(sz));
    if (sz > 0) {
        ifs.read(reinterpret_cast<char*>(out.data()), static_cast<std::streamsize>(sz));
    }
    return ifs.good() || ifs.eof();
}

bool write_file(const std::string& path, const uint8_t* data, size_t size) {
    size_t pos = path.find_last_of('/');
    if (pos != std::string::npos) {
        make_dirs(path.substr(0, pos));
    }
    std::ofstream ofs(path, std::ios::binary | std::ios::trunc);
    if (!ofs) return false;
    if (size > 0 && data != nullptr) {
        ofs.write(reinterpret_cast<const char*>(data), static_cast<std::streamsize>(size));
    }
    return ofs.good();
}

uint64_t file_size(const std::string& path) {
    struct stat st;
    if (stat(path.c_str(), &st) != 0) return 0;
    return static_cast<uint64_t>(st.st_size);
}

bool file_exists(const std::string& path) {
    struct stat st;
    return stat(path.c_str(), &st) == 0;
}

bool is_directory(const std::string& path) {
    struct stat st;
    if (stat(path.c_str(), &st) != 0) return false;
    return S_ISDIR(st.st_mode);
}

bool make_dirs(const std::string& path) {
    if (path.empty()) return true;
    if (is_directory(path)) return true;
    std::string cur;
    for (size_t i = 0; i < path.size(); ++i) {
        cur.push_back(path[i]);
        if (path[i] == '/' || i + 1 == path.size()) {
            if (!cur.empty() && cur != "/" && !is_directory(cur)) {
                mkdir(cur.c_str(), 0755);
            }
        }
    }
    return is_directory(path);
}

std::string sanitize_relpath(const std::string& raw_path) {
    std::string p = ensure_utf8(raw_path);
    for (char& c : p) {
        if (c == '\\' || c == '\0') c = '/';
    }
    std::vector<std::string> parts;
    std::stringstream ss(p);
    std::string item;
    while (std::getline(ss, item, '/')) {
        if (item.empty() || item == "." || item == "..") continue;
        for (char& c : item) {
            if (static_cast<unsigned char>(c) < 32 || c == ':' || c == '*' || c == '?' || c == '"' || c == '<' || c == '>' || c == '|') {
                c = '_';
            }
        }
        parts.push_back(item);
    }
    if (parts.empty()) return "unnamed_entry";
    std::string res;
    for (size_t i = 0; i < parts.size(); ++i) {
        if (i > 0) res += "/";
        res += parts[i];
    }
    return res;
}

std::string base_name(const std::string& path) {
    size_t pos = path.find_last_of("/\\");
    if (pos == std::string::npos) return path;
    return path.substr(pos + 1);
}

std::string to_lower(const std::string& s) {
    std::string r = s;
    for (char& c : r) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return r;
}

std::string get_extension(const std::string& path) {
    std::string b = to_lower(base_name(path));
    if (b.size() > 7 && b.substr(b.size() - 7) == ".tar.gz") return ".tar.gz";
    if (b.size() > 7 && b.substr(b.size() - 7) == ".tar.xz") return ".tar.xz";
    if (b.size() > 8 && b.substr(b.size() - 8) == ".tar.bz2") return ".tar.bz2";
    if (b.size() > 8 && b.substr(b.size() - 8) == ".tar.zst") return ".tar.zst";
    size_t pos = b.find_last_of('.');
    if (pos == std::string::npos || pos == 0) return "";
    return b.substr(pos);
}

std::string join_path(const std::string& a, const std::string& b) {
    if (a.empty()) return b;
    if (b.empty()) return a;
    if (a.back() == '/') return a + (b.front() == '/' ? b.substr(1) : b);
    return a + "/" + (b.front() == '/' ? b.substr(1) : b);
}

namespace {
struct Sha256Ctx {
    uint32_t state[8];
    uint64_t bitlen;
    uint8_t data[64];
    uint32_t datalen;
};

static const uint32_t kSha256K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

inline uint32_t rotr(uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); }

void sha256_transform(Sha256Ctx& ctx, const uint8_t data[64]) {
    uint32_t m[64];
    for (int i = 0, j = 0; i < 16; ++i, j += 4) {
        m[i] = (static_cast<uint32_t>(data[j]) << 24) |
               (static_cast<uint32_t>(data[j + 1]) << 16) |
               (static_cast<uint32_t>(data[j + 2]) << 8) |
               (static_cast<uint32_t>(data[j + 3]));
    }
    for (int i = 16; i < 64; ++i) {
        uint32_t s0 = rotr(m[i - 15], 7) ^ rotr(m[i - 15], 18) ^ (m[i - 15] >> 3);
        uint32_t s1 = rotr(m[i - 2], 17) ^ rotr(m[i - 2], 19) ^ (m[i - 2] >> 10);
        m[i] = m[i - 16] + s0 + m[i - 7] + s1;
    }
    uint32_t a = ctx.state[0], b = ctx.state[1], c = ctx.state[2], d = ctx.state[3];
    uint32_t e = ctx.state[4], f = ctx.state[5], g = ctx.state[6], h = ctx.state[7];
    for (int i = 0; i < 64; ++i) {
        uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t temp1 = h + S1 + ch + kSha256K[i] + m[i];
        uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = S0 + maj;
        h = g; g = f; f = e; e = d + temp1;
        d = c; c = b; b = a; a = temp1 + temp2;
    }
    ctx.state[0] += a; ctx.state[1] += b; ctx.state[2] += c; ctx.state[3] += d;
    ctx.state[4] += e; ctx.state[5] += f; ctx.state[6] += g; ctx.state[7] += h;
}

void sha256_init(Sha256Ctx& ctx) {
    ctx.datalen = 0;
    ctx.bitlen = 0;
    ctx.state[0] = 0x6a09e667; ctx.state[1] = 0xbb67ae85;
    ctx.state[2] = 0x3c6ef372; ctx.state[3] = 0xa54ff53a;
    ctx.state[4] = 0x510e527f; ctx.state[5] = 0x9b05688c;
    ctx.state[6] = 0x1f83d9ab; ctx.state[7] = 0x5be0cd19;
}

void sha256_update(Sha256Ctx& ctx, const uint8_t* data, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        ctx.data[ctx.datalen] = data[i];
        ctx.datalen++;
        if (ctx.datalen == 64) {
            sha256_transform(ctx, ctx.data);
            ctx.bitlen += 512;
            ctx.datalen = 0;
        }
    }
}

std::string sha256_final(Sha256Ctx& ctx) {
    uint32_t i = ctx.datalen;
    if (ctx.datalen < 56) {
        ctx.data[i++] = 0x80;
        while (i < 56) ctx.data[i++] = 0x00;
    } else {
        ctx.data[i++] = 0x80;
        while (i < 64) ctx.data[i++] = 0x00;
        sha256_transform(ctx, ctx.data);
        std::memset(ctx.data, 0, 56);
    }
    ctx.bitlen += ctx.datalen * 8ULL;
    ctx.data[63] = static_cast<uint8_t>(ctx.bitlen);
    ctx.data[62] = static_cast<uint8_t>(ctx.bitlen >> 8);
    ctx.data[61] = static_cast<uint8_t>(ctx.bitlen >> 16);
    ctx.data[60] = static_cast<uint8_t>(ctx.bitlen >> 24);
    ctx.data[59] = static_cast<uint8_t>(ctx.bitlen >> 32);
    ctx.data[58] = static_cast<uint8_t>(ctx.bitlen >> 40);
    ctx.data[57] = static_cast<uint8_t>(ctx.bitlen >> 48);
    ctx.data[56] = static_cast<uint8_t>(ctx.bitlen >> 56);
    sha256_transform(ctx, ctx.data);

    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (int j = 0; j < 8; ++j) {
        oss << std::setw(8) << ctx.state[j];
    }
    return oss.str();
}
} // namespace

std::string sha256_bytes(const uint8_t* data, size_t len) {
    Sha256Ctx ctx;
    sha256_init(ctx);
    sha256_update(ctx, data, len);
    return sha256_final(ctx);
}

std::string sha256_file(const std::string& path) {
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs) return "";
    Sha256Ctx ctx;
    sha256_init(ctx);
    char buf[16384];
    while (ifs.read(buf, sizeof(buf)) || ifs.gcount() > 0) {
        sha256_update(ctx, reinterpret_cast<const uint8_t*>(buf), static_cast<size_t>(ifs.gcount()));
    }
    return sha256_final(ctx);
}

std::vector<uint8_t> base64_decode(const std::string& input) {
    static const int T[256] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
        52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
        15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
        -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
        41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
    };
    std::vector<uint8_t> out;
    out.reserve(input.size() * 3 / 4);
    int val = 0, valb = -8;
    for (unsigned char c : input) {
        if (c == '=') break;
        int d = T[c];
        if (d == -1) continue;
        val = (val << 6) + d;
        valb += 6;
        if (valb >= 0) {
            out.push_back(static_cast<uint8_t>((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return out;
}

bool is_valid_utf8(const std::string& s) {
    size_t i = 0;
    while (i < s.size()) {
        unsigned char c = static_cast<unsigned char>(s[i]);
        if (c < 0x80) {
            i++;
        } else if ((c & 0xE0) == 0xC0) {
            if (i + 1 >= s.size()) return false;
            unsigned char c1 = static_cast<unsigned char>(s[i + 1]);
            if ((c1 & 0xC0) != 0x80 || c < 0xC2) return false;
            i += 2;
        } else if ((c & 0xF0) == 0xE0) {
            if (i + 2 >= s.size()) return false;
            unsigned char c1 = static_cast<unsigned char>(s[i + 1]);
            unsigned char c2 = static_cast<unsigned char>(s[i + 2]);
            if ((c1 & 0xC0) != 0x80 || (c2 & 0xC0) != 0x80) return false;
            if (c == 0xE0 && c1 < 0xA0) return false;
            if (c == 0xED && c1 >= 0xA0) return false;
            i += 3;
        } else if ((c & 0xF8) == 0xF0) {
            if (i + 3 >= s.size()) return false;
            unsigned char c1 = static_cast<unsigned char>(s[i + 1]);
            unsigned char c2 = static_cast<unsigned char>(s[i + 2]);
            unsigned char c3 = static_cast<unsigned char>(s[i + 3]);
            if ((c1 & 0xC0) != 0x80 || (c2 & 0xC0) != 0x80 || (c3 & 0xC0) != 0x80) return false;
            if (c == 0xF0 && c1 < 0x90) return false;
            if (c > 0xF4 || (c == 0xF4 && c1 >= 0x90)) return false;
            i += 4;
        } else {
            return false;
        }
    }
    return true;
}

namespace {
std::string iconv_convert(const char* from_enc, const char* to_enc, const char* src, size_t src_len) {
    if (src_len == 0) return "";
    iconv_t cd = iconv_open(to_enc, from_enc);
    if (cd == reinterpret_cast<iconv_t>(-1)) return "";
    std::string out(src_len * 4 + 4, '\0');
    char* inbuf = const_cast<char*>(src);
    size_t inbytes = src_len;
    char* outbuf = &out[0];
    size_t outbytes = out.size();
    size_t res = iconv(cd, &inbuf, &inbytes, &outbuf, &outbytes);
    iconv_close(cd);
    if (res == static_cast<size_t>(-1)) return "";
    out.resize(out.size() - outbytes);
    while (!out.empty() && out.back() == '\0') out.pop_back();
    return out;
}

void append_codepoint_utf8(std::string& out, uint32_t cp) {
    if (cp == 0) return;
    if (cp <= 0x7F) {
        out.push_back(static_cast<char>(cp));
    } else if (cp <= 0x7FF) {
        out.push_back(static_cast<char>(0xC0 | ((cp >> 6) & 0x1F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else if (cp <= 0xFFFF) {
        out.push_back(static_cast<char>(0xE0 | ((cp >> 12) & 0x0F)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else if (cp <= 0x10FFFF) {
        out.push_back(static_cast<char>(0xF0 | ((cp >> 18) & 0x07)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    }
}
} // namespace

std::string ensure_utf8(const std::string& raw) {
    if (raw.empty() || is_valid_utf8(raw)) return raw;
    std::string gbk = iconv_convert("GB18030", "UTF-8", raw.data(), raw.size());
    if (!gbk.empty() && is_valid_utf8(gbk)) return gbk;
    return raw;
}

std::string utf16le_to_utf8(const uint8_t* data, size_t byte_len) {
    std::string out;
    for (size_t i = 0; i + 1 < byte_len; i += 2) {
        uint16_t w1 = static_cast<uint16_t>(data[i]) | (static_cast<uint16_t>(data[i + 1]) << 8);
        if (w1 == 0) break;
        if (w1 < 32) continue; // skip OLE leading control bytes like \x01, \x02, \x05
        if (w1 >= 0xD800 && w1 <= 0xDBFF && i + 3 < byte_len) {
            uint16_t w2 = static_cast<uint16_t>(data[i + 2]) | (static_cast<uint16_t>(data[i + 3]) << 8);
            if (w2 >= 0xDC00 && w2 <= 0xDFFF) {
                uint32_t cp = 0x10000 + (((w1 - 0xD800) << 10) | (w2 - 0xDC00));
                append_codepoint_utf8(out, cp);
                i += 2;
                continue;
            }
        }
        append_codepoint_utf8(out, w1);
    }
    return out;
}

std::string utf16be_to_utf8(const uint8_t* data, size_t byte_len) {
    std::string out;
    for (size_t i = 0; i + 1 < byte_len; i += 2) {
        uint16_t w1 = (static_cast<uint16_t>(data[i]) << 8) | static_cast<uint16_t>(data[i + 1]);
        if (w1 == 0) break;
        if (w1 < 32) continue;
        if (w1 >= 0xD800 && w1 <= 0xDBFF && i + 3 < byte_len) {
            uint16_t w2 = (static_cast<uint16_t>(data[i + 2]) << 8) | static_cast<uint16_t>(data[i + 3]);
            if (w2 >= 0xDC00 && w2 <= 0xDFFF) {
                uint32_t cp = 0x10000 + (((w1 - 0xD800) << 10) | (w2 - 0xDC00));
                append_codepoint_utf8(out, cp);
                i += 2;
                continue;
            }
        }
        append_codepoint_utf8(out, w1);
    }
    return out;
}

ftype::FileType detect_file_type(const std::string& path, const std::vector<uint8_t>& header) {
    if (!path.empty() && file_exists(path) && !is_directory(path)) {
        ftype::FileType ft = ftype::detect_file(path);
        if (ft.ext && std::strcmp(ft.ext, "unknown") != 0 && std::strcmp(ft.ext, "error") != 0 && std::strcmp(ft.ext, "empty") != 0) {
            return ft;
        }
    }
    if (!header.empty()) {
        ftype::FileType ft = ftype::detect_bytes(header.data(), header.size());
        if (ft.ext && std::strcmp(ft.ext, "unknown") != 0 && std::strcmp(ft.ext, "empty") != 0) {
            return ft;
        }
    }
    return {"unknown", "application/octet-stream"};
}

std::string detect_format(const std::string& path, const std::vector<uint8_t>& h) {
    std::string ext = get_extension(path);
    auto match = [&](size_t offset, const void* sig, size_t len) -> bool {
        if (h.size() < offset + len) return false;
        return std::memcmp(h.data() + offset, sig, len) == 0;
    };

    // 1. High-accuracy real format identification via ftype
    ftype::FileType ft = detect_file_type(path, h);
    std::string fext = (ft.ext && std::strcmp(ft.ext, "unknown") != 0 && std::strcmp(ft.ext, "error") != 0 && std::strcmp(ft.ext, "empty") != 0)
                           ? std::string(ft.ext)
                           : "";

    if (!fext.empty()) {
        // Map OOXML variants
        if (fext == "docx" || fext == "xlsx" || fext == "pptx" ||
            fext == "docm" || fext == "dotx" || fext == "xlsm" || fext == "xltx" ||
            fext == "pptm" || fext == "ppsx" || fext == "potx") {
            return "opc-office(" + fext + ")";
        }
        // Map Legacy OLE2 / WPS / Yongzhong
        if (fext == "doc" || fext == "xls" || fext == "ppt" ||
            fext == "wps" || fext == "wpt" || fext == "et" || fext == "dps" ||
            fext == "vsd" || fext == "msg") {
            return "ole2(" + fext + ")";
        }
        if (fext == "msi") {
            if (ext == ".doc" || ext == ".xls" || ext == ".ppt") return "ole2(" + ext.substr(1) + ")";
            return "ole2(msi)";
        }
        if (fext == "apk" || fext == "aab" || fext == "ipa") return "mobile-bundle(" + fext + ")";
        if (fext == "jar" || fext == "war" || fext == "ear") return "java-archive(" + fext + ")";
        if (fext == "gz") return "gzip";
        if (fext == "bz2") return "bzip2";
        if (fext == "jpg") return "jpeg";
        if (fext == "sh") return "shell-script";
        if (fext == "exe") return "pe-executable";
        if (fext == "dll") return "pe-dll";
        if (fext == "whl") return "python-wheel";
        if (fext == "idml") return "indesign-idml";

        if (fext == "zip") {
            if (ext == ".docx" || ext == ".xlsx" || ext == ".pptx") return "opc-office(" + ext.substr(1) + ")";
            if (ext == ".apk" || ext == ".aab" || ext == ".ipa") return "mobile-bundle(" + ext.substr(1) + ")";
            if (ext == ".jar" || ext == ".war" || ext == ".ear") return "java-archive(" + ext.substr(1) + ")";
            if (ext == ".whl") return "python-wheel";
            if (ext == ".idml") return "indesign-idml";
            return "zip";
        }

        // Direct extractor formats
        if (fext == "7z" || fext == "rar" || fext == "tar" ||
            fext == "xz" || fext == "zstd" || fext == "cpio" || fext == "iso" ||
            fext == "deb" || fext == "ar" || fext == "pdf" || fext == "rtf" ||
            fext == "psd" || fext == "psb" || fext == "ai" || fext == "indd" ||
            fext == "squashfs" || fext == "dmg" || fext == "vmdk" || fext == "vhd" ||
            fext == "vhdx" || fext == "svg" || fext == "png" || fext == "gif" ||
            fext == "bmp" || fext == "webp" || fext == "sqlite" || fext == "elf" ||
            fext == "so" || fext == "ofd" || fext == "uof" || fext == "eio" ||
            fext == "cebx" || fext == "epub") {
            return fext;
        }
    }

    // 2. Legacy / container-specific fallbacks
    if (match(0, "PK\x03\x04", 4) || match(0, "PK\x05\x06", 4)) {
        if (ext == ".docx" || ext == ".xlsx" || ext == ".pptx") return "opc-office(" + ext.substr(1) + ")";
        if (ext == ".apk" || ext == ".aab" || ext == ".ipa") return "mobile-bundle(" + ext.substr(1) + ")";
        if (ext == ".jar" || ext == ".war" || ext == ".ear") return "java-archive(" + ext.substr(1) + ")";
        if (ext == ".whl") return "python-wheel";
        if (ext == ".idml") return "indesign-idml";
        return "zip";
    }
    if (match(0, "\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1", 8)) return "ole2";
    if (match(0, "\x04\x00\x00\x00", 4) && h.size() >= 16 && std::memcmp(h.data() + 16, "{\"files\"", 8) == 0) return "asar";
    if (match(0, "\xE4\x52\x5C\x7B\x8C\xD8\xA7\x4D\xAE\xB1\x53\x78\xD0\x29\x96\xD3", 16)) return "onenote";
    if (match(0, "PYZ\x00", 4)) return "pyz";
    if (match(0, "\x01\x00\x00\x00", 4) && h.size() >= 44 && match(40, " EMF", 4)) return "emf";
    if (match(0, "\xD7\xCD\xC6\x9A", 4) || match(0, "\x01\x00\x09\x00", 4) || match(0, "\x02\x00\x09\x00", 4)) return "wmf";

    if (!fext.empty()) return fext;

    if (ext == ".iso" || ext == ".img" || ext == ".dmg" || ext == ".vhd" || ext == ".vhdx" || ext == ".vmdk" ||
        ext == ".squashfs" || ext == ".fat" || ext == ".ntfs" || ext == ".ext2" || ext == ".ext3" || ext == ".ext4" || ext == ".hfs") {
        return ext.substr(1);
    }
    if (ext == ".deb" || ext == ".udeb") return "deb";
    if (ext == ".ar" || ext == ".a") return "ar";
    if (ext == ".pkg") return "pyinstaller-pkg";
    if (ext == ".pyz") return "pyz";
    if (ext == ".asar") return "asar";
    if (ext == ".svg") return "svg";
    if (ext == ".psb") return "psb";
    if (ext == ".psd") return "psd";
    if (ext == ".ai" || ext == ".indd" || ext == ".idml") return ext.substr(1);
    if (ext == ".one") return "onenote";
    return "binary";
}

namespace {
std::string escape_json(const std::string& s) {
    std::ostringstream o;
    for (unsigned char c : s) {
        switch (c) {
            case '"': o << "\\\""; break;
            case '\\': o << "\\\\"; break;
            case '\b': o << "\\b"; break;
            case '\f': o << "\\f"; break;
            case '\n': o << "\\n"; break;
            case '\r': o << "\\r"; break;
            case '\t': o << "\\t"; break;
            default:
                if (c < 0x20) {
                    o << "\\u" << std::hex << std::setw(4) << std::setfill('0') << static_cast<int>(c);
                } else {
                    o << c;
                }
        }
    }
    return o.str();
}
} // namespace

std::string to_json(const ExtractedItem& item, int indent) {
    std::string pad(indent * 2, ' ');
    std::string pad2((indent + 1) * 2, ' ');
    std::ostringstream oss;
    oss << pad << "{\n";
    oss << pad2 << "\"name\": \"" << escape_json(item.name) << "\",\n";
    oss << pad2 << "\"saved_path\": \"" << escape_json(item.saved_path) << "\",\n";
    oss << pad2 << "\"format\": \"" << escape_json(item.format) << "\",\n";
    if (!item.real_ext.empty()) {
        oss << pad2 << "\"real_ext\": \"" << escape_json(item.real_ext) << "\",\n";
    }
    if (!item.mime_type.empty()) {
        oss << pad2 << "\"mime_type\": \"" << escape_json(item.mime_type) << "\",\n";
    }
    oss << pad2 << "\"extractor\": \"" << escape_json(item.extractor_name) << "\",\n";
    oss << pad2 << "\"offset\": " << item.offset << ",\n";
    oss << pad2 << "\"size\": " << item.size << ",\n";
    oss << pad2 << "\"sha256\": \"" << escape_json(item.sha256) << "\",\n";
    oss << pad2 << "\"depth\": " << item.depth << ",\n";
    if (!item.associated_icon_path.empty()) {
        oss << pad2 << "\"associated_icon_path\": \"" << escape_json(item.associated_icon_path) << "\",\n";
    }
    oss << pad2 << "\"children\": [";
    if (item.children.empty()) {
        oss << "]\n";
    } else {
        oss << "\n";
        for (size_t i = 0; i < item.children.size(); ++i) {
            oss << to_json(item.children[i], indent + 2);
            if (i + 1 < item.children.size()) oss << ",";
            oss << "\n";
        }
        oss << pad2 << "]\n";
    }
    oss << pad << "}";
    return oss.str();
}

bool is_office_extension(const std::string& ext) {
    std::string e = to_lower(ext);
    if (!e.empty() && e[0] == '.') e = e.substr(1);
    return (e == "docx" || e == "xlsx" || e == "pptx" || e == "doc" || e == "xls" ||
            e == "ppt" || e == "dot" || e == "dotx" || e == "docm" || e == "xlt" ||
            e == "xltx" || e == "xlsm" || e == "xlsb" || e == "pot" || e == "potx" ||
            e == "pptm" || e == "ppsx" || e == "rtf" || e == "one" || e == "vsd" ||
            e == "vsdx" || e == "mpp" || e == "wps" || e == "wpt" || e == "et" ||
            e == "dps" || e == "odt" || e == "ott" || e == "ods" || e == "ots" ||
            e == "odp" || e == "otp" || e == "ofd" || e == "uof" || e == "eio" ||
            e == "cebx" || e == "ceb" || e == "caj" || e == "kdh" || e == "epub" ||
            e == "mobi" || e == "azw" || e == "azw3" || e == "fb2" || e == "djvu" ||
            e == "chm" || e == "hlp");
}

bool is_image_extension(const std::string& ext) {
    std::string e = to_lower(ext);
    if (!e.empty() && e[0] == '.') e = e.substr(1);
    return (e == "png" || e == "jpg" || e == "jpeg" || e == "gif" || e == "bmp" ||
            e == "webp" || e == "svg" || e == "ico" || e == "cur" || e == "tiff" ||
            e == "tif" || e == "emf" || e == "wmf" || e == "psd" || e == "psb" ||
            e == "ai" || e == "eps" || e == "raw" || e == "cr2" || e == "cr3" ||
            e == "nef" || e == "arw" || e == "orf" || e == "rw2" || e == "raf" ||
            e == "dng" || e == "heic" || e == "avif" || e == "jxl" || e == "jp2" ||
            e == "exr" || e == "hdr" || e == "dds" || e == "bpg" || e == "dwg" ||
            e == "dxf");
}

bool is_text_extension(const std::string& ext) {
    std::string e = to_lower(ext);
    if (!e.empty() && e[0] == '.') e = e.substr(1);
    return (e == "txt" || e == "md" || e == "json" || e == "jsonl" || e == "xml" ||
            e == "html" || e == "htm" || e == "css" || e == "scss" || e == "js" ||
            e == "ts" || e == "jsx" || e == "tsx" || e == "csv" || e == "tsv" ||
            e == "log" || e == "yaml" || e == "yml" || e == "ini" || e == "conf" ||
            e == "cfg" || e == "sh" || e == "bash" || e == "zsh" || e == "py" || e == "pyc" ||
            e == "c" || e == "cpp" || e == "cc" || e == "cxx" || e == "h" ||
            e == "hpp" || e == "hxx" || e == "java" || e == "class" || e == "kt" || e == "rs" ||
            e == "go" || e == "sql" || e == "proto" || e == "env" || e == "properties" ||
            e == "diff" || e == "patch" || e == "bat" || e == "ps1" || e == "toml" ||
            e == "lua" || e == "rb" || e == "php" || e == "swift" || e == "m" ||
            e == "asm" || e == "wasm" || e == "wat" || e == "desktop");
}

bool is_pdf_extension(const std::string& ext) {
    std::string e = to_lower(ext);
    if (!e.empty() && e[0] == '.') e = e.substr(1);
    return e == "pdf";
}

bool is_container_extension(const std::string& ext) {
    std::string e = to_lower(ext);
    if (!e.empty() && e[0] == '.') e = e.substr(1);
    return (e == "zip" || e == "7z" || e == "rar" || e == "tar" || e == "gz" ||
            e == "tar.gz" || e == "tar.xz" || e == "tar.bz2" || e == "tar.zst" ||
            e == "tgz" || e == "bz2" || e == "xz" || e == "zst" || e == "deb" ||
            e == "udeb" || e == "ar" || e == "a" || e == "asar" || e == "apk" ||
            e == "aab" || e == "ipa" || e == "jar" || e == "war" || e == "ear" ||
            e == "iso" || e == "squashfs" || e == "whl" || e == "pkg" ||
            e == "vhd" || e == "vhdx" || e == "vmdk" || e == "dmg" || e == "cpio" ||
            e == "indd" || e == "idml" || e == "pyz" || e == "bin" || e == "cab" ||
            e == "msix" || e == "xpi" || e == "crx" || e == "wim" || e == "xar" ||
            e == "rpm" || is_office_extension(e) || is_pdf_extension(e));
}

bool should_extract_item(const std::string& path_or_name, const UnnestConfig& config, const std::string& fmt) {
    if (config.extract_all) return true;

    std::string ext = get_extension(path_or_name);
    std::string base = to_lower(base_name(path_or_name));

    // OCI layer blobs (e.g. blobs/sha256/<hash>) have no extension but are tar/gz containers
    if (path_or_name.find("blobs/") != std::string::npos || path_or_name.find("sha256/") != std::string::npos) {
        return true;
    }

    // Inspect real format via ftype if physical file exists on disk
    std::string real_ext;
    if (file_exists(path_or_name) && !is_directory(path_or_name)) {
        ftype::FileType ft = ftype::detect_file(path_or_name);
        if (ft.ext && std::strcmp(ft.ext, "unknown") != 0 && std::strcmp(ft.ext, "error") != 0 && std::strcmp(ft.ext, "empty") != 0) {
            real_ext = ft.ext;
        }
    } else if (!fmt.empty()) {
        real_ext = fmt;
        if (real_ext.find("opc-office(") == 0 && real_ext.back() == ')') {
            real_ext = real_ext.substr(11, real_ext.size() - 12);
        } else if (real_ext.find("ole2(") == 0 && real_ext.back() == ')') {
            real_ext = real_ext.substr(5, real_ext.size() - 6);
        }
    }

    // Always preserve container files for recursive traversal
    if (is_container_extension(ext) || (!real_ext.empty() && is_container_extension(real_ext))) {
        return true;
    }

    if (!fmt.empty() && (fmt == "zip" || fmt == "7z" || fmt == "rar" || fmt == "tar" ||
                         fmt == "gzip" || fmt == "bzip2" || fmt == "xz" || fmt == "zstd" ||
                         fmt == "deb" || fmt == "ar" || fmt == "asar" || fmt == "iso" ||
                         fmt == "squashfs" || fmt == "ole2" || fmt == "pdf" ||
                         fmt.find("opc-office") == 0 || fmt.find("mobile-bundle") == 0 ||
                         fmt.find("java-archive") == 0)) {
        return true;
    }

    // Real type checks from ftype first
    if (!real_ext.empty()) {
        if (config.filter_office && is_office_extension(real_ext)) return true;
        if (config.filter_image && is_image_extension(real_ext)) return true;
        if (config.filter_text && is_text_extension(real_ext)) return true;
        if (config.filter_pdf && is_pdf_extension(real_ext)) return true;
    }

    // Extension fallback
    if (!ext.empty()) {
        if (config.filter_office && is_office_extension(ext)) return true;
        if (config.filter_image && is_image_extension(ext)) return true;
        if (config.filter_text && is_text_extension(ext)) return true;
        if (config.filter_pdf && is_pdf_extension(ext)) return true;
    }

    // Files without extension (README, LICENSE, Makefile, Dockerfile, control, postinst, etc.)
    if (ext.empty() || ext == path_or_name) {
        if (config.filter_text) {
            return true;
        }
    }

    return false;
}

std::vector<std::string> list_files_recursive(const std::string& root_dir) {
    std::vector<std::string> result;
    DIR* dir = opendir(root_dir.c_str());
    if (!dir) return result;
    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr) {
        std::string name = entry->d_name;
        if (name == "." || name == "..") continue;
        std::string full = join_path(root_dir, name);
        if (is_directory(full)) {
            std::vector<std::string> sub = list_files_recursive(full);
            result.insert(result.end(), sub.begin(), sub.end());
        } else {
            result.push_back(full);
        }
    }
    closedir(dir);
    std::sort(result.begin(), result.end());
    return result;
}

bool run_external_cmd(const std::vector<std::string>& args) {
    if (args.empty()) return false;
    pid_t pid = fork();
    if (pid < 0) return false;
    if (pid == 0) {
        // Redirect stdout/stderr to /dev/null
        FILE* f = std::fopen("/dev/null", "w");
        if (f) {
            dup2(fileno(f), STDOUT_FILENO);
            dup2(fileno(f), STDERR_FILENO);
            std::fclose(f);
        }
        std::vector<char*> cargs;
        for (const auto& s : args) cargs.push_back(const_cast<char*>(s.c_str()));
        cargs.push_back(nullptr);
        execvp(cargs[0], cargs.data());
        _exit(127);
    }
    int status = 0;
    if (waitpid(pid, &status, 0) < 0) return false;
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

} // namespace utils
} // namespace unnest
