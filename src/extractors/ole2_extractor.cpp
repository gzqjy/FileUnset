#include "fileunnest/extractor.h"
#include "fileunnest/utils.h"
#include <cstdint>
#include <cstring>
#include <map>
#include <set>
#include <zlib.h>

namespace unnest {

namespace {

inline uint16_t read_u16_le(const uint8_t* p) {
    return static_cast<uint16_t>(p[0]) | (static_cast<uint16_t>(p[1]) << 8);
}

inline uint32_t read_u32_le(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) |
           (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) |
           (static_cast<uint32_t>(p[3]) << 24);
}

inline uint64_t read_u64_le(const uint8_t* p) {
    return static_cast<uint64_t>(read_u32_le(p)) |
           (static_cast<uint64_t>(read_u32_le(p + 4)) << 32);
}

inline void write_u16_le(uint8_t* p, uint16_t v) {
    p[0] = static_cast<uint8_t>(v & 0xFF);
    p[1] = static_cast<uint8_t>((v >> 8) & 0xFF);
}

inline void write_u32_le(uint8_t* p, uint32_t v) {
    p[0] = static_cast<uint8_t>(v & 0xFF);
    p[1] = static_cast<uint8_t>((v >> 8) & 0xFF);
    p[2] = static_cast<uint8_t>((v >> 16) & 0xFF);
    p[3] = static_cast<uint8_t>((v >> 24) & 0xFF);
}

struct CfbDirNode {
    uint32_t id;
    std::string parent_path;
    std::string full_path;
    std::string base_name;
    std::vector<uint8_t> raw_name_u16; // Original UTF-16LE bytes from directory entry
    uint8_t obj_type;
    uint32_t start_sec;
    uint64_t stream_size;
};

bool zlib_inflate_stream(const uint8_t* src, size_t src_len, std::vector<uint8_t>& out, size_t max_out) {
    z_stream strm;
    std::memset(&strm, 0, sizeof(strm));
    if (inflateInit(&strm) != Z_OK) return false;
    strm.next_in = const_cast<Bytef*>(src);
    strm.avail_in = static_cast<uInt>(src_len);
    uint8_t buf[16384];
    int ret = Z_OK;
    while (ret == Z_OK) {
        strm.next_out = buf;
        strm.avail_out = sizeof(buf);
        ret = inflate(&strm, Z_NO_FLUSH);
        if (ret != Z_OK && ret != Z_STREAM_END) {
            inflateEnd(&strm);
            return false;
        }
        size_t have = sizeof(buf) - strm.avail_out;
        if (out.size() + have > max_out) {
            inflateEnd(&strm);
            return false;
        }
        out.insert(out.end(), buf, buf + have);
    }
    inflateEnd(&strm);
    return !out.empty();
}

// Parse \x01CompObj stream (offset 28: Length-prefixed ANSI UserType, ClipboardFormat, ProgID)
std::string parse_compobj_progid(const std::vector<uint8_t>& compobj) {
    if (compobj.size() < 32) return "";
    size_t pos = 28;
    std::string user_type, prog_id;
    for (int field = 0; field < 3 && pos + 4 <= compobj.size(); ++field) {
        uint32_t slen = read_u32_le(compobj.data() + pos);
        pos += 4;
        if (slen == 0) continue;
        if (field == 1 && (slen == 0xFFFFFFFF || slen == 0xFFFFFFFE)) {
            if (pos + 4 <= compobj.size()) pos += 4;
            continue;
        }
        if (slen > 512 || pos + slen > compobj.size()) break;
        std::string s(reinterpret_cast<const char*>(compobj.data() + pos), slen > 0 ? slen - 1 : 0);
        if (field == 0) user_type = utils::ensure_utf8(s);
        else if (field == 2) prog_id = utils::ensure_utf8(s);
        pos += slen;
    }
    return !prog_id.empty() ? prog_id : user_type;
}

// Extension Item 1: Unwrap OLE10Native (both standard flags==2 Package and compact flags!=2 raw mode)
bool try_unwrap_ole10native(const std::vector<uint8_t>& stream,
                            std::string& out_filename,
                            std::vector<uint8_t>& out_payload) {
    if (stream.size() < 8) return false;
    uint32_t declared_total = read_u32_le(stream.data());
    uint16_t flags = read_u16_le(stream.data() + 4);

    // Mode A: Standard Package header (flags == 2)
    if (flags == 2 && stream.size() >= 20) {
        size_t pos = 6;
        while (pos < stream.size() && stream[pos] != 0) pos++;
        if (pos < stream.size()) {
            std::string label(reinterpret_cast<const char*>(stream.data() + 6), pos - 6);
            pos++;
            size_t fn_start = pos;
            while (pos < stream.size() && stream[pos] != 0) pos++;
            if (pos < stream.size()) {
                std::string orig_fn(reinterpret_cast<const char*>(stream.data() + fn_start), pos - fn_start);
                pos++;
                for (size_t probe = pos; probe + 4 <= stream.size(); ++probe) {
                    uint32_t sz = read_u32_le(stream.data() + probe);
                    if (sz >= 8 && probe + 4 + sz <= stream.size()) {
                        const uint8_t* p = stream.data() + probe + 4;
                        bool valid_sig = (std::memcmp(p, "PK\x03\x04", 4) == 0 ||
                                          std::memcmp(p, "\x89PNG\r\n\x1A\n", 8) == 0 ||
                                          std::memcmp(p, "\xFF\xD8\xFF", 3) == 0 ||
                                          std::memcmp(p, "%PDF-", 5) == 0 ||
                                          std::memcmp(p, "\xD0\xCF\x11\xE0", 4) == 0 ||
                                          (probe + 4 + sz >= stream.size() - 16));
                        if (valid_sig) {
                            std::string utf8_wide_fn;
                            size_t tail = probe + 4 + sz;
                            if (tail + 4 <= stream.size()) {
                                uint32_t wlen1 = read_u32_le(stream.data() + tail);
                                if (wlen1 < 512 && tail + 4 + wlen1 * 2 + 4 <= stream.size()) {
                                    size_t t2 = tail + 4 + wlen1 * 2;
                                    uint32_t wlen2 = read_u32_le(stream.data() + t2);
                                    if (wlen2 > 0 && wlen2 < 512 && t2 + 4 + wlen2 * 2 <= stream.size()) {
                                        utf8_wide_fn = utils::utf16le_to_utf8(stream.data() + t2 + 4, wlen2 * 2);
                                    }
                                }
                            }
                            std::string raw_chosen = !utf8_wide_fn.empty()
                                                         ? utf8_wide_fn
                                                         : (!orig_fn.empty() ? orig_fn : (!label.empty() ? label : "ole10_embedded.bin"));
                            out_filename = utils::base_name(utils::ensure_utf8(raw_chosen));
                            out_payload.assign(p, p + sz);
                            return true;
                        }
                    }
                }
            }
        }
    }

    // Mode B: Compact / Headerless Ole10Native (flags != 2, payload starts right at offset 4)
    if (declared_total > 0 && 4ULL + declared_total <= stream.size()) {
        out_payload.assign(stream.data() + 4, stream.data() + 4 + declared_total);
        std::string fmt = utils::detect_format("", out_payload);
        std::string ext = ".bin";
        if (fmt == "zip") ext = ".zip";
        else if (fmt == "png") ext = ".png";
        else if (fmt == "jpeg") ext = ".jpg";
        else if (fmt == "pdf") ext = ".pdf";
        else if (fmt == "ole2") ext = ".ole";
        out_filename = "ole10_compact_payload" + ext;
        return true;
    }
    return false;
}

// Extension Item 1: Rebuild a standalone MS-CFB (.xls / .doc / .ppt) from an embedded Sub-Storage
std::vector<uint8_t> repackage_substorage_to_cfb(const std::vector<std::pair<CfbDirNode, std::vector<uint8_t>>>& streams) {
    // Calculate sectors needed when mini_stream_cutoff = 0 (all streams in regular 512B sectors)
    std::vector<uint32_t> stream_start_sec(streams.size(), 0xFFFFFFFE);
    size_t num_dir_entries = 1 + streams.size(); // Entry 0 (Root Entry) + N streams
    size_t num_dir_sectors = (num_dir_entries * 128 + 511) / 512;

    size_t data_sectors = 0;
    for (const auto& kv : streams) {
        size_t n = (kv.second.size() + 511) / 512;
        data_sectors += n;
    }

    size_t total_non_fat_sectors = num_dir_sectors + data_sectors;
    size_t num_fat_sectors = (total_non_fat_sectors + 127) / 128;
    if (num_fat_sectors == 0) num_fat_sectors = 1;
    // Recalculate if FAT sectors themselves push total sectors over boundary
    num_fat_sectors = (total_non_fat_sectors + num_fat_sectors + 127) / 128;

    size_t total_sectors = num_fat_sectors + num_dir_sectors + data_sectors;
    std::vector<uint8_t> cfb((1 + total_sectors) * 512, 0);

    // 1. Write 512B Header
    const uint8_t sig[8] = {0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1};
    std::memcpy(cfb.data(), sig, 8);
    write_u16_le(cfb.data() + 24, 0x003E);
    write_u16_le(cfb.data() + 26, 0x0003);
    write_u16_le(cfb.data() + 28, 0xFFFE);
    write_u16_le(cfb.data() + 30, 9);
    write_u16_le(cfb.data() + 32, 6);
    write_u32_le(cfb.data() + 44, static_cast<uint32_t>(num_fat_sectors));
    write_u32_le(cfb.data() + 48, static_cast<uint32_t>(num_fat_sectors)); // First Dir sector right after FAT sectors
    write_u32_le(cfb.data() + 56, 0); // mini_stream_cutoff = 0
    write_u32_le(cfb.data() + 60, 0xFFFFFFFE);
    write_u32_le(cfb.data() + 68, 0xFFFFFFFE);
    for (int i = 0; i < 109; ++i) {
        uint32_t v = (static_cast<size_t>(i) < num_fat_sectors) ? static_cast<uint32_t>(i) : 0xFFFFFFFF;
        write_u32_le(cfb.data() + 76 + i * 4, v);
    }

    // 2. Initialize FAT with 0xFFFFFFFF
    size_t fat_base = 512;
    for (size_t i = 0; i < num_fat_sectors * 128; ++i) {
        write_u32_le(cfb.data() + fat_base + i * 4, 0xFFFFFFFF);
    }
    for (size_t i = 0; i < num_fat_sectors; ++i) {
        write_u32_le(cfb.data() + fat_base + i * 4, 0xFFFFFFFD); // FATSECT
    }
    for (size_t i = 0; i < num_dir_sectors; ++i) {
        uint32_t sec = static_cast<uint32_t>(num_fat_sectors + i);
        uint32_t nxt = (i + 1 < num_dir_sectors) ? (sec + 1) : 0xFFFFFFFE;
        write_u32_le(cfb.data() + fat_base + sec * 4, nxt);
    }

    // 3. Write Stream data sectors & FAT chains
    uint32_t cur_sec = static_cast<uint32_t>(num_fat_sectors + num_dir_sectors);
    for (size_t idx = 0; idx < streams.size(); ++idx) {
        const auto& payload = streams[idx].second;
        if (payload.empty()) {
            stream_start_sec[idx] = 0xFFFFFFFE;
            continue;
        }
        stream_start_sec[idx] = cur_sec;
        size_t n_sec = (payload.size() + 511) / 512;
        std::memcpy(cfb.data() + (1 + cur_sec) * 512, payload.data(), payload.size());
        for (size_t s = 0; s < n_sec; ++s) {
            uint32_t sec_id = cur_sec + static_cast<uint32_t>(s);
            uint32_t nxt = (s + 1 < n_sec) ? (sec_id + 1) : 0xFFFFFFFE;
            write_u32_le(cfb.data() + fat_base + sec_id * 4, nxt);
        }
        cur_sec += static_cast<uint32_t>(n_sec);
    }

    // 4. Write Directory Entries (Entry 0 = Root Entry, Entry 1..N chained via rightSiblingID)
    size_t dir_base = (1 + num_fat_sectors) * 512;
    for (size_t s = 0; s < num_dir_sectors * 4; ++s) {
        uint8_t* ent = cfb.data() + dir_base + s * 128;
        write_u32_le(ent + 68, 0xFFFFFFFF);
        write_u32_le(ent + 72, 0xFFFFFFFF);
        write_u32_le(ent + 76, 0xFFFFFFFF);
    }
    const char* rname = "Root Entry";
    for (size_t i = 0; rname[i]; ++i) write_u16_le(cfb.data() + dir_base + i * 2, rname[i]);
    write_u16_le(cfb.data() + dir_base + 64, static_cast<uint16_t>((std::strlen(rname) + 1) * 2));
    cfb[dir_base + 66] = 5;
    cfb[dir_base + 67] = 1;
    write_u32_le(cfb.data() + dir_base + 76, streams.empty() ? 0xFFFFFFFF : 1);
    write_u32_le(cfb.data() + dir_base + 116, 0xFFFFFFFE);

    for (size_t idx = 0; idx < streams.size(); ++idx) {
        uint8_t* ent = cfb.data() + dir_base + (1 + idx) * 128;
        const auto& raw_u16 = streams[idx].first.raw_name_u16;
        size_t copy_len = std::min<size_t>(raw_u16.size(), 62);
        std::memcpy(ent, raw_u16.data(), copy_len);
        write_u16_le(ent + 64, static_cast<uint16_t>(copy_len + 2));
        ent[66] = 2; // Stream
        ent[67] = 1;
        write_u32_le(ent + 68, 0xFFFFFFFF);
        write_u32_le(ent + 72, (idx + 1 < streams.size()) ? static_cast<uint32_t>(idx + 2) : 0xFFFFFFFF);
        write_u32_le(ent + 76, 0xFFFFFFFF);
        write_u32_le(ent + 116, stream_start_sec[idx]);
        write_u32_le(ent + 120, static_cast<uint32_t>(streams[idx].second.size()));
    }
    return cfb;
}

// Extension Item 2: MS-ODRAW OfficeArtBlip Record Parser (PNG, JPEG, DIB->BMP, compressed EMF/WMF)
int extract_officeart_blips(const std::string& stream_label,
                            const std::vector<uint8_t>& content,
                            const std::string& output_dir,
                            uint64_t max_file_size,
                            std::vector<ExtractedItem>& out_items) {
    int count = 0;
    size_t pos = 0;

    // 1. Scan for formal MS-ODRAW OfficeArtBlip records (0xF01A..0xF029)
    while (pos + 25 <= content.size()) {
        uint16_t ver_inst = read_u16_le(content.data() + pos);
        uint16_t rec_type = read_u16_le(content.data() + pos + 2);
        uint32_t rec_len = read_u32_le(content.data() + pos + 4);
        uint16_t rec_inst = ver_inst >> 4;

        if (rec_type >= 0xF01A && rec_type <= 0xF029 && rec_len >= 17 && pos + 8 + rec_len <= content.size()) {
            const uint8_t* body = content.data() + pos + 8;
            // Metafile Blips: EMF (0xF01A), WMF (0xF01B), PICT (0xF01C)
            if (rec_type == 0xF01A || rec_type == 0xF01B) {
                uint16_t base_inst = (rec_type == 0xF01A) ? 0x03D4 : 0x0216;
                size_t uid_size = ((rec_inst ^ base_inst) == 1) ? 32 : 16;
                if (rec_len > uid_size + 34) {
                    const uint8_t* meta_hdr = body + uid_size;
                    uint8_t f_compression = meta_hdr[32];
                    const uint8_t* comp_data = meta_hdr + 34;
                    size_t comp_len = rec_len - uid_size - 34;

                    std::vector<uint8_t> raw_meta;
                    if (f_compression == 0) {
                        zlib_inflate_stream(comp_data, comp_len, raw_meta, static_cast<size_t>(max_file_size));
                    } else {
                        raw_meta.assign(comp_data, comp_data + comp_len);
                    }

                    if (!raw_meta.empty()) {
                        // For WMF (0xF01B), prepend 22-byte Aldus Placeable Metafile Header if not present
                        if (rec_type == 0xF01B && (raw_meta.size() < 4 || read_u32_le(raw_meta.data()) != 0x9AC6CDD7)) {
                            std::vector<uint8_t> aldus(22, 0);
                            write_u32_le(aldus.data() + 0, 0x9AC6CDD7);
                            write_u16_le(aldus.data() + 6, 0);
                            write_u16_le(aldus.data() + 8, 0);
                            write_u16_le(aldus.data() + 10, 1000);
                            write_u16_le(aldus.data() + 12, 1000);
                            write_u16_le(aldus.data() + 14, 96);
                            uint16_t chksum = 0;
                            for (int k = 0; k < 10; ++k) chksum ^= read_u16_le(aldus.data() + k * 2);
                            write_u16_le(aldus.data() + 20, chksum);
                            aldus.insert(aldus.end(), raw_meta.begin(), raw_meta.end());
                            raw_meta.swap(aldus);
                        }
                        std::string ext = (rec_type == 0xF01A) ? ".emf" : ".wmf";
                        std::string iname = stream_label + "_blip_" + std::to_string(count++) + ext;
                        std::string ipath = utils::join_path(output_dir, utils::sanitize_relpath(iname));
                        if (utils::write_file(ipath, raw_meta.data(), raw_meta.size())) {
                            ExtractedItem item;
                            item.name = iname;
                            item.saved_path = ipath;
                            item.offset = pos;
                            item.size = raw_meta.size();
                            item.extractor_name = "Ole2Extractor(OfficeArtBlip)";
                            out_items.push_back(item);
                        }
                        pos += 8 + rec_len;
                        continue;
                    }
                }
            } else if (rec_type == 0xF01D || rec_type == 0xF01E || rec_type == 0xF01F) {
                // Bitmap Blips: JPEG (0xF01D), PNG (0xF01E), DIB (0xF01F)
                uint16_t base_inst = (rec_type == 0xF01D) ? 0x046A : ((rec_type == 0xF01E) ? 0x06E0 : 0x07A8);
                size_t hdr_skip = (((rec_inst ^ base_inst) & 1) == 1) ? 33 : 17;
                if (rec_len > hdr_skip) {
                    const uint8_t* img_ptr = body + hdr_skip;
                    size_t img_len = rec_len - hdr_skip;
                    std::vector<uint8_t> img_out;
                    std::string ext = (rec_type == 0xF01D) ? ".jpg" : ((rec_type == 0xF01E) ? ".png" : ".bmp");
                    if (rec_type == 0xF01F && img_len >= 40) {
                        // Prepend 14-byte BITMAPFILEHEADER ("BM") to DIB
                        uint32_t bi_size = read_u32_le(img_ptr);
                        uint16_t bi_bitcount = read_u16_le(img_ptr + 14);
                        uint32_t bi_clrused = read_u32_le(img_ptr + 32);
                        uint32_t palette_sz = (bi_clrused > 0) ? (bi_clrused * 4) : ((bi_bitcount <= 8) ? ((1U << bi_bitcount) * 4) : 0);
                        uint32_t bf_offbits = 14 + bi_size + palette_sz;
                        uint32_t bf_size = static_cast<uint32_t>(14 + img_len);
                        img_out.resize(14, 0);
                        img_out[0] = 'B'; img_out[1] = 'M';
                        write_u32_le(img_out.data() + 2, bf_size);
                        write_u32_le(img_out.data() + 10, bf_offbits);
                        img_out.insert(img_out.end(), img_ptr, img_ptr + img_len);
                    } else {
                        img_out.assign(img_ptr, img_ptr + img_len);
                    }
                    std::string iname = stream_label + "_image_" + std::to_string(count++) + ext;
                    std::string ipath = utils::join_path(output_dir, utils::sanitize_relpath(iname));
                    if (utils::write_file(ipath, img_out.data(), img_out.size())) {
                        ExtractedItem item;
                        item.name = iname;
                        item.saved_path = ipath;
                        item.offset = pos;
                        item.size = img_out.size();
                        item.extractor_name = "Ole2Extractor(OfficeArtBlip)";
                        out_items.push_back(item);
                    }
                    pos += 8 + rec_len;
                    continue;
                }
            }
        }

        // Fallback signature scan inside stream if not wrapped in standard Blip header
        if (std::memcmp(content.data() + pos, "\x89PNG\r\n\x1A\n", 8) == 0) {
            size_t png_end = 0;
            for (size_t e = pos + 8; e + 8 <= content.size(); ++e) {
                if (std::memcmp(content.data() + e, "IEND", 4) == 0) { png_end = e + 8; break; }
            }
            if (png_end > pos) {
                std::string iname = stream_label + "_image_" + std::to_string(count++) + ".png";
                std::string ipath = utils::join_path(output_dir, utils::sanitize_relpath(iname));
                if (utils::write_file(ipath, content.data() + pos, png_end - pos)) {
                    ExtractedItem item;
                    item.name = iname;
                    item.saved_path = ipath;
                    item.offset = pos;
                    item.size = png_end - pos;
                    item.extractor_name = "Ole2Extractor(OfficeArtBlip)";
                    out_items.push_back(item);
                }
                pos = png_end;
                continue;
            }
        }
        pos++;
    }
    return count;
}

// Extension Item 2b: WordDocument FIB & FKP Parser for Object-Icon Correlation (MS-DOC)
static std::map<std::string, uint32_t> parse_word_doc_icon_links(
    const std::vector<uint8_t>& word_doc,
    const std::vector<uint8_t>& table_stream) {
    std::map<std::string, uint32_t> result;
    if (word_doc.size() < 512 || table_stream.empty()) return result;
    if (read_u16_le(word_doc.data()) != 0xA5EC) return result;

    uint32_t fcPlcfbteChpx = read_u32_le(word_doc.data() + 0x00FA);
    uint32_t lcbPlcfbteChpx = read_u32_le(word_doc.data() + 0x00FE);
    if (lcbPlcfbteChpx < 8 || fcPlcfbteChpx + lcbPlcfbteChpx > table_stream.size()) {
        return result;
    }

    const uint8_t* plcf = table_stream.data() + fcPlcfbteChpx;
    uint32_t n = (lcbPlcfbteChpx - 4) / 8;
    const uint8_t* pns = plcf + (n + 1) * 4;

    std::vector<uint32_t> fc_list;
    for (uint32_t k = 0; k < n; ++k) {
        uint32_t pn = read_u32_le(pns + k * 4);
        if (static_cast<size_t>(pn) * 512 + 512 > word_doc.size()) continue;
        const uint8_t* fkp = word_doc.data() + pn * 512;
        uint8_t crun = fkp[511];
        for (uint8_t r = 0; r < crun; ++r) {
            uint16_t off = static_cast<uint16_t>(fkp[4 * (crun + 1) + r]) * 2;
            if (off > 0 && off < 511) {
                uint8_t cb = fkp[off];
                size_t max_len = std::min<size_t>(512 - off - 1, cb);
                const uint8_t* grpprl = fkp + off + 1;
                for (size_t idx = 0; idx + 6 <= max_len; ++idx) {
                    uint16_t sprm = read_u16_le(grpprl + idx);
                    if (sprm == 0x6A03 || sprm == 0x6803) {
                        fc_list.push_back(read_u32_le(grpprl + idx + 2));
                        break;
                    }
                }
            }
        }
    }

    for (size_t k = 0; k + 1 < fc_list.size(); ++k) {
        std::string obj_key = "_" + std::to_string(fc_list[k]);
        result[obj_key] = fc_list[k + 1];
    }
    return result;
}

class Ole2Extractor : public IExtractor {
public:
    std::string name() const override { return "Ole2Extractor(MS-CFB)"; }

    bool can_handle(const std::string&,
                    const std::string& fmt,
                    const std::vector<uint8_t>& header) const override {
        if (fmt == "ole2" || fmt.find("ole2") == 0 || fmt == "wps" || fmt == "wpt" ||
            fmt == "et" || fmt == "dps" || fmt == "doc" || fmt == "xls" || fmt == "ppt" ||
            fmt == "vsd" || fmt == "msg" || fmt == "eio") {
            return true;
        }
        return header.size() >= 8 && std::memcmp(header.data(), "\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1", 8) == 0;
    }

    bool extract(const std::string& file_path,
                 const std::string& output_dir,
                 const UnnestConfig& config,
                 std::vector<ExtractedItem>& out_items) override {
        std::vector<uint8_t> data;
        if (!utils::read_entire_file(file_path, data, config.max_file_size)) return false;
        if (data.size() < 512) return false;
        if (std::memcmp(data.data(), "\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1", 8) != 0) return false;

        uint16_t major_ver = read_u16_le(data.data() + 26);
        uint16_t byte_order = read_u16_le(data.data() + 28);
        uint16_t sector_shift = read_u16_le(data.data() + 30);
        uint16_t mini_shift = read_u16_le(data.data() + 32);
        if ((major_ver != 3 && major_ver != 4) || byte_order != 0xFFFE) return false;
        if (sector_shift < 7 || sector_shift > 16 || mini_shift < 4 || mini_shift > sector_shift) return false;

        size_t sector_size = 1ULL << sector_shift;
        size_t mini_sector_size = 1ULL << mini_shift;

        uint32_t num_fat_sectors = read_u32_le(data.data() + 44);
        uint32_t first_dir_sector = read_u32_le(data.data() + 48);
        uint32_t mini_stream_cutoff = read_u32_le(data.data() + 56);
        uint32_t first_minifat_sector = read_u32_le(data.data() + 60);
        uint32_t num_minifat_sectors = read_u32_le(data.data() + 64);
        uint32_t first_difat_sector = read_u32_le(data.data() + 68);
        uint32_t num_difat_sectors = read_u32_le(data.data() + 72);

        auto sector_offset = [&](uint32_t sec_id) -> size_t {
            return (static_cast<size_t>(sec_id) + 1) * sector_size;
        };

        std::vector<uint32_t> fat_sector_ids;
        for (int i = 0; i < 109 && fat_sector_ids.size() < num_fat_sectors; ++i) {
            uint32_t sid = read_u32_le(data.data() + 76 + i * 4);
            if (sid < 0xFFFFFFFC) fat_sector_ids.push_back(sid);
        }
        uint32_t cur_difat = first_difat_sector;
        uint32_t difat_count = 0;
        while (cur_difat < 0xFFFFFFFC && difat_count < num_difat_sectors) {
            size_t off = sector_offset(cur_difat);
            if (off + sector_size > data.size()) break;
            size_t entries_per_difat = (sector_size / 4) - 1;
            for (size_t i = 0; i < entries_per_difat && fat_sector_ids.size() < num_fat_sectors; ++i) {
                uint32_t sid = read_u32_le(data.data() + off + i * 4);
                if (sid < 0xFFFFFFFC) fat_sector_ids.push_back(sid);
            }
            cur_difat = read_u32_le(data.data() + off + entries_per_difat * 4);
            difat_count++;
        }

        std::vector<uint32_t> fat;
        for (uint32_t sid : fat_sector_ids) {
            size_t off = sector_offset(sid);
            if (off + sector_size > data.size()) continue;
            for (size_t i = 0; i < sector_size / 4; ++i) {
                fat.push_back(read_u32_le(data.data() + off + i * 4));
            }
        }

        auto read_chain = [&](uint32_t start_sec, uint64_t max_bytes) -> std::vector<uint8_t> {
            std::vector<uint8_t> out;
            uint32_t cur = start_sec;
            std::set<uint32_t> visited;
            while (cur < 0xFFFFFFFC && cur < fat.size()) {
                if (!visited.insert(cur).second) break;
                size_t off = sector_offset(cur);
                if (off + sector_size > data.size()) break;
                size_t to_copy = sector_size;
                if (out.size() + to_copy > max_bytes) {
                    to_copy = static_cast<size_t>(max_bytes - out.size());
                }
                out.insert(out.end(), data.data() + off, data.data() + off + to_copy);
                if (out.size() >= max_bytes) break;
                cur = fat[cur];
            }
            return out;
        };

        std::vector<uint8_t> dir_stream = read_chain(first_dir_sector, config.max_file_size);
        if (dir_stream.size() < 128) return false;

        std::vector<uint32_t> minifat;
        if (first_minifat_sector < 0xFFFFFFFC && num_minifat_sectors > 0) {
            std::vector<uint8_t> mf_bytes = read_chain(first_minifat_sector, num_minifat_sectors * sector_size);
            for (size_t i = 0; i + 4 <= mf_bytes.size(); i += 4) {
                minifat.push_back(read_u32_le(mf_bytes.data() + i));
            }
        }

        uint32_t root_start = read_u32_le(dir_stream.data() + 116);
        uint64_t root_size = (sector_shift == 9)
                                 ? static_cast<uint64_t>(read_u32_le(dir_stream.data() + 120))
                                 : read_u64_le(dir_stream.data() + 120);
        std::vector<uint8_t> mini_stream;
        if (root_start < 0xFFFFFFFC && root_size > 0) {
            mini_stream = read_chain(root_start, std::min<uint64_t>(root_size, config.max_file_size));
        }

        auto read_mini_chain = [&](uint32_t start_msec, uint64_t size) -> std::vector<uint8_t> {
            std::vector<uint8_t> out;
            uint32_t cur = start_msec;
            std::set<uint32_t> visited;
            while (cur < 0xFFFFFFFC && out.size() < size) {
                if (!visited.insert(cur).second) break;
                size_t off = static_cast<size_t>(cur) * mini_sector_size;
                if (off >= mini_stream.size()) break;
                size_t avail = std::min<size_t>(mini_sector_size, mini_stream.size() - off);
                size_t need = static_cast<size_t>(size - out.size());
                size_t to_copy = std::min(avail, need);
                out.insert(out.end(), mini_stream.data() + off, mini_stream.data() + off + to_copy);
                if (cur < minifat.size()) cur = minifat[cur];
                else cur++;
            }
            return out;
        };

        auto read_node_bytes = [&](const CfbDirNode& n) -> std::vector<uint8_t> {
            if (n.stream_size == 0 || n.stream_size > config.max_file_size) return {};
            if (n.stream_size < mini_stream_cutoff && !mini_stream.empty()) {
                return read_mini_chain(n.start_sec, n.stream_size);
            }
            return read_chain(n.start_sec, n.stream_size);
        };

        // Traverse Directory RB-Tree
        size_t num_entries = dir_stream.size() / 128;
        std::vector<CfbDirNode> stream_nodes;
        std::set<uint32_t> visited_dir;

        struct StackFrame {
            uint32_t sid;
            std::string parent_path;
        };
        uint32_t root_child = read_u32_le(dir_stream.data() + 76);
        std::vector<StackFrame> stack;
        if (root_child != 0xFFFFFFFF && root_child < num_entries) {
            stack.push_back({root_child, ""});
        }

        while (!stack.empty()) {
            StackFrame cur = stack.back();
            stack.pop_back();
            if (cur.sid >= num_entries || !visited_dir.insert(cur.sid).second) continue;

            const uint8_t* ent = dir_stream.data() + cur.sid * 128;
            uint16_t name_len = read_u16_le(ent + 64);
            uint8_t obj_type = ent[66];
            uint32_t left_sid = read_u32_le(ent + 68);
            uint32_t right_sid = read_u32_le(ent + 72);
            uint32_t child_sid = read_u32_le(ent + 76);

            if (right_sid != 0xFFFFFFFF && right_sid < num_entries) stack.push_back({right_sid, cur.parent_path});
            if (left_sid != 0xFFFFFFFF && left_sid < num_entries) stack.push_back({left_sid, cur.parent_path});

            if (name_len < 2 || name_len > 64) continue;
            std::string entry_name = utils::utf16le_to_utf8(ent, name_len - 2);
            if (entry_name.empty()) entry_name = "entry_" + std::to_string(cur.sid);
            std::string full_rel = cur.parent_path.empty() ? entry_name : (cur.parent_path + "/" + entry_name);

            if (obj_type == 1 && child_sid != 0xFFFFFFFF && child_sid < num_entries) {
                stack.push_back({child_sid, full_rel});
            } else if (obj_type == 2) {
                uint32_t start_sec = read_u32_le(ent + 116);
                uint64_t stream_size = (sector_shift == 9)
                                           ? static_cast<uint64_t>(read_u32_le(ent + 120))
                                           : read_u64_le(ent + 120);
                std::vector<uint8_t> raw_u16(ent, ent + (name_len - 2));
                stream_nodes.push_back({cur.sid, cur.parent_path, full_rel, entry_name, raw_u16, obj_type, start_sec, stream_size});
            }
        }

        // Check if any Sub-Storages represent embedded Office documents (e.g. ObjectPool/_123456 containing Workbook / WordDocument / PowerPoint Document)
        std::map<std::string, std::vector<CfbDirNode>> substorages;
        for (const auto& node : stream_nodes) {
            if (!node.parent_path.empty()) {
                substorages[node.parent_path].push_back(node);
            }
        }

        // Extract WordDocument and Table streams if present for object-icon correlation
        std::vector<uint8_t> word_doc_bytes;
        std::vector<uint8_t> table_bytes;
        for (const auto& node : stream_nodes) {
            std::string ln = utils::to_lower(node.base_name);
            if (ln == "worddocument") {
                word_doc_bytes = read_node_bytes(node);
            }
        }
        if (!word_doc_bytes.empty()) {
            bool use_1table = (word_doc_bytes.size() > 0x000B) && ((word_doc_bytes[0x000A] & 0x02) != 0);
            std::string target_tbl = use_1table ? "1table" : "0table";
            for (const auto& node : stream_nodes) {
                if (utils::to_lower(node.base_name) == target_tbl) {
                    table_bytes = read_node_bytes(node);
                    break;
                }
            }
        }
        std::map<std::string, uint32_t> obj_to_icon_fc = parse_word_doc_icon_links(word_doc_bytes, table_bytes);

        struct ItemMeta {
            size_t item_index;
            std::string origin_parent;
            std::string sub_name;
            bool is_embedded = false;
        };
        std::vector<ItemMeta> item_metas;

        std::set<std::string> repackaged_parents;
        for (const auto& kv : substorages) {
            const std::string& parent = kv.first;
            const auto& children = kv.second;
            std::string doc_ext;
            std::string prog_id;
            for (const auto& ch : children) {
                std::string ln = utils::to_lower(ch.base_name);
                if (ln == "workbook" || ln == "book") doc_ext = ".xls";
                else if (ln == "worddocument") doc_ext = ".doc";
                else if (ln == "powerpoint document") doc_ext = ".ppt";
                else if (ln == "compobj") {
                    prog_id = parse_compobj_progid(read_node_bytes(ch));
                }
            }
            if (!doc_ext.empty()) {
                std::vector<std::pair<CfbDirNode, std::vector<uint8_t>>> child_streams;
                for (const auto& ch : children) {
                    child_streams.push_back({ch, read_node_bytes(ch)});
                }
                std::vector<uint8_t> rebuilt_cfb = repackage_substorage_to_cfb(child_streams);
                if (!rebuilt_cfb.empty()) {
                    std::string safe_parent = utils::sanitize_relpath(parent);
                    for (char& c : safe_parent) if (c == '/') c = '_';
                    std::string fname = safe_parent + doc_ext;
                    std::string out_path = utils::join_path(output_dir, fname);
                    if (utils::write_file(out_path, rebuilt_cfb.data(), rebuilt_cfb.size())) {
                        ExtractedItem item;
                        item.name = fname;
                        item.saved_path = out_path;
                        item.size = rebuilt_cfb.size();
                        item.extractor_name = "Ole2Extractor(SubStorageRebuilder)";
                        ItemMeta meta;
                        meta.item_index = out_items.size();
                        meta.origin_parent = parent;
                        size_t slash = parent.find_last_of("/\\");
                        meta.sub_name = (slash != std::string::npos) ? parent.substr(slash + 1) : parent;
                        meta.is_embedded = true;
                        item_metas.push_back(meta);
                        out_items.push_back(item);
                        repackaged_parents.insert(parent);
                    }
                }
            }
        }

        for (const auto& node : stream_nodes) {
            if (!node.parent_path.empty() && repackaged_parents.count(node.parent_path) > 0) {
                continue; // Already repackaged as a standalone .xls/.doc/.ppt
            }
            std::string entry_name = node.full_path;
            std::string lower_name = utils::to_lower(node.base_name);
            if (lower_name == "compobj" || lower_name == "ole" ||
                lower_name == "summaryinformation" || lower_name == "documentsummaryinformation" ||
                lower_name == "1table" || lower_name == "0table" ||
                lower_name == "objinfo" || lower_name == "\x03objinfo") {
                continue;
            }

            std::vector<uint8_t> content = read_node_bytes(node);
            if (content.empty()) continue;

            if (lower_name == "data" || lower_name == "pictures" ||
                lower_name == "worddocument" || lower_name == "powerpoint document" ||
                lower_name == "workbook" || lower_name == "book") {
                int blip_cnt = extract_officeart_blips(node.base_name, content, output_dir, config.max_file_size, out_items);
                if (blip_cnt > 0 || lower_name == "worddocument" || lower_name == "workbook" || lower_name == "book" || lower_name == "powerpoint document") {
                    continue;
                }
            }

            std::string unwrapped_name;
            std::vector<uint8_t> unwrapped_data;
            if (lower_name.find("ole10native") != std::string::npos &&
                try_unwrap_ole10native(content, unwrapped_name, unwrapped_data)) {
                entry_name = unwrapped_name;
                content.swap(unwrapped_data);
            }

            std::string safe_name = utils::sanitize_relpath(entry_name);
            std::string out_path = utils::join_path(output_dir, safe_name);
            if (utils::file_exists(out_path)) {
                out_path = utils::join_path(output_dir, std::to_string(node.id) + "_" + safe_name);
            }
            if (utils::write_file(out_path, content.data(), content.size())) {
                ExtractedItem item;
                item.name = safe_name;
                item.saved_path = out_path;
                item.size = content.size();
                item.extractor_name = name();
                ItemMeta meta;
                meta.item_index = out_items.size();
                meta.origin_parent = node.parent_path;
                size_t slash = node.parent_path.find_last_of("/\\");
                meta.sub_name = (slash != std::string::npos) ? node.parent_path.substr(slash + 1) : node.parent_path;
                if (lower_name.find("ole10native") != std::string::npos || !node.parent_path.empty()) {
                    meta.is_embedded = true;
                }
                item_metas.push_back(meta);
                out_items.push_back(item);
            }
        }

        // Link associated presentation icons for files:
        // Case 1: Exact WordDocument FIB/FKP matching via sprmCPicLocation (fcPic)
        if (!obj_to_icon_fc.empty()) {
            for (const auto& meta : item_metas) {
                if (!meta.is_embedded) continue;
                auto it_fc = obj_to_icon_fc.find(meta.sub_name);
                if (it_fc != obj_to_icon_fc.end()) {
                    uint32_t target_fc = it_fc->second;
                    int best_idx = -1;
                    uint64_t min_dist = UINT64_MAX;
                    for (size_t i = 0; i < out_items.size(); ++i) {
                        const auto& item = out_items[i];
                        std::string ext = utils::get_extension(item.saved_path);
                        if (ext == ".png" || ext == ".jpg" || ext == ".bmp" || ext == ".emf" || ext == ".wmf") {
                            if (item.offset >= target_fc && (item.offset - target_fc) < min_dist) {
                                min_dist = item.offset - target_fc;
                                best_idx = static_cast<int>(i);
                            }
                        }
                    }
                    if (best_idx >= 0 && min_dist < 20000) {
                        out_items[meta.item_index].associated_icon_path = out_items[best_idx].saved_path;
                    }
                }
            }
        }

        // Case 2: Fallback correlation for unlinked embedded objects (e.g. legacy Word or generic OLE2)
        std::vector<size_t> unlinked_obj_indices;
        for (const auto& meta : item_metas) {
            if (meta.is_embedded && out_items[meta.item_index].associated_icon_path.empty()) {
                unlinked_obj_indices.push_back(meta.item_index);
            }
        }
        if (!unlinked_obj_indices.empty()) {
            std::vector<std::string> icon_candidates;
            for (const auto& it : out_items) {
                std::string ext = utils::get_extension(it.saved_path);
                if (ext == ".emf" || ext == ".wmf" || ext == ".png" || ext == ".jpg" || ext == ".bmp") {
                    if (it.name.find("Pres") != std::string::npos || it.name.find("blip") != std::string::npos || it.name.find("Data_image_") != std::string::npos) {
                        icon_candidates.push_back(it.saved_path);
                    }
                }
            }
            if (!icon_candidates.empty()) {
                if (unlinked_obj_indices.size() == 1) {
                    out_items[unlinked_obj_indices[0]].associated_icon_path = icon_candidates[0];
                } else {
                    for (size_t i = 0; i < unlinked_obj_indices.size() && i < icon_candidates.size(); ++i) {
                        out_items[unlinked_obj_indices[i]].associated_icon_path = icon_candidates[i];
                    }
                }
            }
        }

        return !out_items.empty();
    }
};

} // namespace

std::unique_ptr<IExtractor> create_ole2_extractor() {
    return std::unique_ptr<IExtractor>(new Ole2Extractor());
}

} // namespace unnest
