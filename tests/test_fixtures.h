#ifndef FILEUNNEST_TEST_FIXTURES_H
#define FILEUNNEST_TEST_FIXTURES_H

#include "fileunnest/utils.h"
#include <cstdint>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>
#include <zlib.h>

namespace unnest {
namespace test_fixtures {

inline void write_u16_le(std::vector<uint8_t>& buf, size_t off, uint16_t v) {
    buf[off] = static_cast<uint8_t>(v & 0xFF);
    buf[off + 1] = static_cast<uint8_t>((v >> 8) & 0xFF);
}

inline void write_u32_le(std::vector<uint8_t>& buf, size_t off, uint32_t v) {
    buf[off] = static_cast<uint8_t>(v & 0xFF);
    buf[off + 1] = static_cast<uint8_t>((v >> 8) & 0xFF);
    buf[off + 2] = static_cast<uint8_t>((v >> 16) & 0xFF);
    buf[off + 3] = static_cast<uint8_t>((v >> 24) & 0xFF);
}

inline void append_u16_le(std::vector<uint8_t>& buf, uint16_t v) {
    size_t off = buf.size();
    buf.resize(off + 2);
    write_u16_le(buf, off, v);
}

inline void append_u32_le(std::vector<uint8_t>& buf, uint32_t v) {
    size_t off = buf.size();
    buf.resize(off + 4);
    write_u32_le(buf, off, v);
}

inline void append_u64_le(std::vector<uint8_t>& buf, uint64_t v) {
    append_u32_le(buf, static_cast<uint32_t>(v & 0xFFFFFFFFULL));
    append_u32_le(buf, static_cast<uint32_t>(v >> 32));
}

inline void append_u32_be(std::vector<uint8_t>& buf, uint32_t v) {
    buf.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
    buf.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
    buf.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
    buf.push_back(static_cast<uint8_t>(v & 0xFF));
}

inline void append_u64_be(std::vector<uint8_t>& buf, uint64_t v) {
    append_u32_be(buf, static_cast<uint32_t>(v >> 32));
    append_u32_be(buf, static_cast<uint32_t>(v & 0xFFFFFFFFULL));
}

inline std::vector<uint8_t> zlib_compress(const std::vector<uint8_t>& in) {
    uLongf bound = compressBound(static_cast<uLong>(in.size()));
    std::vector<uint8_t> out(bound);
    if (compress(out.data(), &bound, in.data(), static_cast<uLong>(in.size())) == Z_OK) {
        out.resize(bound);
    } else {
        out.clear();
    }
    return out;
}

// 1. Build MS-CFB (OLE2) with Ole10Native embedded payload
inline std::vector<uint8_t> build_ole2_with_ole10(const std::string& embedded_filename, const std::vector<uint8_t>& payload) {
    std::vector<uint8_t> ole10;
    append_u32_le(ole10, 0);
    ole10.push_back(0x02); ole10.push_back(0x00); // flags = 2
    std::string label = "OLE_Embedded_Package";
    ole10.insert(ole10.end(), label.begin(), label.end());
    ole10.push_back(0);
    ole10.insert(ole10.end(), embedded_filename.begin(), embedded_filename.end());
    ole10.push_back(0);
    for (int i = 0; i < 8; ++i) ole10.push_back(0);
    append_u32_le(ole10, static_cast<uint32_t>(payload.size()));
    ole10.insert(ole10.end(), payload.begin(), payload.end());
    write_u32_le(ole10, 0, static_cast<uint32_t>(ole10.size() - 4));

    size_t num_stream_sectors = (ole10.size() + 511) / 512;
    if (num_stream_sectors == 0) num_stream_sectors = 1;

    size_t total_sectors = 2 + num_stream_sectors;
    std::vector<uint8_t> cfb((1 + total_sectors) * 512, 0);

    const uint8_t sig[8] = {0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1};
    std::memcpy(cfb.data(), sig, 8);
    write_u16_le(cfb, 24, 0x003E);
    write_u16_le(cfb, 26, 0x0003);
    write_u16_le(cfb, 28, 0xFFFE);
    write_u16_le(cfb, 30, 9);
    write_u16_le(cfb, 32, 6);
    write_u32_le(cfb, 44, 1);
    write_u32_le(cfb, 48, 1);
    write_u32_le(cfb, 56, 0); // force regular FAT
    write_u32_le(cfb, 60, 0xFFFFFFFE);
    write_u32_le(cfb, 68, 0xFFFFFFFE);
    write_u32_le(cfb, 76, 0);
    for (int i = 1; i < 109; ++i) write_u32_le(cfb, 76 + i * 4, 0xFFFFFFFF);

    size_t fat_off = 512;
    for (int i = 0; i < 128; ++i) write_u32_le(cfb, fat_off + i * 4, 0xFFFFFFFF);
    write_u32_le(cfb, fat_off + 0 * 4, 0xFFFFFFFD);
    write_u32_le(cfb, fat_off + 1 * 4, 0xFFFFFFFE);
    for (size_t s = 0; s < num_stream_sectors; ++s) {
        uint32_t sec_id = static_cast<uint32_t>(2 + s);
        uint32_t next_id = (s + 1 < num_stream_sectors) ? (sec_id + 1) : 0xFFFFFFFE;
        write_u32_le(cfb, fat_off + sec_id * 4, next_id);
    }

    //Entry 0: Root Entry
    size_t dir_off = 1024;
    const char* root_name = "Root Entry";
    for (size_t i = 0; root_name[i]; ++i) write_u16_le(cfb, dir_off + i * 2, root_name[i]);
    write_u16_le(cfb, dir_off + 64, static_cast<uint16_t>((std::strlen(root_name) + 1) * 2));
    cfb[dir_off + 66] = 5;
    write_u32_le(cfb, dir_off + 68, 0xFFFFFFFF);
    write_u32_le(cfb, dir_off + 72, 0xFFFFFFFF);
    write_u32_le(cfb, dir_off + 76, 1);
    write_u32_le(cfb, dir_off + 116, 0xFFFFFFFE);

    size_t ent1_off = dir_off + 128;
    const char* sname = "\x01Ole10Native";
    for (size_t i = 0; sname[i]; ++i) write_u16_le(cfb, ent1_off + i * 2, static_cast<uint8_t>(sname[i]));
    write_u16_le(cfb, ent1_off + 64, static_cast<uint16_t>((std::strlen(sname) + 1) * 2));
    cfb[ent1_off + 66] = 2;
    write_u32_le(cfb, ent1_off + 68, 0xFFFFFFFF);
    write_u32_le(cfb, ent1_off + 72, 0xFFFFFFFF);
    write_u32_le(cfb, ent1_off + 76, 0xFFFFFFFF);
    write_u32_le(cfb, ent1_off + 116, 2);
    write_u32_le(cfb, ent1_off + 120, static_cast<uint32_t>(ole10.size()));

    std::memcpy(cfb.data() + 1536, ole10.data(), ole10.size());
    return cfb;
}

// 2. Build MS-CFB (OLE2) using MiniFAT & MiniStream (< 4096B cutoff)
inline std::vector<uint8_t> build_ole2_ministream(const std::string& stream_name, const std::vector<uint8_t>& small_payload) {
    // Sector 0: FAT
    // Sector 1: Directory
    // Sector 2: MiniFAT
    // Sector 3: Root MiniStream container
    std::vector<uint8_t> cfb(5 * 512, 0);
    const uint8_t sig[8] = {0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1};
    std::memcpy(cfb.data(), sig, 8);
    write_u16_le(cfb, 24, 0x003E);
    write_u16_le(cfb, 26, 0x0003);
    write_u16_le(cfb, 28, 0xFFFE);
    write_u16_le(cfb, 30, 9);  // 512B sector
    write_u16_le(cfb, 32, 6);  // 64B mini sector
    write_u32_le(cfb, 44, 1);  // 1 FAT sector
    write_u32_le(cfb, 48, 1);  // Dir at sector 1
    write_u32_le(cfb, 56, 4096); // MiniStream cutoff = 4096
    write_u32_le(cfb, 60, 2);  // MiniFAT at sector 2
    write_u32_le(cfb, 64, 1);  // 1 MiniFAT sector
    write_u32_le(cfb, 68, 0xFFFFFFFE);
    write_u32_le(cfb, 76, 0);
    for (int i = 1; i < 109; ++i) write_u32_le(cfb, 76 + i * 4, 0xFFFFFFFF);

    // Sector 0: FAT
    size_t fat_off = 512;
    for (int i = 0; i < 128; ++i) write_u32_le(cfb, fat_off + i * 4, 0xFFFFFFFF);
    write_u32_le(cfb, fat_off + 0 * 4, 0xFFFFFFFD);
    write_u32_le(cfb, fat_off + 1 * 4, 0xFFFFFFFE);
    write_u32_le(cfb, fat_off + 2 * 4, 0xFFFFFFFE);
    write_u32_le(cfb, fat_off + 3 * 4, 0xFFFFFFFE);

    // Sector 2: MiniFAT (chain mini-sectors 0..N)
    size_t mfat_off = 512 * 3;
    for (int i = 0; i < 128; ++i) write_u32_le(cfb, mfat_off + i * 4, 0xFFFFFFFF);
    size_t num_msec = (small_payload.size() + 63) / 64;
    if (num_msec == 0) num_msec = 1;
    for (size_t m = 0; m < num_msec; ++m) {
        write_u32_le(cfb, mfat_off + m * 4, (m + 1 < num_msec) ? static_cast<uint32_t>(m + 1) : 0xFFFFFFFE);
    }

    // Sector 1: Directory
    size_t dir_off = 512 * 2;
    const char* root_name = "Root Entry";
    for (size_t i = 0; root_name[i]; ++i) write_u16_le(cfb, dir_off + i * 2, root_name[i]);
    write_u16_le(cfb, dir_off + 64, static_cast<uint16_t>((std::strlen(root_name) + 1) * 2));
    cfb[dir_off + 66] = 5;
    write_u32_le(cfb, dir_off + 68, 0xFFFFFFFF);
    write_u32_le(cfb, dir_off + 72, 0xFFFFFFFF);
    write_u32_le(cfb, dir_off + 76, 1);
    write_u32_le(cfb, dir_off + 116, 3); // Root MiniStream starts at Sector 3
    write_u32_le(cfb, dir_off + 120, 512);

    size_t ent1_off = dir_off + 128;
    for (size_t i = 0; i < stream_name.size(); ++i) write_u16_le(cfb, ent1_off + i * 2, static_cast<uint8_t>(stream_name[i]));
    write_u16_le(cfb, ent1_off + 64, static_cast<uint16_t>((stream_name.size() + 1) * 2));
    cfb[ent1_off + 66] = 2;
    write_u32_le(cfb, ent1_off + 68, 0xFFFFFFFF);
    write_u32_le(cfb, ent1_off + 72, 0xFFFFFFFF);
    write_u32_le(cfb, ent1_off + 76, 0xFFFFFFFF);
    write_u32_le(cfb, ent1_off + 116, 0); // starts at MiniSector 0
    write_u32_le(cfb, ent1_off + 120, static_cast<uint32_t>(small_payload.size()));

    // Sector 3: Root MiniStream content
    std::memcpy(cfb.data() + 512 * 4, small_payload.data(), small_payload.size());
    return cfb;
}

// 3. Build Electron .asar
inline std::vector<uint8_t> build_asar(const std::string& filename, const std::vector<uint8_t>& content) {
    std::string json = "{\"files\":{\"" + filename + "\":{\"size\":" + std::to_string(content.size()) + ",\"offset\":\"0\"}}}";
    uint32_t str_len = static_cast<uint32_t>(json.size());
    uint32_t aligned_str = (str_len + 3) & ~3u;
    uint32_t pickle_payload_len = 4 + aligned_str;
    uint32_t header_size = 4 + pickle_payload_len;

    std::vector<uint8_t> asar;
    append_u32_le(asar, 4);
    append_u32_le(asar, header_size);
    append_u32_le(asar, pickle_payload_len);
    append_u32_le(asar, str_len);
    asar.insert(asar.end(), json.begin(), json.end());
    while ((asar.size() - 16) < aligned_str) asar.push_back(0);
    asar.insert(asar.end(), content.begin(), content.end());
    return asar;
}

// 4. Build Photoshop PSD with Smart Object (supports UTF-8 -> UTF-16BE filename encoding)
inline std::vector<uint8_t> build_psd(const std::string& so_name, const std::vector<uint8_t>& so_data) {
    std::vector<uint8_t> psd(26, 0);
    std::memcpy(psd.data(), "8BPS\x00\x01", 6);

    // Convert UTF-8 so_name to UTF-16BE code units
    std::vector<uint16_t> u16;
    for (size_t i = 0; i < so_name.size(); ) {
        unsigned char c = static_cast<unsigned char>(so_name[i]);
        if (c < 0x80) {
            u16.push_back(c);
            i += 1;
        } else if ((c & 0xE0) == 0xC0 && i + 1 < so_name.size()) {
            uint16_t cp = ((c & 0x1F) << 6) | (static_cast<unsigned char>(so_name[i + 1]) & 0x3F);
            u16.push_back(cp);
            i += 2;
        } else if ((c & 0xF0) == 0xE0 && i + 2 < so_name.size()) {
            uint16_t cp = ((c & 0x0F) << 12) |
                          ((static_cast<unsigned char>(so_name[i + 1]) & 0x3F) << 6) |
                          (static_cast<unsigned char>(so_name[i + 2]) & 0x3F);
            u16.push_back(cp);
            i += 3;
        } else {
            i += 1;
        }
    }

    std::vector<uint8_t> lifd;
    lifd.insert(lifd.end(), {'l', 'i', 'F', 'D'});
    append_u32_be(lifd, 3);
    lifd.push_back(4);
    lifd.insert(lifd.end(), {'u', 'u', 'i', 'd'});
    append_u32_be(lifd, static_cast<uint32_t>(u16.size()));
    for (uint16_t ch : u16) {
        lifd.push_back(static_cast<uint8_t>((ch >> 8) & 0xFF));
        lifd.push_back(static_cast<uint8_t>(ch & 0xFF));
    }
    lifd.insert(lifd.end(), {'Z', 'I', 'P', ' '});
    lifd.insert(lifd.end(), {'8', 'B', 'I', 'M'});
    append_u64_be(lifd, so_data.size());
    lifd.push_back(0);
    lifd.insert(lifd.end(), so_data.begin(), so_data.end());

    psd.insert(psd.end(), {'8', 'B', 'I', 'M', 'l', 'n', 'k', '2'});
    append_u32_be(psd, static_cast<uint32_t>(lifd.size()));
    psd.insert(psd.end(), lifd.begin(), lifd.end());
    return psd;
}

// 5. Build PDF with FlateDecode compressed EmbeddedFile stream
inline std::vector<uint8_t> build_pdf_with_flate_attachment(const std::string& att_name, const std::vector<uint8_t>& raw_payload) {
    std::vector<uint8_t> compressed = zlib_compress(raw_payload);
    std::string pdf_str = "%PDF-1.7\n1 0 obj\n<< /Type /Filespec /F (" + att_name + ") >>\nendobj\n"
                          "2 0 obj\n<< /Type /EmbeddedFile /Filter /FlateDecode /Length " +
                          std::to_string(compressed.size()) + " >>\nstream\n";
    std::vector<uint8_t> pdf_bytes(pdf_str.begin(), pdf_str.end());
    pdf_bytes.insert(pdf_bytes.end(), compressed.begin(), compressed.end());
    std::string pdf_tail = "\nendstream\nendobj\n%%EOF\n";
    pdf_bytes.insert(pdf_bytes.end(), pdf_tail.begin(), pdf_tail.end());
    return pdf_bytes;
}

// 5b. Build RTF document with {\pict\pngblip ...} and {\*\objdata ...} OLE 1.0 Package containing a Chinese-named ZIP
inline std::vector<uint8_t> build_rtf_with_pict_and_ole1(const std::vector<uint8_t>& png_bytes,
                                                         const std::string& pkg_filename_utf8,
                                                         const std::vector<uint8_t>& zip_bytes) {
    auto to_hex = [](const std::vector<uint8_t>& b) -> std::string {
        static const char* h = "0123456789abcdef";
        std::string s;
        s.reserve(b.size() * 2);
        for (uint8_t v : b) {
            s.push_back(h[v >> 4]);
            s.push_back(h[v & 0x0F]);
        }
        return s;
    };

    // Build OLE10Native payload for "Package"
    std::vector<uint8_t> ole10;
    append_u32_le(ole10, 0);
    append_u16_le(ole10, 2); // flags = 2
    std::string label = "RTF_Attachment";
    ole10.insert(ole10.end(), label.begin(), label.end());
    ole10.push_back(0);
    ole10.insert(ole10.end(), pkg_filename_utf8.begin(), pkg_filename_utf8.end());
    ole10.push_back(0);
    append_u32_le(ole10, 0); // flags2 + unknown
    append_u32_le(ole10, 0); // temp path len = 0
    append_u32_le(ole10, static_cast<uint32_t>(zip_bytes.size()));
    ole10.insert(ole10.end(), zip_bytes.begin(), zip_bytes.end());
    write_u32_le(ole10, 0, static_cast<uint32_t>(ole10.size() - 4));

    // Wrap inside OLE 1.0 Object Header
    std::vector<uint8_t> ole1;
    append_u32_le(ole1, 0x00000501); // OLEVersion 1.0
    append_u32_le(ole1, 2);          // FormatID = 2 (Embedded)
    std::string cls = "Package";
    append_u32_le(ole1, static_cast<uint32_t>(cls.size() + 1));
    ole1.insert(ole1.end(), cls.begin(), cls.end());
    ole1.push_back(0);
    append_u32_le(ole1, 0); // TopicNameLen = 0
    append_u32_le(ole1, 0); // ItemNameLen = 0
    append_u32_le(ole1, static_cast<uint32_t>(ole10.size()));
    ole1.insert(ole1.end(), ole10.begin(), ole10.end());

    std::string rtf = "{\\rtf1\\ansi\\deff0\n"
                      "{\\p Rich Text Document with Embedded PNG and OLE1.0 Package}\n"
                      "{\\pict\\pngblip\\picw80\\pich60 " + to_hex(png_bytes) + "}\n"
                      "{\\object\\objemb{\\*\\objclass Package}{\\*\\objdata " + to_hex(ole1) + "}}\n"
                      "}\n";
    return std::vector<uint8_t>(rtf.begin(), rtf.end());
}

// 5c. Build MS-ONESTORE (.one) file containing multiple FileDataStoreObject entries (PNG + ZIP)
inline std::vector<uint8_t> build_onenote_with_objects(const std::vector<std::vector<uint8_t>>& payloads) {
    // MS-ONESTORE Header GUID: {7B5C52E4-D88C-4DA7-AEB1-5378D02996D3}
    static const uint8_t hdr_guid[16] = {
        0xE4, 0x52, 0x5C, 0x7B, 0x8C, 0xD8, 0xA7, 0x4D,
        0xAE, 0xB1, 0x53, 0x78, 0xD0, 0x29, 0x96, 0xD3
    };
    // FileDataStoreObject Header GUID: {BDE316E7-2665-4511-A4C4-8D4D0B7A9EAC}
    static const uint8_t fds_hdr[16] = {
        0xE7, 0x16, 0xE3, 0xBD, 0x65, 0x26, 0x11, 0x45,
        0xA4, 0xC4, 0x8D, 0x4D, 0x0B, 0x7A, 0x9E, 0xAC
    };
    // FileDataStoreObject Footer GUID: {71FBA722-0F79-4A0B-BB13-899256426B24}
    static const uint8_t fds_ftr[16] = {
        0x22, 0xA7, 0xFB, 0x71, 0x79, 0x0F, 0x0B, 0x4A,
        0xBB, 0x13, 0x89, 0x92, 0x56, 0x42, 0x6B, 0x24
    };

    std::vector<uint8_t> one(1024, 0); // 1024-byte MS-ONESTORE file header
    std::memcpy(one.data(), hdr_guid, 16);

    for (const auto& p : payloads) {
        one.insert(one.end(), fds_hdr, fds_hdr + 16);
        append_u64_le(one, p.size()); // cbLength
        append_u32_le(one, 0);        // unused
        append_u64_le(one, 0);        // reserved
        one.insert(one.end(), p.begin(), p.end());
        while (one.size() % 8 != 0) one.push_back(0); // 8-byte alignment
        one.insert(one.end(), fds_ftr, fds_ftr + 16);
    }
    return one;
}

// 5d. Build Photoshop Large Document Format (.psb, version=2, 64-bit lnk2 length) with Chinese Smart Object
inline std::vector<uint8_t> build_psb_v2(const std::string& so_name, const std::vector<uint8_t>& so_data) {
    std::vector<uint8_t> psb(26, 0);
    std::memcpy(psb.data(), "8BPS\x00\x02", 6); // Version 2 = PSB

    std::vector<uint16_t> u16;
    for (size_t i = 0; i < so_name.size(); ) {
        unsigned char c = static_cast<unsigned char>(so_name[i]);
        if (c < 0x80) { u16.push_back(c); i += 1; }
        else if ((c & 0xE0) == 0xC0 && i + 1 < so_name.size()) {
            u16.push_back(((c & 0x1F) << 6) | (static_cast<unsigned char>(so_name[i + 1]) & 0x3F));
            i += 2;
        } else if ((c & 0xF0) == 0xE0 && i + 2 < so_name.size()) {
            u16.push_back(((c & 0x0F) << 12) |
                          ((static_cast<unsigned char>(so_name[i + 1]) & 0x3F) << 6) |
                          (static_cast<unsigned char>(so_name[i + 2]) & 0x3F));
            i += 3;
        } else i += 1;
    }

    std::vector<uint8_t> lifd;
    lifd.insert(lifd.end(), {'l', 'i', 'F', 'D'});
    append_u32_be(lifd, 3);
    lifd.push_back(4);
    lifd.insert(lifd.end(), {'u', 'u', 'i', 'd'});
    append_u32_be(lifd, static_cast<uint32_t>(u16.size()));
    for (uint16_t ch : u16) {
        lifd.push_back(static_cast<uint8_t>((ch >> 8) & 0xFF));
        lifd.push_back(static_cast<uint8_t>(ch & 0xFF));
    }
    lifd.insert(lifd.end(), {'Z', 'I', 'P', ' '});
    lifd.insert(lifd.end(), {'8', 'B', 'I', 'M'});
    append_u64_be(lifd, so_data.size());
    lifd.push_back(0);
    lifd.insert(lifd.end(), so_data.begin(), so_data.end());

    // In PSB v2, Additional Layer Info block "lnk2" uses 8-byte (64-bit) length
    psb.insert(psb.end(), {'8', 'B', '6', '4', 'l', 'n', 'k', '2'});
    append_u64_be(psb, lifd.size());
    psb.insert(psb.end(), lifd.begin(), lifd.end());
    return psb;
}

// 5e. Build Adobe InDesign (.indd) with Master Page GUID + XMP Thumbnail + Contiguous Embedded PNG & ZIP
inline std::vector<uint8_t> build_indd_with_embeds(const std::vector<uint8_t>& png_bytes, const std::vector<uint8_t>& zip_bytes) {
    static const uint8_t indd_guid[16] = {
        0x06, 0x06, 0xED, 0xF5, 0xD8, 0x1D, 0x46, 0xE5,
        0xBD, 0x31, 0xEF, 0xE7, 0xFE, 0x74, 0xB7, 0x1D
    };
    std::vector<uint8_t> indd(256, 0);
    std::memcpy(indd.data(), indd_guid, 16);

    std::string xmp = "<x:xmpmeta xmlns:x=\"adobe:ns:meta/\"><rdf:RDF>"
                      "<xmpGImg:image>iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=</xmpGImg:image>"
                      "</rdf:RDF></x:xmpmeta>";
    indd.insert(indd.end(), xmp.begin(), xmp.end());
    indd.resize(indd.size() + 32, 0);
    indd.insert(indd.end(), png_bytes.begin(), png_bytes.end());
    indd.resize(indd.size() + 32, 0);
    indd.insert(indd.end(), zip_bytes.begin(), zip_bytes.end());
    return indd;
}

// 5f. Build PyInstaller ELF binary with full CArchive TOC (compressed main.pyc + Chinese-named config + embedded ZIP)
inline std::vector<uint8_t> build_pyinstaller_elf(const std::vector<uint8_t>& zip_bytes) {
    std::vector<uint8_t> elf = {0x7F, 'E', 'L', 'F', 0x02, 0x01, 0x01, 0x00};
    elf.resize(64, 0x90);
    size_t pkg_start = elf.size();

    struct RawEntry {
        std::string name;
        char type_code;
        uint8_t comp_flag;
        std::vector<uint8_t> raw_data;
        std::vector<uint8_t> stored_data;
        uint32_t offset_in_pkg;
    };

    std::string pyc_str = "PyInstaller Compiled BytecodeStub - main.pyc";
    std::vector<uint8_t> pyc_raw(pyc_str.begin(), pyc_str.end());

    std::vector<RawEntry> items = {
        {"app_main", 's', 1, pyc_raw, zlib_compress(pyc_raw), 0},
        {"配置清单_内嵌包.zip", 'x', 1, zip_bytes, zlib_compress(zip_bytes), 0}
    };

    for (auto& it : items) {
        it.offset_in_pkg = static_cast<uint32_t>(elf.size() - pkg_start);
        elf.insert(elf.end(), it.stored_data.begin(), it.stored_data.end());
    }

    uint32_t toc_offset = static_cast<uint32_t>(elf.size() - pkg_start);
    for (const auto& it : items) {
        // Entry len = 18 + name.size() + 1 (aligned to 4 bytes)
        uint32_t raw_entry_len = static_cast<uint32_t>(18 + it.name.size() + 1);
        uint32_t entry_len = (raw_entry_len + 3) & ~3u;
        append_u32_be(elf, entry_len);
        append_u32_be(elf, it.offset_in_pkg);
        append_u32_be(elf, static_cast<uint32_t>(it.stored_data.size()));
        append_u32_be(elf, static_cast<uint32_t>(it.raw_data.size()));
        elf.push_back(it.comp_flag);
        elf.push_back(static_cast<uint8_t>(it.type_code));
        elf.insert(elf.end(), it.name.begin(), it.name.end());
        size_t pad = entry_len - (18 + it.name.size());
        for (size_t p = 0; p < pad; ++p) elf.push_back(0);
    }
    uint32_t toc_len = static_cast<uint32_t>((elf.size() - pkg_start) - toc_offset);

    // Append 24-byte PyInstaller 2.0 Cookie
    uint32_t pkg_len = static_cast<uint32_t>((elf.size() - pkg_start) + 24);
    const uint8_t magic[8] = {'M', 'E', 'I', 0x0C, 0x0B, 0x0A, 0x0B, 0x0E};
    elf.insert(elf.end(), magic, magic + 8);
    append_u32_be(elf, pkg_len);
    append_u32_be(elf, toc_offset);
    append_u32_be(elf, toc_len);
    append_u32_be(elf, 312);
    return elf;
}

// 6. Generate all persistent sample files into target_dir
inline bool generate_all_samples(const std::string& samples_dir) {
    utils::make_dirs(samples_dir);
    std::string tmp_dir = samples_dir + "/_tmp_build";
    utils::make_dirs(tmp_dir);

    // Base leaf payload
    std::string leaf_txt = tmp_dir + "/secret_payload.txt";
    std::string leaf_content = "FileUnnest Verification Payload - 2026";
    utils::write_file(leaf_txt, reinterpret_cast<const uint8_t*>(leaf_content.data()), leaf_content.size());

    // Inner ZIP
    std::string inner_zip = tmp_dir + "/inner_payload.zip";
    utils::run_external_cmd({"7z", "a", "-tzip", inner_zip, leaf_txt});
    std::vector<uint8_t> zip_bytes;
    utils::read_entire_file(inner_zip, zip_bytes);

    // Sample 01: PDF with FlateDecode compressed ZIP attachment
    std::vector<uint8_t> pdf_bytes = build_pdf_with_flate_attachment("invoice_bundle.zip", zip_bytes);
    utils::write_file(samples_dir + "/01_pdf_with_attachment.pdf", pdf_bytes.data(), pdf_bytes.size());

    // Sample 02 & 03: Real MS Office Word (.docx and Word 97-2003 .doc) generated via Pandoc & LibreOffice
    // Contains:
    //   - Body text & headings
    //   - Body inline image 1 (body_diagram.png, 80x60 RGB PNG)
    //   - Inserted figure image 2 (inserted_photo.png, 100x50 RGB PNG)
    //   - Inserted OLE Package image attachment (attached_image_object.png) & embedded archive (embedded_table.zip)
    std::string py_script = tmp_dir + "/gen_office_docs.py";
    std::string py_code = R"PY(
import sys, os, subprocess, zipfile, struct, zlib

tmp_dir, samples_dir, inner_zip = sys.argv[1], sys.argv[2], sys.argv[3]
zip_bytes = open(inner_zip, "rb").read()

def make_png(w, h, rgb):
    r, g, b = rgb
    raw = b"".join(b"\x00" + bytes([r, g, b]) * w for _ in range(h))
    def chunk(t, data):
        return struct.pack(">I", len(data)) + t + data + struct.pack(">I", zlib.crc32(t + data) & 0xffffffff)
    return (b"\x89PNG\r\n\x1a\n" +
            chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0)) +
            chunk(b"IDAT", zlib.compress(raw)) +
            chunk(b"IEND", b""))

img1_path = os.path.join(tmp_dir, "body_diagram.png")
img2_path = os.path.join(tmp_dir, "inserted_photo.png")
att_img_bytes = make_png(120, 90, (40, 180, 100))
with open(img1_path, "wb") as f: f.write(make_png(80, 60, (40, 120, 220)))
with open(img2_path, "wb") as f: f.write(make_png(100, 50, (220, 80, 40)))

md_path = os.path.join(tmp_dir, "office_doc.md")
with open(md_path, "w") as f:
    f.write("# 复合文档测试（正文图片 + 插入图片对象 + 附件）\n\n"
            "第一部分：正文内嵌示意图（Body Inline Image）：\n\n"
            "![BodyDiagram](" + img1_path + ")\n\n"
            "第二部分：正文中插入的图片对象（Inserted Image Object）：\n\n"
            "![InsertedPhoto](" + img2_path + ")\n")

base_docx = os.path.join(tmp_dir, "base.docx")
subprocess.run(["pandoc", md_path, "-o", base_docx], check=True)

# 1) Convert base_docx to real Word 97-2003 .doc via LibreOffice
env = os.environ.copy()
env["HOME"] = tmp_dir
env["XDG_RUNTIME_DIR"] = tmp_dir
subprocess.run([
    "libreoffice", "-env:UserInstallation=file://" + tmp_dir + "/lo_prof",
    "--headless", "--convert-to", "doc", base_docx, "--outdir", tmp_dir
], env=env, check=True)

doc_bytes = bytearray(open(os.path.join(tmp_dir, "base.doc"), "rb").read())

def build_ole10_stream(label_str, filename_str, payload):
    # Simulate Windows GBK ANSI filename + UTF-16LE wide filename trailer (standard MS Office Packager behavior)
    label = label_str.encode("gb18030") + b"\x00"
    fname_gbk = filename_str.encode("gb18030") + b"\x00"
    fname_u16 = filename_str.encode("utf-16le")
    wide_char_count = len(fname_u16) // 2
    # Trailer: [uint32_le wide_temp_len=0] [uint32_le wide_label_len] [wide_label_u16] [uint32_le wide_fn_len] [wide_fn_u16]
    wide_trailer = struct.pack("<I", 0) + struct.pack("<I", wide_char_count) + fname_u16
    body = struct.pack("<H", 2) + label + fname_gbk + b"\x00" * 8 + struct.pack("<I", len(payload)) + payload + wide_trailer
    if len(body) + 4 < 4096:
        body += b"\x00" * (4096 - 4 - len(body))
    return struct.pack("<I", len(body)) + body

# Add two OLE10Native streams into the Word 97-2003 .doc with Chinese filenames:
#   - "\x01Ole10Native" (插入的图片对象_附件.png - inserted Chinese-named image attachment/object)
#   - "\x02Ole10Native" (内嵌报表数据.zip - inserted Chinese-named zip package attachment)
ole10_img = build_ole10_stream("图片附件", "插入的图片对象_附件.png", att_img_bytes)
ole10_zip = build_ole10_stream("压缩包附件", "内嵌报表数据.zip", zip_bytes)

def append_sectors(buf, data):
    start_sec = (len(buf) // 512) - 1
    n_secs = (len(data) + 511) // 512
    buf.extend(data + b"\x00" * (n_secs * 512 - len(data)))
    for s in range(n_secs):
        sec_id = start_sec + s
        nxt = (sec_id + 1) if (s + 1 < n_secs) else 0xFFFFFFFE
        struct.pack_into("<I", buf, 512 + sec_id * 4, nxt)
    return start_sec, len(data)

sec_img, len_img = append_sectors(doc_bytes, ole10_img)
sec_zip, len_zip = append_sectors(doc_bytes, ole10_zip)

# Find last directory sector in FAT chain starting from first_dir_sec
first_dir_sec = struct.unpack_from("<I", doc_bytes, 48)[0]
last_dir_sec = first_dir_sec
while True:
    nxt = struct.unpack_from("<I", doc_bytes, 512 + last_dir_sec * 4)[0]
    if nxt >= 0xFFFFFFFC:
        break
    last_dir_sec = nxt

new_dir_sec = (len(doc_bytes) // 512) - 1
doc_bytes.extend(b"\x00" * 512)
struct.pack_into("<I", doc_bytes, 512 + last_dir_sec * 4, new_dir_sec)
struct.pack_into("<I", doc_bytes, 512 + new_dir_sec * 4, 0xFFFFFFFE)

# Link DirEntry 7 right-sibling -> DirEntry 8, and DirEntry 8 right-sibling -> DirEntry 9
last_dir_off = (last_dir_sec + 1) * 512
struct.pack_into("<I", doc_bytes, last_dir_off + 3 * 128 + 72, 8)

def write_dir_entry(buf, dir_sec, slot_idx, name_str, right_sid, start_s, sz):
    off = (dir_sec + 1) * 512 + slot_idx * 128
    sname = name_str.encode("utf-16le") + b"\x00\x00"
    buf[off : off + len(sname)] = sname
    struct.pack_into("<H", buf, off + 64, len(sname))
    buf[off + 66] = 2 # Stream
    buf[off + 67] = 1 # Black
    struct.pack_into("<III", buf, off + 68, 0xFFFFFFFF, right_sid, 0xFFFFFFFF)
    struct.pack_into("<II", buf, off + 116, start_s, sz)

write_dir_entry(doc_bytes, new_dir_sec, 0, "\x01Ole10Native", 9, sec_img, len_img)
write_dir_entry(doc_bytes, new_dir_sec, 1, "\x02Ole10Native", 0xFFFFFFFF, sec_zip, len_zip)
# Mark remaining 2 slots in new_dir_sec as unallocated (0xFFFFFFFF siblings)
for empty_slot in (2, 3):
    e_off = (new_dir_sec + 1) * 512 + empty_slot * 128
    struct.pack_into("<III", doc_bytes, e_off + 68, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF)

out_doc_path = os.path.join(samples_dir, "03_legacy_ole2.doc")
with open(out_doc_path, "wb") as f:
    f.write(doc_bytes)

# 2) Build valid 02_office_opc.docx from Pandoc base_docx + embedded OLE objects in word/embeddings/
out_docx_path = os.path.join(samples_dir, "02_office_opc.docx")
with zipfile.ZipFile(base_docx, "r") as zin, zipfile.ZipFile(out_docx_path, "w", zipfile.ZIP_DEFLATED) as zout:
    for item in zin.infolist():
        data = zin.read(item.filename)
        if item.filename == "[Content_Types].xml":
            data = data.replace(b"</Types>", b'<Default Extension="bin" ContentType="application/vnd.openxmlformats-officedocument.oleObject" /></Types>')
        elif item.filename == "word/_rels/document.xml.rels":
            rels_add = (b'<Relationship Id="rId98" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/oleObject" Target="embeddings/oleObject_img.bin" />'
                        b'<Relationship Id="rId99" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/oleObject" Target="embeddings/oleObject1.bin" /></Relationships>')
            data = data.replace(b"</Relationships>", rels_add)
        elif item.filename == "word/document.xml":
            ole_xml = (b'<w:p><w:r><w:t>Inserted OLE Objects (Image Attachment &amp; Archive Package):</w:t></w:r></w:p>'
                       b'<w:p><w:r><w:object><v:shape id="_x0000_i1025" style="width:90pt;height:68pt"><v:imagedata r:id="rId20"/></v:shape>'
                       b'<o:OLEObject Type="Embed" ProgID="Package" ShapeID="_x0000_i1025" DrawAspect="Content" ObjectID="_101" r:id="rId98"/></w:object></w:r></w:p>'
                       b'<w:p><w:r><w:object><v:shape id="_x0000_i1026" style="width:90pt;height:68pt"><v:imagedata r:id="rId23"/></v:shape>'
                       b'<o:OLEObject Type="Embed" ProgID="Package" ShapeID="_x0000_i1026" DrawAspect="Icon" ObjectID="_102" r:id="rId99"/></w:object></w:r></w:p></w:body>')
            data = data.replace(b"</w:body>", ole_xml)
        zout.writestr(item, data)

    # Also write the two OLE2 packages into word/embeddings/
    zout.writestr("word/embeddings/插入的图片对象_附件.png", att_img_bytes)
    zout.writestr("word/embeddings/oleObject1.bin", open( os.path.join(tmp_dir, "ole_zip.bin"), "rb").read())
)PY";
    std::vector<uint8_t> ole_in_docx = build_ole2_with_ole10("内嵌报表数据.zip", zip_bytes);
    utils::write_file(tmp_dir + "/ole_zip.bin", ole_in_docx.data(), ole_in_docx.size());
    utils::write_file(py_script, reinterpret_cast<const uint8_t*>(py_code.data()), py_code.size());
    utils::run_external_cmd({"python3", py_script, tmp_dir, samples_dir, inner_zip});

    // Sample 04: Nested Archive (7z -> tar.gz -> zip -> txt)
    std::string nested_tgz = tmp_dir + "/layer2.tar.gz";
    utils::run_external_cmd({"tar", "-czf", nested_tgz, "-C", tmp_dir, "inner_payload.zip"});
    utils::run_external_cmd({"7z", "a", samples_dir + "/04_nested_archive.7z", nested_tgz});

    // Sample 05: Photoshop PSD with embedded Chinese-named Smart Object ZIP
    std::vector<uint8_t> psd_bytes = build_psd("智能对象_设计图层.zip", zip_bytes);
    utils::write_file(samples_dir + "/05_photoshop_smartobj.psd", psd_bytes.data(), psd_bytes.size());

    // Sample 06: SVG with multiple Base64 Data URIs (PNG + embedded ZIP)
    std::string svg_str = "<svg xmlns=\"http://www.w3.org/2000/svg\">\n"
                          "  <image id=\"img1\" href=\"data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=\"/>\n"
                          "</svg>\n";
    utils::write_file(samples_dir + "/06_vector_base64.svg", reinterpret_cast<const uint8_t*>(svg_str.data()), svg_str.size());

    // Sample 07: Electron .asar containing the SVG
    std::vector<uint8_t> svg_bytes(svg_str.begin(), svg_str.end());
    std::vector<uint8_t> asar_bytes = build_asar("assets/icon.svg", svg_bytes);
    utils::write_file(samples_dir + "/07_electron_bundle.asar", asar_bytes.data(), asar_bytes.size());

    // Sample 08: Polyglot Image ("图种" JPG + ZIP)
    std::vector<uint8_t> poly_bytes = {
        0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 'J', 'F', 'I', 'F', 0x00,
        0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0xFF, 0xD9
    };
    poly_bytes.insert(poly_bytes.end(), zip_bytes.begin(), zip_bytes.end());
    utils::write_file(samples_dir + "/08_polyglot_image.jpg", poly_bytes.data(), poly_bytes.size());

    // Sample 09: Linux Self-Extracting Shell Script (.run)
    std::vector<uint8_t> tgz_bytes;
    utils::read_entire_file(nested_tgz, tgz_bytes);
    std::string sh_head = "#!/bin/sh\n# Self-Extracting Installer\necho \"Extracting...\"\nexit 0\n__PAYLOAD_BELOW__\n";
    std::vector<uint8_t> sfx_bytes(sh_head.begin(), sh_head.end());
    sfx_bytes.insert(sfx_bytes.end(), tgz_bytes.begin(), tgz_bytes.end());
    utils::write_file(samples_dir + "/09_self_extracting.run", sfx_bytes.data(), sfx_bytes.size());

    // Sample 10: RTF document (.rtf) with {\pict\pngblip} and {\*\objdata} OLE 1.0 Package ("RTF内嵌数据包.zip")
    std::vector<uint8_t> png_1x1 = utils::base64_decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=");
    std::vector<uint8_t> rtf_bytes = build_rtf_with_pict_and_ole1(png_1x1, "RTF内嵌数据包.zip", zip_bytes);
    utils::write_file(samples_dir + "/10_rtf_embedded.rtf", rtf_bytes.data(), rtf_bytes.size());

    // Sample 11: OneNote (.one) with MS-ONESTORE FileDataStoreObject entries (PNG + ZIP)
    std::vector<uint8_t> one_bytes = build_onenote_with_objects({png_1x1, zip_bytes});
    utils::write_file(samples_dir + "/11_onenote_section.one", one_bytes.data(), one_bytes.size());

    // Sample 12: Multi-Payload Polyglot / Self-Extracting Bundle (Shell + 7z + PNG + ZIP concatenated)
    std::vector<uint8_t> s7z_bytes;
    utils::read_entire_file(samples_dir + "/04_nested_archive.7z", s7z_bytes);
    std::string multi_hdr = "#!/bin/sh\n# Multi-payload concatenated stream\nexit 0\n";
    std::vector<uint8_t> multi_carve(multi_hdr.begin(), multi_hdr.end());
    multi_carve.insert(multi_carve.end(), s7z_bytes.begin(), s7z_bytes.end());
    multi_carve.insert(multi_carve.end(), png_1x1.begin(), png_1x1.end());
    multi_carve.insert(multi_carve.end(), zip_bytes.begin(), zip_bytes.end());
    utils::write_file(samples_dir + "/12_multi_carve_bundle.bin", multi_carve.data(), multi_carve.size());

    // Sample 13: PyInstaller Single-File Executable (.elf) with CArchive TOC (app_main.pyc + 配置清单_内嵌包.zip)
    std::vector<uint8_t> pyi_elf = build_pyinstaller_elf(zip_bytes);
    utils::write_file(samples_dir + "/13_pyinstaller_bundle.elf", pyi_elf.data(), pyi_elf.size());

    // Sample 14: Adobe InDesign (.indd) with XMP Thumbnail + Contiguous Embedded PNG & ZIP
    std::vector<uint8_t> indd_bytes = build_indd_with_embeds(png_1x1, zip_bytes);
    utils::write_file(samples_dir + "/14_indesign_document.indd", indd_bytes.data(), indd_bytes.size());

    // Sample 15: Photoshop Large Document Format (.psb, v2 64-bit) with Chinese Smart Object
    std::vector<uint8_t> psb_bytes = build_psb_v2("超大文档_智能对象层.zip", zip_bytes);
    utils::write_file(samples_dir + "/15_photoshop_large.psb", psb_bytes.data(), psb_bytes.size());

    // Sample 16: Docker / OCI Container Image (.tar with manifest.json + extensionless blobs/sha256/<hash> tar.gz layer)
    std::string oci_stage = tmp_dir + "/oci_stage";
    utils::make_dirs(oci_stage + "/blobs/sha256");
    std::string layer_hash = utils::sha256_file(nested_tgz);
    std::vector<uint8_t> layer_bytes;
    utils::read_entire_file(nested_tgz, layer_bytes);
    utils::write_file(oci_stage + "/blobs/sha256/" + layer_hash, layer_bytes.data(), layer_bytes.size());
    std::string oci_layout = "{\"imageLayoutVersion\": \"1.0.0\"}";
    utils::write_file(oci_stage + "/oci-layout", reinterpret_cast<const uint8_t*>(oci_layout.data()), oci_layout.size());
    std::string oci_manifest = "[{\"Config\":\"blobs/sha256/config\",\"RepoTags\":[\"demo:latest\"],\"Layers\":[\"blobs/sha256/" + layer_hash + "\"]}]";
    utils::write_file(oci_stage + "/manifest.json", reinterpret_cast<const uint8_t*>(oci_manifest.data()), oci_manifest.size());
    utils::run_external_cmd({"tar", "-cf", samples_dir + "/16_docker_oci_image.tar", "-C", oci_stage, "oci-layout", "manifest.json", "blobs"});

    // Sample 17: SquashFS Embedded Linux Filesystem Image (.squashfs)
    std::string sq_stage = tmp_dir + "/sq_stage";
    utils::make_dirs(sq_stage + "/etc");
    utils::write_file(sq_stage + "/etc/firmware_archive.zip", zip_bytes.data(), zip_bytes.size());
    utils::run_external_cmd({"mksquashfs", sq_stage, samples_dir + "/17_linux_rootfs.squashfs", "-noappend", "-quiet"});

    // Sample 18: ISO 9660 Optical Disc Image (.iso)
    std::string iso_stage = tmp_dir + "/iso_stage";
    utils::make_dirs(iso_stage);
    utils::write_file(iso_stage + "/cdrom_package.zip", zip_bytes.data(), zip_bytes.size());
    utils::run_external_cmd({"genisoimage", "-quiet", "-R", "-J", "-o", samples_dir + "/18_optical_disc.iso", iso_stage});

    // Sample 19: Master Showcase Bundle (.7z containing all 01..18 samples)
    utils::run_external_cmd({
        "7z", "a", samples_dir + "/19_master_showcase.7z",
        samples_dir + "/01_pdf_with_attachment.pdf",
        samples_dir + "/02_office_opc.docx",
        samples_dir + "/03_legacy_ole2.doc",
        samples_dir + "/04_nested_archive.7z",
        samples_dir + "/05_photoshop_smartobj.psd",
        samples_dir + "/06_vector_base64.svg",
        samples_dir + "/07_electron_bundle.asar",
        samples_dir + "/08_polyglot_image.jpg",
        samples_dir + "/09_self_extracting.run",
        samples_dir + "/10_rtf_embedded.rtf",
        samples_dir + "/11_onenote_section.one",
        samples_dir + "/12_multi_carve_bundle.bin",
        samples_dir + "/13_pyinstaller_bundle.elf",
        samples_dir + "/14_indesign_document.indd",
        samples_dir + "/15_photoshop_large.psb",
        samples_dir + "/16_docker_oci_image.tar",
        samples_dir + "/17_linux_rootfs.squashfs",
        samples_dir + "/18_optical_disc.iso"
    });

    utils::run_external_cmd({"rm", "-rf", tmp_dir});
    return true;
}

} // namespace test_fixtures
} // namespace unnest

#endif // FILEUNNEST_TEST_FIXTURES_H
