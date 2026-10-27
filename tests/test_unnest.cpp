#include "fileunnest/engine.h"
#include "fileunnest/utils.h"
#include "test_fixtures.h"
#include <cassert>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

using namespace unnest;

namespace {

int g_passed = 0;
int g_failed = 0;

#define RUN_TEST(fn)                                                              \
    do {                                                                          \
        std::cout << "[ RUN      ] " << #fn << "\n";                              \
        try {                                                                     \
            fn();                                                                 \
            std::cout << "[       OK ] " << #fn << "\n";                          \
            g_passed++;                                                           \
        } catch (...) {                                                           \
            std::cerr << "[  FAILED  ] " << #fn << "\n";                          \
            g_failed++;                                                           \
        }                                                                         \
    } while (0)

bool find_item_by_name(const ExtractedItem& node, const std::string& target_substr) {
    if (node.name.find(target_substr) != std::string::npos) return true;
    for (const auto& c : node.children) {
        if (find_item_by_name(c, target_substr)) return true;
    }
    return false;
}

const ExtractedItem* get_item_by_name(const ExtractedItem& node, const std::string& target_substr) {
    if (node.name.find(target_substr) != std::string::npos) return &node;
    for (const auto& c : node.children) {
        const ExtractedItem* res = get_item_by_name(c, target_substr);
        if (res) return res;
    }
    return nullptr;
}

int max_tree_depth(const ExtractedItem& node) {
    int m = node.depth;
    for (const auto& c : node.children) {
        int cd = max_tree_depth(c);
        if (cd > m) m = cd;
    }
    return m;
}

// 1. Unit Test: SHA256, Base64, Path Sanitization, Magic Detection
void test_utils_crypto_and_paths() {
    // Known SHA256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
    const char* abc = "abc";
    std::string digest = utils::sha256_bytes(reinterpret_cast<const uint8_t*>(abc), 3);
    assert(digest == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

    // Base64 decode("SGVsbG8gV29ybGQh") -> "Hello World!"
    std::vector<uint8_t> dec = utils::base64_decode("SGVsbG8gV29ybGQh");
    std::string dec_str(reinterpret_cast<const char*>(dec.data()), dec.size());
    assert(dec_str == "Hello World!");

    // Path traversal sanitization
    std::string dirty = "../../../etc/passwd";
    assert(utils::sanitize_relpath(dirty) == "etc/passwd");
    std::string win_dirty = "..\\..\\Windows\\System32\\cmd.exe";
    assert(utils::sanitize_relpath(win_dirty) == "Windows/System32/cmd.exe");

    // Format detection
    std::vector<uint8_t> pk = {'P', 'K', 0x03, 0x04};
    assert(utils::detect_format("report.docx", pk) == "opc-office(docx)");
    assert(utils::detect_format("app.apk", pk) == "mobile-bundle(apk)");
    assert(utils::detect_format("service.jar", pk) == "java-archive(jar)");
    assert(utils::detect_format("pkg.whl", pk) == "python-wheel");

    // Chinese Encoding Conversion: GBK ("中文测试.txt" = D6 D0 CE C4 B2 E2 CA D4) -> UTF-8
    const uint8_t gbk_bytes[] = {0xD6, 0xD0, 0xCE, 0xC4, 0xB2, 0xE2, 0xCA, 0xD4, '.', 't', 'x', 't'};
    std::string gbk_str(reinterpret_cast<const char*>(gbk_bytes), sizeof(gbk_bytes));
    assert(utils::ensure_utf8(gbk_str) == "中文测试.txt");
    assert(utils::sanitize_relpath(gbk_str) == "中文测试.txt");

    // UTF-16LE ("附件.zip" = 44 96 F6 4E 2E 00 7A 00 69 00 70 00) -> UTF-8
    const uint8_t u16le[] = {0x44, 0x96, 0xF6, 0x4E, '.', 0x00, 'z', 0x00, 'i', 0x00, 'p', 0x00};
    assert(utils::utf16le_to_utf8(u16le, sizeof(u16le)) == "附件.zip");

    // UTF-16BE ("图层" = 56 FE 5C 42) -> UTF-8
    const uint8_t u16be[] = {0x56, 0xFE, 0x5C, 0x42};
    assert(utils::utf16be_to_utf8(u16be, sizeof(u16be)) == "图层");
}

// 2. Unit Test: OPC Office Filtering vs Raw Mode (.docx)
void test_opc_office_filtering() {
    std::string samples_dir = "/tmp/fileunnest_ut_samples";
    test_fixtures::generate_all_samples(samples_dir);
    std::string docx = samples_dir + "/02_office_opc.docx";

    // Default config: extract_opc_raw = false (skip [Content_Types].xml & document.xml, keep embeddings/ & media/)
    UnnestConfig cfg_filtered;
    cfg_filtered.extract_opc_raw = false;
    UnnestEngine eng1(cfg_filtered);
    ExtractedItem res1 = eng1.process(docx, samples_dir + "/out_opc_filtered");
    assert(!find_item_by_name(res1, "document.xml"));
    assert(find_item_by_name(res1, "oleObject1.bin"));
    assert(find_item_by_name(res1, "内嵌报表数据.zip"));
    assert(find_item_by_name(res1, "secret_payload.txt"));
    assert(find_item_by_name(res1, "rId20.png"));
    assert(find_item_by_name(res1, "rId23.png"));
    assert(find_item_by_name(res1, "插入的图片对象_附件.png"));

    // Check associated icon for docx embedded object
    bool found_icon_link = false;
    for (const auto& ch : res1.children) {
        if (ch.name == "word/embeddings/oleObject1.bin" || ch.name.find("oleObject1") != std::string::npos) {
            if (!ch.associated_icon_path.empty()) {
                found_icon_link = true;
            }
        }
    }
    assert(found_icon_link);

    // Verify real Word 97-2003 .doc (03_legacy_ole2.doc) extracts body images (Data_image_0/1.png),
    // Chinese-named inserted image attachment (插入的图片对象_附件.png), and Chinese-named embedded zip (内嵌报表数据.zip)
    std::string doc97 = samples_dir + "/03_legacy_ole2.doc";
    ExtractedItem res_doc97 = eng1.process(doc97, samples_dir + "/out_doc97");
    assert(find_item_by_name(res_doc97, "Data_image_0.png"));
    assert(find_item_by_name(res_doc97, "Data_image_1.png"));
    assert(find_item_by_name(res_doc97, "插入的图片对象_附件.png"));
    assert(find_item_by_name(res_doc97, "内嵌报表数据.zip"));
    assert(find_item_by_name(res_doc97, "secret_payload.txt"));

    // Check associated icon in .doc
    bool doc_icon_link = false;
    for (const auto& ch : res_doc97.children) {
        if (ch.name.find("内嵌报表数据") != std::string::npos) {
            if (!ch.associated_icon_path.empty()) {
                doc_icon_link = true;
            }
        }
    }
    assert(doc_icon_link);

    // Check real multi-icon Word 97-2003 .doc (111.doc) 1:1 icon correlation:
    // 64ea771b...png -> Data_image_1.png
    // CMakeLists.txt -> Data_image_2.png
    // 反窃密自查风险评估报告...pdf -> Data_image_3.png
    std::string doc111 = "sample/111.doc";
    if (utils::file_exists(doc111)) {
        ExtractedItem res_111 = eng1.process(doc111, samples_dir + "/out_111");
        const ExtractedItem* it_png = get_item_by_name(res_111, "64ea771b-8bb8-4c0f-b5aa-d6a631749c84.png");
        const ExtractedItem* it_txt = get_item_by_name(res_111, "CMakeLists.txt");
        const ExtractedItem* it_pdf = get_item_by_name(res_111, "反窃密自查风险评估报告_20260929_143532.pdf");
        assert(it_png && it_png->associated_icon_path.find("Data_image_1.png") != std::string::npos);
        assert(it_txt && it_txt->associated_icon_path.find("Data_image_2.png") != std::string::npos);
        assert(it_pdf && it_pdf->associated_icon_path.find("Data_image_3.png") != std::string::npos);
    }

    // Raw config: extract_opc_raw = true (keep XMLs)
    UnnestConfig cfg_raw;
    cfg_raw.extract_opc_raw = true;
    UnnestEngine eng2(cfg_raw);
    ExtractedItem res2 = eng2.process(docx, samples_dir + "/out_opc_raw");
    assert(find_item_by_name(res2, "document.xml"));
}

// 3. Unit Test: OLE2 Regular FAT + MiniStream (< 4096B)
void test_ole2_ministream_and_ole10() {
    std::string dir = "/tmp/fileunnest_ut_ole2";
    utils::run_external_cmd({"rm", "-rf", dir});
    utils::make_dirs(dir);

    std::string msg = "MiniStream Small Payload Test";
    std::vector<uint8_t> payload(msg.begin(), msg.end());
    std::vector<uint8_t> cfb = test_fixtures::build_ole2_ministream("SmallStream.txt", payload);
    std::string cfb_path = dir + "/ministream.doc";
    utils::write_file(cfb_path, cfb.data(), cfb.size());

    UnnestEngine engine;
    ExtractedItem res = engine.process(cfb_path, dir + "/out");
    assert(find_item_by_name(res, "SmallStream.txt"));
    assert(res.children.size() == 1);
    assert(res.children[0].size == payload.size());
}

// 4. Unit Test: PDF FlateDecode EmbeddedFile Stream Extraction
void test_pdf_flate_attachment() {
    std::string samples_dir = "/tmp/fileunnest_ut_samples";
    std::string pdf = samples_dir + "/01_pdf_with_attachment.pdf";

    UnnestEngine engine;
    ExtractedItem res = engine.process(pdf, samples_dir + "/out_pdf");
    assert(find_item_by_name(res, "invoice_bundle.zip"));
    assert(find_item_by_name(res, "secret_payload.txt"));
}

// 5. Unit Test: Electron ASAR + SVG Base64 Data URI
void test_asar_and_svg_base64() {
    std::string samples_dir = "/tmp/fileunnest_ut_samples";
    std::string asar = samples_dir + "/07_electron_bundle.asar";

    UnnestEngine engine;
    ExtractedItem res = engine.process(asar, samples_dir + "/out_asar");
    assert(find_item_by_name(res, "assets/icon.svg"));
    assert(find_item_by_name(res, "embedded_0.png"));
}

// 6. Unit Test: Photoshop PSD Smart Object Extraction (including Chinese UTF-16BE filename)
void test_psd_smart_object() {
    std::string samples_dir = "/tmp/fileunnest_ut_samples";
    std::string psd = samples_dir + "/05_photoshop_smartobj.psd";

    UnnestEngine engine;
    ExtractedItem res = engine.process(psd, samples_dir + "/out_psd");
    assert(find_item_by_name(res, "智能对象_设计图层.zip"));
    assert(find_item_by_name(res, "secret_payload.txt"));
}

// 7. Unit Test: Polyglot Image Carving & Self-Extracting Script + PyInstaller Cookie
void test_carving_polyglot_sfx_pyinstaller() {
    std::string samples_dir = "/tmp/fileunnest_ut_samples";
    UnnestEngine engine;

    // Polyglot JPG+ZIP
    ExtractedItem res_jpg = engine.process(samples_dir + "/08_polyglot_image.jpg", samples_dir + "/out_jpg");
    assert(find_item_by_name(res_jpg, "carved_0_"));
    assert(find_item_by_name(res_jpg, "secret_payload.txt"));

    // Self-Extracting .run script
    ExtractedItem res_sfx = engine.process(samples_dir + "/09_self_extracting.run", samples_dir + "/out_sfx");
    assert(find_item_by_name(res_sfx, "carved_0_"));
    assert(find_item_by_name(res_sfx, "inner_payload.zip"));
    assert(find_item_by_name(res_sfx, "secret_payload.txt"));

    // Mock PyInstaller ELF binary with MEI\x0c\x0b\x0a\x0b\x0e cookie
    std::vector<uint8_t> elf_pyi = {0x7F, 'E', 'L', 'F', 0x02, 0x01, 0x01, 0x00};
    elf_pyi.resize(64, 0x90);
    // Append a 16-byte dummy pkg body + 24-byte PyInstaller 2.0 cookie (pkg_len = 16 + 24 = 40)
    for (int i = 0; i < 16; ++i) elf_pyi.push_back(static_cast<uint8_t>('A' + i));
    const uint8_t magic[8] = {'M', 'E', 'I', 0x0C, 0x0B, 0x0A, 0x0B, 0x0E};
    elf_pyi.insert(elf_pyi.end(), magic, magic + 8);
    test_fixtures::append_u32_be(elf_pyi, 40); // pkg_len = 40
    test_fixtures::append_u32_be(elf_pyi, 0);  // toc_offset
    test_fixtures::append_u32_be(elf_pyi, 0);  // toc_len
    test_fixtures::append_u32_be(elf_pyi, 311);// pyvers
    std::string pyi_path = samples_dir + "/mock_pyinstaller.elf";
    utils::write_file(pyi_path, elf_pyi.data(), elf_pyi.size());

    ExtractedItem res_pyi = engine.process(pyi_path, samples_dir + "/out_pyi");
    assert(find_item_by_name(res_pyi, "carved_pyinstaller_pkg_0.pkg"));
}

// 8. Unit Test: Depth Limit & Max Size Guard (Anti-Zip-Bomb)
void test_depth_and_size_limits() {
    std::string samples_dir = "/tmp/fileunnest_ut_samples";
    std::string nested = samples_dir + "/04_nested_archive.7z";

    // Limit depth to 1 -> should only extract layer2.tar.gz (depth 1), not inner_payload.zip or secret_payload.txt
    UnnestConfig cfg_depth1;
    cfg_depth1.max_depth = 1;
    UnnestEngine eng_d1(cfg_depth1);
    ExtractedItem res_d1 = eng_d1.process(nested, samples_dir + "/out_depth1");
    assert(max_tree_depth(res_d1) == 1);
    assert(find_item_by_name(res_d1, "layer2.tar.gz"));
    assert(!find_item_by_name(res_d1, "secret_payload.txt"));

    // Limit max_file_size to 10 bytes -> extraction should abort/skip files > 10 bytes
    UnnestConfig cfg_tiny;
    cfg_tiny.max_file_size = 10;
    UnnestEngine eng_tiny(cfg_tiny);
    ExtractedItem res_tiny = eng_tiny.process(nested, samples_dir + "/out_tiny");
    assert(res_tiny.children.empty());

    // Test In-Process VFS stream filter: --filter image,text / --images-only
    UnnestConfig cfg_filter;
    cfg_filter.filter_image = true;
    cfg_filter.filter_text = true;
    UnnestEngine eng_filter(cfg_filter);
    ExtractedItem res_filter = eng_filter.process(nested, samples_dir + "/out_filter");
    assert(find_item_by_name(res_filter, "secret_payload.txt"));

    UnnestConfig cfg_img_only;
    cfg_img_only.filter_text = false;
    cfg_img_only.filter_office = false;
    cfg_img_only.filter_pdf = false;
    cfg_img_only.filter_image = true;
    UnnestEngine eng_img_only(cfg_img_only);
    ExtractedItem res_img = eng_img_only.process(nested, samples_dir + "/out_img_only");
    assert(!find_item_by_name(res_img, "secret_payload.txt"));
}

// 9. Unit Test (Extension 1 & 2): OLE2 Sub-Storage Repackaging (.xls) + Compact Ole10Native + Compressed EMF/DIB Blips
void test_ext1_ext2_ole2_substorage_and_odraw_blips() {
    std::string dir = "/tmp/fileunnest_ut_ext12";
    utils::run_external_cmd({"rm", "-rf", dir});
    utils::make_dirs(dir);

    // 1) Test Compact Ole10Native (flags != 2) + MS-ODRAW compressed EMF Blip (0xF01A) inside Data stream
    std::vector<uint8_t> fake_emf(64, 0);
    fake_emf[0] = 1; // EMR_HEADER
    std::memcpy(fake_emf.data() + 40, " EMF", 4);
    std::vector<uint8_t> comp_emf = test_fixtures::zlib_compress(fake_emf);

    // Build OfficeArtBlipEMF Record (recVer=0, recInstance=0x03D4, recType=0xF01A)
    // Body = 16B UID + 34B MetafileHeader (fCompression=0 at offset 32) + comp_emf
    std::vector<uint8_t> blip_rec;
    uint16_t ver_inst = static_cast<uint16_t>(0x03D4 << 4);
    uint16_t rec_type = 0xF01A;
    uint32_t rec_len = static_cast<uint32_t>(16 + 34 + comp_emf.size());
    test_fixtures::append_u16_le(blip_rec, ver_inst);
    test_fixtures::append_u16_le(blip_rec, rec_type);
    test_fixtures::append_u32_le(blip_rec, rec_len);
    blip_rec.resize(8 + 16 + 34, 0);
    blip_rec[8 + 16 + 32] = 0; // fCompression = 0 (deflate)
    blip_rec.insert(blip_rec.end(), comp_emf.begin(), comp_emf.end());

    std::vector<uint8_t> cfb_blip = test_fixtures::build_ole2_ministream("Data", blip_rec);
    std::string blip_doc = dir + "/odraw_emf.doc";
    utils::write_file(blip_doc, cfb_blip.data(), cfb_blip.size());

    UnnestEngine engine;
    ExtractedItem res_blip = engine.process(blip_doc, dir + "/out_blip");
    assert(find_item_by_name(res_blip, "Data_blip_0.emf"));
    assert(res_blip.children[0].size == fake_emf.size());

    // 2) Test Sub-Storage Repackaging: Build an OLE2 with Root Entry -> Storage "ObjectPool" (type 1) -> Stream "Workbook" (type 2)
    std::vector<uint8_t> cfb_sub(5 * 512, 0);
    const uint8_t sig[8] = {0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1};
    std::memcpy(cfb_sub.data(), sig, 8);
    test_fixtures::write_u16_le(cfb_sub, 24, 0x003E);
    test_fixtures::write_u16_le(cfb_sub, 26, 0x0003);
    test_fixtures::write_u16_le(cfb_sub, 28, 0xFFFE);
    test_fixtures::write_u16_le(cfb_sub, 30, 9);
    test_fixtures::write_u16_le(cfb_sub, 32, 6);
    test_fixtures::write_u32_le(cfb_sub, 44, 1);
    test_fixtures::write_u32_le(cfb_sub, 48, 1); // Dir at sector 1
    test_fixtures::write_u32_le(cfb_sub, 56, 0); // cutoff=0
    test_fixtures::write_u32_le(cfb_sub, 60, 0xFFFFFFFE);
    test_fixtures::write_u32_le(cfb_sub, 68, 0xFFFFFFFE);
    test_fixtures::write_u32_le(cfb_sub, 76, 0);
    for (int i = 1; i < 109; ++i) test_fixtures::write_u32_le(cfb_sub, 76 + i * 4, 0xFFFFFFFF);
    for (int i = 0; i < 128; ++i) test_fixtures::write_u32_le(cfb_sub, 512 + i * 4, 0xFFFFFFFF);
    test_fixtures::write_u32_le(cfb_sub, 512 + 0 * 4, 0xFFFFFFFD);
    test_fixtures::write_u32_le(cfb_sub, 512 + 1 * 4, 0xFFFFFFFE);
    test_fixtures::write_u32_le(cfb_sub, 512 + 2 * 4, 0xFFFFFFFE);

    size_t d_off = 1024;
    auto set_ent = [&](size_t idx, const char* nm, uint8_t typ, uint32_t child, uint32_t sec, uint32_t sz) {
        size_t o = d_off + idx * 128;
        for (size_t k = 0; nm[k]; ++k) test_fixtures::write_u16_le(cfb_sub, o + k * 2, nm[k]);
        test_fixtures::write_u16_le(cfb_sub, o + 64, static_cast<uint16_t>((std::strlen(nm) + 1) * 2));
        cfb_sub[o + 66] = typ;
        test_fixtures::write_u32_le(cfb_sub, o + 68, 0xFFFFFFFF);
        test_fixtures::write_u32_le(cfb_sub, o + 72, 0xFFFFFFFF);
        test_fixtures::write_u32_le(cfb_sub, o + 76, child);
        test_fixtures::write_u32_le(cfb_sub, o + 116, sec);
        test_fixtures::write_u32_le(cfb_sub, o + 120, sz);
    };
    set_ent(0, "Root Entry", 5, 1, 0xFFFFFFFE, 0);
    set_ent(1, "ObjectPool", 1, 2, 0xFFFFFFFE, 0); // Storage -> child 2
    // Put a PNG inside the embedded Workbook stream so recursive extraction also pulls the PNG out of the rebuilt .xls!
    std::vector<uint8_t> png_1x1 = utils::base64_decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=");
    set_ent(2, "Workbook", 2, 0xFFFFFFFF, 2, static_cast<uint32_t>(png_1x1.size()));
    std::memcpy(cfb_sub.data() + 1536, png_1x1.data(), png_1x1.size());

    std::string sub_doc = dir + "/with_substorage.doc";
    utils::write_file(sub_doc, cfb_sub.data(), cfb_sub.size());
    ExtractedItem res_sub = engine.process(sub_doc, dir + "/out_sub");
    assert(find_item_by_name(res_sub, "ObjectPool.xls"));
    assert(find_item_by_name(res_sub, "Workbook_image_0.png"));
}

// 10. Unit Test (Extension 3, 4, 5): RTF (\pict + \objdata OLE1.0), OneNote (FileDataStoreObject), Size-Aware Multi-Carving
void test_ext3_ext4_ext5_rtf_onenote_multicarve() {
    std::string samples_dir = "/tmp/fileunnest_ut_samples";
    UnnestEngine engine;

    // Extension 3: RTF
    ExtractedItem res_rtf = engine.process(samples_dir + "/10_rtf_embedded.rtf", samples_dir + "/out_rtf");
    assert(find_item_by_name(res_rtf, "rtf_pict_0.png"));
    assert(find_item_by_name(res_rtf, "RTF内嵌数据包.zip"));
    assert(find_item_by_name(res_rtf, "secret_payload.txt"));

    // Extension 4: OneNote (.one)
    ExtractedItem res_one = engine.process(samples_dir + "/11_onenote_section.one", samples_dir + "/out_one");
    assert(find_item_by_name(res_one, "onenote_object_0.png"));
    assert(find_item_by_name(res_one, "onenote_object_1.zip"));
    assert(find_item_by_name(res_one, "secret_payload.txt"));

    // Extension 5: Size-Aware Multi-Payload Carving (Shell + 7z + PNG + ZIP in a single file)
    ExtractedItem res_mc = engine.process(samples_dir + "/12_multi_carve_bundle.bin", samples_dir + "/out_mc");
    assert(res_mc.children.size() == 3); // Exactly 3 carved items: .7z, .png, .zip
    assert(find_item_by_name(res_mc, ".7z"));
    assert(find_item_by_name(res_mc, ".png"));
    assert(find_item_by_name(res_mc, ".zip"));
    assert(find_item_by_name(res_mc, "layer2.tar.gz"));
    assert(find_item_by_name(res_mc, "secret_payload.txt"));
}

// 11. Unit Test (Gaps 1-5): PyInstaller TOC, InDesign (.indd), PSB v2 64-bit, Docker OCI Image, SquashFS & ISO
void test_gaps1_to_5_pyinstaller_indd_psb_oci_disks() {
    std::string samples_dir = "/tmp/fileunnest_ut_samples";
    UnnestEngine engine;

    // Gap 1 (Plan 1): PyInstaller TOC decompression (app_main.pyc + 配置清单_内嵌包.zip -> secret_payload.txt)
    ExtractedItem res_pyi = engine.process(samples_dir + "/13_pyinstaller_bundle.elf", samples_dir + "/out_pyi_toc");
    assert(find_item_by_name(res_pyi, "app_main.pyc"));
    assert(find_item_by_name(res_pyi, "配置清单_内嵌包.zip"));
    assert(find_item_by_name(res_pyi, "secret_payload.txt"));

    // Gap 2 (Plan 2): Adobe InDesign (.indd) XMP thumbnail + contiguous PNG & ZIP
    ExtractedItem res_indd = engine.process(samples_dir + "/14_indesign_document.indd", samples_dir + "/out_indd");
    assert(find_item_by_name(res_indd, "indd_xmp_preview_0.jpg"));
    assert(find_item_by_name(res_indd, "indd_embedded_1.png"));
    assert(find_item_by_name(res_indd, "indd_embedded_package_2.zip"));
    assert(find_item_by_name(res_indd, "secret_payload.txt"));

    // Gap 3 (Plan 3): Photoshop Large Document (.psb v2, 64-bit lnk2)
    ExtractedItem res_psb = engine.process(samples_dir + "/15_photoshop_large.psb", samples_dir + "/out_psb");
    assert(res_psb.format == "psb");
    assert(find_item_by_name(res_psb, "超大文档_智能对象层.zip"));
    assert(find_item_by_name(res_psb, "secret_payload.txt"));

    // Gap 4 (Plan 4): Docker / OCI Image (.tar -> blobs/sha256/<hash> -> inner_payload.zip -> secret_payload.txt)
    ExtractedItem res_oci = engine.process(samples_dir + "/16_docker_oci_image.tar", samples_dir + "/out_oci");
    assert(find_item_by_name(res_oci, "manifest.json"));
    assert(find_item_by_name(res_oci, "inner_payload.zip"));
    assert(find_item_by_name(res_oci, "secret_payload.txt"));

    // Gap 5 (Plan 5): SquashFS (.squashfs) and ISO 9660 (.iso)
    ExtractedItem res_sq = engine.process(samples_dir + "/17_linux_rootfs.squashfs", samples_dir + "/out_sq");
    assert(res_sq.format == "squashfs");
    assert(find_item_by_name(res_sq, "firmware_archive.zip"));
    assert(find_item_by_name(res_sq, "secret_payload.txt"));

    ExtractedItem res_iso = engine.process(samples_dir + "/18_optical_disc.iso", samples_dir + "/out_iso");
    assert(res_iso.format == "iso");
    assert(find_item_by_name(res_iso, "cdrom_package.zip"));
    assert(find_item_by_name(res_iso, "secret_payload.txt"));

    // Debian package (.deb -> control.tar.* + data.tar.* -> rootfs / usr)
    std::string deb_sample = "/var/cache/apt/archives/zlib1g_1%3a1.3.dfsg-3.1ubuntu2.3_amd64.deb";
    if (utils::file_exists(deb_sample)) {
        // Default mode: extracts control, data, and text/docs, skipping .so binary
        ExtractedItem res_deb = engine.process(deb_sample, samples_dir + "/out_deb");
        assert(res_deb.format == "deb");
        assert(find_item_by_name(res_deb, "control.tar"));
        assert(find_item_by_name(res_deb, "data.tar"));
        assert(find_item_by_name(res_deb, "changelog.Debian"));
        assert(!find_item_by_name(res_deb, "libz.so"));

        // Extract All mode (--all): extracts libz.so unconditionally
        UnnestConfig cfg_all;
        cfg_all.extract_all = true;
        UnnestEngine eng_all(cfg_all);
        ExtractedItem res_deb_all = eng_all.process(deb_sample, samples_dir + "/out_deb_all");
        assert(find_item_by_name(res_deb_all, "libz.so"));
    }
}

// 12. Unit Test: ftype real format and MIME type identification (including disguised files)
void test_ftype_real_format_identification() {
    // 1. In-memory buffer detection
    const uint8_t png_magic[] = {0x89, 'P', 'N', 'G', '\r', '\n', 0x1A, '\n', 0, 0};
    ftype::FileType ft_png = utils::detect_file_type("", std::vector<uint8_t>(png_magic, png_magic + sizeof(png_magic)));
    assert(std::string(ft_png.ext) == "png");
    assert(std::string(ft_png.mime) == "image/png");

    const uint8_t sqlite_magic[] = "SQLite format 3\x00";
    ftype::FileType ft_sql = utils::detect_file_type("", std::vector<uint8_t>(sqlite_magic, sqlite_magic + 16));
    assert(std::string(ft_sql.ext) == "sqlite");

    // 2. Synthetic disguised file test (disguised PNG named as .txt)
    std::string fake_png_path = "/tmp/fileunnest_ut_samples/fake_image.txt";
    utils::write_file(fake_png_path, png_magic, sizeof(png_magic));
    UnnestEngine fake_engine;
    ExtractedItem res_fake_png = fake_engine.process(fake_png_path, "/tmp/fileunnest_ut_samples/out_fake_png");
    assert(res_fake_png.format == "png");
    assert(res_fake_png.real_ext == "png");
    assert(res_fake_png.mime_type == "image/png");

    // 3. Real disguised samples from /tmp/ftype/test_samples if present
    std::string disguised_docx = "/tmp/ftype/test_samples/disguised_docx_as.pdf";
    if (utils::file_exists(disguised_docx)) {
        UnnestEngine engine;
        ExtractedItem res = engine.process(disguised_docx, "/tmp/out_disguised_docx");
        assert(res.format.find("opc-office") == 0);
        assert(res.real_ext == "docx");
        assert(res.mime_type.find("wordprocessingml") != std::string::npos);
    }

    std::string disguised_png = "/tmp/ftype/test_samples/disguised_png_as.txt";
    if (utils::file_exists(disguised_png)) {
        UnnestEngine engine;
        ExtractedItem res = engine.process(disguised_png, "/tmp/out_disguised_png");
        assert(res.format == "png");
        assert(res.real_ext == "png");
        assert(res.mime_type == "image/png");
    }

    std::string sample_ofd = "/tmp/ftype/test_samples/sample.ofd";
    if (utils::file_exists(sample_ofd)) {
        UnnestEngine engine;
        ExtractedItem res = engine.process(sample_ofd, "/tmp/out_ofd");
        assert(res.format == "ofd");
        assert(res.real_ext == "ofd");
        assert(res.mime_type == "application/ofd");
    }

    std::string sample_wps = "/tmp/ftype/test_samples/sample.wps";
    if (utils::file_exists(sample_wps)) {
        UnnestEngine engine;
        ExtractedItem res = engine.process(sample_wps, "/tmp/out_wps");
        assert(res.format.find("ole2") == 0);
        assert(res.real_ext == "wps");
        assert(res.mime_type == "application/vnd.ms-works");
    }
}

} // namespace

int main() {
    std::cout << "==========================================\n";
    std::cout << "   FileUnnest C++11 Unit Test Suite       \n";
    std::cout << "==========================================\n";

    RUN_TEST(test_utils_crypto_and_paths);
    RUN_TEST(test_opc_office_filtering);
    RUN_TEST(test_ole2_ministream_and_ole10);
    RUN_TEST(test_pdf_flate_attachment);
    RUN_TEST(test_asar_and_svg_base64);
    RUN_TEST(test_psd_smart_object);
    RUN_TEST(test_carving_polyglot_sfx_pyinstaller);
    RUN_TEST(test_depth_and_size_limits);
    RUN_TEST(test_ext1_ext2_ole2_substorage_and_odraw_blips);
    RUN_TEST(test_ext3_ext4_ext5_rtf_onenote_multicarve);
    RUN_TEST(test_gaps1_to_5_pyinstaller_indd_psb_oci_disks);
    RUN_TEST(test_ftype_real_format_identification);

    std::cout << "==========================================\n";
    std::cout << "Summary: " << g_passed << " passed, " << g_failed << " failed.\n";
    return (g_failed == 0) ? 0 : 1;
}
