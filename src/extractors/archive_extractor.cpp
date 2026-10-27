#include "fileunnest/extractor.h"
#include "fileunnest/utils.h"
#include <cstdint>
#include <cstring>
#include <dlfcn.h>
#include <fstream>
#include <map>
#include <sys/stat.h>

namespace unnest {

namespace {

// Minimal libarchive C ABI declarations for dynamic loading via dlopen("libarchive.so.13")
struct archive;
struct archive_entry;

typedef struct archive* (*fn_archive_read_new)();
typedef int (*fn_archive_read_support_filter_all)(struct archive*);
typedef int (*fn_archive_read_support_format_all)(struct archive*);
typedef int (*fn_archive_read_open_filename)(struct archive*, const char*, size_t);
typedef int (*fn_archive_read_next_header)(struct archive*, struct archive_entry**);
typedef int (*fn_archive_read_data_block)(struct archive*, const void**, size_t*, int64_t*);
typedef int (*fn_archive_read_free)(struct archive*);
typedef const char* (*fn_archive_entry_pathname)(struct archive_entry*);
typedef const char* (*fn_archive_entry_pathname_utf8)(struct archive_entry*);
typedef unsigned int (*fn_archive_entry_filetype)(struct archive_entry*);

struct LibArchiveApi {
    void* handle = nullptr;
    fn_archive_read_new read_new = nullptr;
    fn_archive_read_support_filter_all support_filter_all = nullptr;
    fn_archive_read_support_format_all support_format_all = nullptr;
    fn_archive_read_open_filename open_filename = nullptr;
    fn_archive_read_next_header next_header = nullptr;
    fn_archive_read_data_block data_block = nullptr;
    fn_archive_read_free read_free = nullptr;
    fn_archive_entry_pathname entry_pathname = nullptr;
    fn_archive_entry_pathname_utf8 entry_pathname_utf8 = nullptr;
    fn_archive_entry_filetype entry_filetype = nullptr;
    bool loaded = false;

    LibArchiveApi() {
        const char* names[] = {"libarchive.so.13", "libarchive.so", nullptr};
        for (int i = 0; names[i]; ++i) {
            handle = dlopen(names[i], RTLD_LAZY);
            if (handle) break;
        }
        if (!handle) return;
        read_new = reinterpret_cast<fn_archive_read_new>(dlsym(handle, "archive_read_new"));
        support_filter_all = reinterpret_cast<fn_archive_read_support_filter_all>(dlsym(handle, "archive_read_support_filter_all"));
        support_format_all = reinterpret_cast<fn_archive_read_support_format_all>(dlsym(handle, "archive_read_support_format_all"));
        open_filename = reinterpret_cast<fn_archive_read_open_filename>(dlsym(handle, "archive_read_open_filename"));
        next_header = reinterpret_cast<fn_archive_read_next_header>(dlsym(handle, "archive_read_next_header"));
        data_block = reinterpret_cast<fn_archive_read_data_block>(dlsym(handle, "archive_read_data_block"));
        read_free = reinterpret_cast<fn_archive_read_free>(dlsym(handle, "archive_read_free"));
        entry_pathname = reinterpret_cast<fn_archive_entry_pathname>(dlsym(handle, "archive_entry_pathname"));
        entry_pathname_utf8 = reinterpret_cast<fn_archive_entry_pathname_utf8>(dlsym(handle, "archive_entry_pathname_utf8"));
        entry_filetype = reinterpret_cast<fn_archive_entry_filetype>(dlsym(handle, "archive_entry_filetype"));
        loaded = (read_new && support_filter_all && support_format_all && open_filename &&
                  next_header && data_block && read_free && entry_pathname && entry_filetype);
    }

    ~LibArchiveApi() {
        if (handle) dlclose(handle);
    }
};

static LibArchiveApi& get_libarchive() {
    static LibArchiveApi api;
    return api;
}

bool is_opc_interesting_entry(const std::string& rel_path) {
    // In DOCX/XLSX/PPTX, embedded objects, media, and ActiveX live in embeddings/, media/, activeX/
    // Or any non-xml/non-rels file
    std::string lower = utils::to_lower(rel_path);
    if (lower.find("embeddings/") != std::string::npos ||
        lower.find("media/") != std::string::npos ||
        lower.find("activex/") != std::string::npos ||
        lower.find("customxml/") != std::string::npos) {
        return true;
    }
    std::string ext = utils::get_extension(lower);
    if (ext == ".xml" || ext == ".rels" || lower.find("_rels/") != std::string::npos) return false;
    return true;
}

// Correlate embedded objects with their display icons in OPC .docx/.xlsx/.pptx
void correlate_opc_icons(const std::string& output_dir, std::vector<ExtractedItem>& items) {
    // Check if word/document.xml and word/_rels/document.xml.rels exist
    // If not on disk, check if there are xml/rels files or read them
    std::string doc_xml_path = utils::join_path(output_dir, "word/document.xml");
    std::string rels_xml_path = utils::join_path(output_dir, "word/_rels/document.xml.rels");
    
    std::vector<uint8_t> rels_data;
    std::vector<uint8_t> doc_data;
    if (!utils::read_entire_file(rels_xml_path, rels_data)) return;
    if (!utils::read_entire_file(doc_xml_path, doc_data)) return;

    std::string rels_str(reinterpret_cast<const char*>(rels_data.data()), rels_data.size());
    std::string doc_str(reinterpret_cast<const char*>(doc_data.data()), doc_data.size());

    // 1. Build map of rId -> Target from document.xml.rels
    // <Relationship Id="rId20" ... Target="media/rId20.png" />
    std::map<std::string, std::string> rid_to_target;
    size_t pos = 0;
    while ((pos = rels_str.find("<Relationship ", pos)) != std::string::npos) {
        size_t end_tag = rels_str.find("/>", pos);
        if (end_tag == std::string::npos) end_tag = rels_str.find(">", pos);
        if (end_tag == std::string::npos) break;
        std::string tag = rels_str.substr(pos, end_tag - pos);
        
        std::string rid, target;
        size_t id_p = tag.find("Id=\"");
        if (id_p != std::string::npos) {
            size_t id_e = tag.find("\"", id_p + 4);
            if (id_e != std::string::npos) rid = tag.substr(id_p + 4, id_e - (id_p + 4));
        }
        size_t tg_p = tag.find("Target=\"");
        if (tg_p != std::string::npos) {
            size_t tg_e = tag.find("\"", tg_p + 8);
            if (tg_e != std::string::npos) target = tag.substr(tg_p + 8, tg_e - (tg_p + 8));
        }
        if (!rid.empty() && !target.empty()) {
            rid_to_target[rid] = target;
        }
        pos = end_tag + 1;
    }

    // 2. Parse <w:object> blocks in document.xml to map embed_rId -> icon_rId
    // <w:object>
    //   <v:shape ...><v:imagedata r:id="rId23"/></v:shape>
    //   <o:OLEObject ... r:id="rId99"/>
    // </w:object>
    std::map<std::string, std::string> embed_target_to_icon_target;
    pos = 0;
    while ((pos = doc_str.find("<w:object", pos)) != std::string::npos) {
        size_t obj_end = doc_str.find("</w:object>", pos);
        if (obj_end == std::string::npos) break;
        std::string obj_xml = doc_str.substr(pos, obj_end + 11 - pos);

        std::string icon_rid;
        size_t img_p = obj_xml.find("imagedata");
        if (img_p != std::string::npos) {
            size_t rid_p = obj_xml.find("r:id=\"", img_p);
            if (rid_p != std::string::npos) {
                size_t rid_e = obj_xml.find("\"", rid_p + 6);
                if (rid_e != std::string::npos) icon_rid = obj_xml.substr(rid_p + 6, rid_e - (rid_p + 6));
            }
        }

        std::string embed_rid;
        size_t ole_p = obj_xml.find("OLEObject");
        if (ole_p != std::string::npos) {
            size_t rid_p = obj_xml.find("r:id=\"", ole_p);
            if (rid_p != std::string::npos) {
                size_t rid_e = obj_xml.find("\"", rid_p + 6);
                if (rid_e != std::string::npos) embed_rid = obj_xml.substr(rid_p + 6, rid_e - (rid_p + 6));
            }
        }

        if (!icon_rid.empty() && !embed_rid.empty()) {
            std::string icon_target = rid_to_target[icon_rid];
            std::string embed_target = rid_to_target[embed_rid];
            if (!icon_target.empty() && !embed_target.empty()) {
                // Targets are relative to 'word/', normalize to match rel_path in items
                std::string norm_embed = "word/" + embed_target;
                std::string norm_icon = "word/" + icon_target;
                embed_target_to_icon_target[norm_embed] = norm_icon;
            }
        }
        pos = obj_end + 11;
    }

    // 3. Link items
    for (auto& it : items) {
        std::string item_rel = it.name;
        auto fit = embed_target_to_icon_target.find(item_rel);
        if (fit != embed_target_to_icon_target.end()) {
            std::string icon_path = utils::join_path(output_dir, fit->second);
            it.associated_icon_path = icon_path;
        }
    }
}

class ArchiveExtractor : public IExtractor {
public:
    std::string name() const override { return "ArchiveExtractor(libarchive/7z)"; }

    bool can_handle(const std::string& file_path,
                    const std::string& fmt,
                    const std::vector<uint8_t>&) const override {
        if (fmt == "zip" || fmt == "7z" || fmt == "rar" || fmt == "tar" ||
            fmt == "gzip" || fmt == "bzip2" || fmt == "xz" || fmt == "zstd" ||
            fmt == "cpio" || fmt == "iso" || fmt == "python-wheel" || fmt == "indesign-idml" ||
            fmt == "deb" || fmt == "ar" || fmt == "ofd" || fmt == "uof" || fmt == "cebx" || fmt == "epub" ||
            fmt.find("opc-office") == 0 || fmt.find("mobile-bundle") == 0 ||
            fmt.find("java-archive") == 0) {
            return true;
        }
        std::string ext = utils::get_extension(file_path);
        return (ext == ".zip" || ext == ".7z" || ext == ".rar" || ext == ".tar" ||
                ext == ".tar.gz" || ext == ".tgz" || ext == ".tar.bz2" || ext == ".tar.xz" ||
                ext == ".tar.zst" || ext == ".zst" || ext == ".deb" || ext == ".udeb" ||
                ext == ".ar" || ext == ".a" ||
                ext == ".cpio" || ext == ".iso" || ext == ".jar" || ext == ".war" ||
                ext == ".ear" || ext == ".apk" || ext == ".aab" || ext == ".ipa" ||
                ext == ".whl" || ext == ".idml" || ext == ".docx" || ext == ".xlsx" || ext == ".pptx");
    }

    bool extract(const std::string& file_path,
                 const std::string& output_dir,
                 const UnnestConfig& config,
                 std::vector<ExtractedItem>& out_items) override {
        std::vector<uint8_t> hdr;
        utils::read_file_header(file_path, hdr, 512);
        std::string fmt = utils::detect_format(file_path, hdr);
        bool is_opc = (fmt.find("opc-office") == 0);

        LibArchiveApi& api = get_libarchive();
        if (api.loaded) {
            struct archive* a = api.read_new();
            api.support_filter_all(a);
            api.support_format_all(a);
            if (api.open_filename(a, file_path.c_str(), 16384) == 0) {
                struct archive_entry* entry = nullptr;
                uint64_t total_written = 0;
                bool any = false;
                while (api.next_header(a, &entry) == 0) {
                    const char* raw_name = api.entry_pathname(entry);
                    if (!raw_name || raw_name[0] == '\0') {
                        if (api.entry_pathname_utf8) {
                            raw_name = api.entry_pathname_utf8(entry);
                        }
                    }
                    if (!raw_name) continue;
                    unsigned int ftype = api.entry_filetype(entry);
                    // AE_IFREG = 0100000 (0x8000)
                    if ((ftype & 0170000) == 0040000) continue; // skip directory

                    std::string rel = utils::sanitize_relpath(raw_name);
                    bool is_interesting = is_opc_interesting_entry(rel);
                    // Also always extract document.xml and document.xml.rels temporarily for correlation
                    bool is_doc_rel_xml = (rel == "word/document.xml" || rel == "word/_rels/document.xml.rels");
                    if (is_opc && !config.extract_opc_raw && !is_interesting && !is_doc_rel_xml) {
                        continue;
                    }
                    if (!is_doc_rel_xml && !utils::should_extract_item(rel, config)) {
                        continue;
                    }

                    std::string dest = utils::join_path(output_dir, rel);
                    size_t slash = dest.find_last_of('/');
                    if (slash != std::string::npos) {
                        utils::make_dirs(dest.substr(0, slash));
                    }

                    std::ofstream ofs(dest, std::ios::binary | std::ios::trunc);
                    if (!ofs) continue;

                    const void* buff = nullptr;
                    size_t size = 0;
                    int64_t offset = 0;
                    uint64_t file_written = 0;
                    bool ok = true;
                    bool hit_limit = false;
                    while (true) {
                        int r = api.data_block(a, &buff, &size, &offset);
                        if (r == 1) break; // ARCHIVE_EOF
                        if (r < 0) { ok = false; break; }
                        if (file_written + size > config.max_file_size ||
                            total_written + size > config.max_total_size) {
                            ok = false;
                            hit_limit = true;
                            break;
                        }
                        ofs.write(reinterpret_cast<const char*>(buff), static_cast<std::streamsize>(size));
                        file_written += size;
                        total_written += size;
                    }
                    ofs.close();

                    if (ok) {
                        if (is_opc && !config.extract_opc_raw && is_doc_rel_xml) {
                            // Keep file on disk for correlation, but don't add to output items
                        } else {
                            ExtractedItem item;
                            item.name = rel;
                            item.saved_path = dest;
                            item.size = file_written;
                            item.extractor_name = name();
                            out_items.push_back(item);
                        }
                        any = true;
                    } else if (hit_limit) {
                        std::remove(dest.c_str());
                        api.read_free(a);
                        return false;
                    }
                }
                api.read_free(a);
                if (is_opc) {
                    correlate_opc_icons(output_dir, out_items);
                }
                if (any) return true;
            } else {
                api.read_free(a);
            }
        }

        // Fallback to 7z CLI if libarchive could not extract (e.g., RAR5 or complex 7z)
        utils::make_dirs(output_dir);
        if (utils::run_external_cmd({"7z", "x", "-y", "-o" + output_dir, file_path})) {
            std::vector<std::string> files = utils::list_files_recursive(output_dir);
            uint64_t total_written = 0;
            for (const auto& f : files) {
                std::string rel = f.substr(output_dir.size());
                if (!rel.empty() && rel[0] == '/') rel = rel.substr(1);
                if (is_opc && !config.extract_opc_raw && !is_opc_interesting_entry(rel)) {
                    continue;
                }
                if (!utils::should_extract_item(rel, config)) {
                    std::remove(f.c_str());
                    continue;
                }
                uint64_t fsz = utils::file_size(f);
                if (fsz > config.max_file_size || total_written + fsz > config.max_total_size) {
                    continue;
                }
                total_written += fsz;
                ExtractedItem item;
                item.name = rel;
                item.saved_path = f;
                item.size = fsz;
                item.extractor_name = "ArchiveExtractor(7z)";
                out_items.push_back(item);
            }
            return !out_items.empty();
        }
        return false;
    }
};

} // namespace

std::unique_ptr<IExtractor> create_archive_extractor() {
    return std::unique_ptr<IExtractor>(new ArchiveExtractor());
}

} // namespace unnest
