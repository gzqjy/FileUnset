# FileUnnest

高性能 C++11 嵌套文件递归解包与全景溯源分析引擎。

针对复合办公文档、系统镜像与归档、专业设计工程、运行时虚拟文件系统、隐写/多载荷拼接及自解压脚本等全类型容器，执行深度物理与逻辑层级文件还原，并生成携带 SHA-256 与展示图标关联的 JSON 溯源拓扑清单。

---

## 核心特性

- **现代 C++11 标准**：无冗余抽象，支持流式扫描与内存安全解构。
- **真实格式精准识别 (ftype)**：深度集成 [gzqjy/ftype](https://github.com/gzqjy/ftype)，通过魔数（Magic Bytes）与内部目录跳读（ZIP/OLE2/ELF/PE/ISO/SSTable）识别 260+ 种真实格式，免疫后缀伪装（如 `.docx` 伪装为 `.pdf`、`.png` 伪装为 `.txt`），自动提取真实扩展名与精确 MIME 类型。
- **全格式覆盖**：6 大类别、数十种复合嵌套容器原生逆向提取。
- **编码自适应引擎**：内置 UTF-8、UTF-16LE/BE、GBK/GB18030、`\uXXXX` 动态感知转码，杜绝乱码。
- **精准图标双向绑定**：MS-DOC (FIB/FKP) 与 OOXML (OPC/Rels) 对象与展示图标 1:1 精确关联。
- **完整安全防范**：深度阈值与单文件体积阈值控制，免疫 Zip-Bomb 与嵌套死循环。
- **全链路溯源证据链**：导出格式化 `manifest.json`，含节点层级、字节偏移、解析器、大小与 SHA-256 哈希。

---

## 支持格式矩阵

| 类别 | 格式 / 载荷 | 技术实现要点 |
| :--- | :--- | :--- |
| **办公文档** | **PDF** (.pdf) | 解析 `/EmbeddedFiles` 附件、PDF Portfolio 集锦包与 XObject 图像流，支持 FlateDecode。 |
| | **Office OPC** (.docx, .xlsx, .pptx) | 智能过滤模板 XML，提取 `embeddings/` 与 `media/`；通过 `document.xml.rels` 建立对象与小图标关联。 |
| | **Legacy OLE2** (.doc, .xls, .ppt) | 解析 FAT/MiniFAT/MiniStream；解包 `Ole10Native`；重构子存储为合法 CFB；通过 FIB/FKP `sprmCPicLocation` 与 `MS-ODRAW Blip` 绑定图标。 |
| | **RTF** (.rtf) | 逆向提取 `\pict` 图像与 `\objdata`（OLE 1.0 序列化流）。 |
| | **OneNote** (.one) | 基于 GUID 定位解析 `FileDataStoreObject`，导出附件与图片副本。 |
| **归档与镜像** | **通用压缩包** (.zip, .7z, .tar, .gz, .bz2, .rar) | 基于 `libarchive` 与本地算法，无限层级穿透嵌套归档。 |
| | **Linux 安装包 / ar 归档** (.deb, .udeb, .ar) | 原生解构 `ar` 容器，递归解压 `control.tar.*`（DEBIAN 元数据）与 `data.tar.*`（完整系统根目录树如 opt/、usr/ 等）。 |
| | **虚拟磁盘/镜像** (.iso, .squashfs, .vhd, .vhdx, .vmdk) | 原生解包 ISO 9660 与 SquashFS 只读文件系统，自动探测虚拟硬盘容器。 |
| | **移动应用包** (.apk, .aab, .ipa) | 解析专有 ZIP 容器，递归导出 DEX/SO/Assets 及 App Bundle 资产。 |
| **专业设计** | **Photoshop** (.psd, .psb) | 解析 IRB 资源块与图层附加信息（`SoCo`/`SoLd`/`lnk2`/`lnk3`），导出智能对象子文件。全面兼容 PSB 64 位。 |
| | **Adobe InDesign** (.indd) | 解析主数据库对象流，导出内嵌资源与 XMP 预览图。 |
| | **矢量图** (.svg) | 正则提取 `<image>` 标签内的 Base64 内嵌图像并即时还原。 |
| **工程与运行时**| **Electron** (.asar) | 解析 Chromium ASAR 文件头 JSON 目录树，导出全部源码与静态依赖。 |
| | **PyInstaller 打包单文件** | 逆向定位 `MEI\012\013\014` Cookie，解析 CArchive TOC 目录表，解压 `PYZ` 库与嵌入文件。 |
| | **容器镜像** (Docker OCI) | 扫描 `blobs/sha256/` 校验层与 `layer.tar` 导出镜像资产。 |
| | **Java / Python** (.jar, .war, .whl) | 解析多层 JAR-in-JAR 与 Python Wheel 归档。 |
| **隐写与拼接** | **Size-Aware Multi-Carving** | 依据前置文件逻辑结构头长度定位真实末尾，连续识别并剥离图种（JPG+ZIP）、合并包或隐写数据。 |
| **自解压脚本** | **Linux SFX Script** (.sh, .run, .bin) | 剥离 Bash 头部逻辑，识别 Magic 头或边界锚点提取压缩载荷。 |

---

## 架构概览

```
FileUnnest/
├── include/fileunnest/
│   ├── extractor.h     # 统一解包接口 IExtractor 定义与工厂声明
│   ├── types.h         # ExtractedItem、UnnestConfig 等数据结构
│   └── utils.h         # 编码转码、哈希计算、文件 IO 工具
├── src/
│   ├── engine.cpp      # 核心解包调度引擎，负责递归下钻、循环检测与清单组装
│   ├── main.cpp        # 命令行 CLI 入口，树状渲染与 JSON 输出
│   ├── utils.cpp       # 编码转换（GBK/UTF-16/UTF-8）、SHA-256、JSON 序列化
│   └── extractors/
│       ├── ole2_extractor.cpp        # OLE2/CFB, Word FIB/FKP 图标关联, Blip 解码, 子存储重组
│       ├── archive_extractor.cpp     # Zip, 7z, Tar, Gz, Rar, OPC Office 过滤与图标关联
│       ├── pdf_extractor.cpp         # PDF 附件、Portfolio 与 XObject 提取
│       ├── psd_extractor.cpp         # PSD / PSB 智能对象与资源块解析
│       ├── indd_extractor.cpp        # InDesign .indd 资源流与 XMP 提取
│       ├── asar_extractor.cpp        # Electron .asar 目录表与资产解包
│       ├── pyinstaller_extractor.cpp # PyInstaller ELF/PE 单文件 TOC 逆向
│       ├── disk_extractor.cpp        # SquashFS, ISO 9660, VHD 虚拟镜像解包
│       ├── rtf_extractor.cpp         # RTF pict 与 objdata 提取
│       ├── onenote_extractor.cpp     # OneNote FileDataStoreObject 提取
│       ├── svg_extractor.cpp         # SVG 内嵌 Base64 提取
│       └── carve_extractor.cpp       # 逻辑尺寸自适应多载荷雕刻与 Linux SFX 脚本解包
├── tests/
│   └── test_unnest.cpp # 11 项全功能回归测试套件
└── CMakeLists.txt      # CMake 构建配置 (C++11)
```

---

## 编译与安装

### 依赖环境
- Linux / POSIX 环境
- CMake >= 3.10
- C++11 兼容编译器（GCC >= 4.8 或 Clang >= 3.4）
- `zlib` 与 `libarchive` 开发库

在 Ubuntu / Debian 安装依赖：
```bash
sudo apt-get update
sudo apt-get install -y cmake g++ libarchive-dev zlib1g-dev
```

### 构建工程
```bash
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build . -j$(nproc)
```

编译生成以下产物：
- `build/fileunnest`：命令行执行主程序
- `build/libfileunnest_core.a`：核心静态库
- `build/test_unnest`：单元测试程序
- `build/demo_unnest`：多场景提取示例程序

---

## 命令行使用指南

```bash
fileunnest <input_file> <output_dir> [options]
```

### 选项说明
- `--all` / `--extract-all`：关闭过滤策略，无差别全量提取（如 `.so`、`.dll`、`.node`、`.pak` 等）
- `--filter <types>`：自定义过滤组合，逗号分隔，可选 `office`、`image`、`text`、`pdf`（如 `--filter office,pdf`）
- `--images-only`：仅提取图片（及包含它们的中间容器）
- `--text-only`：仅提取文本代码与文档（及包含它们的中间容器）
- `--office-only`：仅提取 Office 办公文档（及包含它们的中间容器）
- `--pdf-only`：仅提取 PDF 文档（及包含它们的中间容器）
- `--max-depth <n>`：最大递归深度（默认值：`10`）
- `--max-size <bytes>`：单文件最大提取体积限制（字节，默认：`1073741824` 即 1GB）
- `--opc-all`：关闭 OPC 过滤策略，保留解压出来的全部骨架 XML 与 `.rels`
- `--manifest <path>`：自定义 `manifest.json` 导出路径（默认存放在 `<output_dir>/manifest.json`）

> **提取策略说明**：
> 默认情况下，FileUnnest 启用**内存挂载流式按需提取**（默认目标：**Office 办公文档、图片类、文本类、PDF 类**）。在流式穿透归档（如 `.deb`、`.tar.gz`、`.zip`、`.asar` 等）时，自动跳过无关大型二进制产物（如 `.so`、`.dll`、`.pak`、`.node`），极大降低解包磁盘占用与耗时。传入 `--all` 时恢复全量无差别提取。

### 使用示例

#### 1. 递归提取并控制台输出树状视图
```bash
./build/fileunnest sample/111.doc /tmp/doc_output
```
控制台树状拓扑输出示例：
```text
[ROOT] 111.doc (ole2, 367616 bytes)
├── CMakeLists.txt [binary | 1141 B | via Ole2Extractor(MS-CFB)] (icon: Data_image_2.png)
├── 64ea771b-8bb8-4c0f-b5aa-d6a631749c84.png [png | 58907 B | via Ole2Extractor(MS-CFB)] (icon: Data_image_1.png)
├── 反窃密自查风险评估报告_20260929_143532.pdf [pdf | 210168 B | via Ole2Extractor(MS-CFB)] (icon: Data_image_3.png)
│   ├── pdf_object_0.jpg [jpeg | 18219 B | via PdfExtractor(native)]
│   └── pdf_object_1.jpg [jpeg | 19481 B | via PdfExtractor(native)]
├── Data_image_0.png [png | 70271 B | via Ole2Extractor(OfficeArtBlip)]
├── Data_image_1.png [png | 4421 B | via Ole2Extractor(OfficeArtBlip)]
├── Data_image_2.png [png | 1607 B | via Ole2Extractor(OfficeArtBlip)]
└── Data_image_3.png [png | 4020 B | via Ole2Extractor(OfficeArtBlip)]

Manifest written to: /tmp/doc_output/manifest.json
```

#### 2. 生成的证据链清单结构 (`manifest.json`)
```json
{
  "name": "111.doc",
  "saved_path": "sample/111.doc",
  "format": "ole2",
  "real_ext": "doc",
  "mime_type": "application/msword",
  "extractor": "root",
  "offset": 0,
  "size": 367616,
  "sha256": "f49dbb27b5969d6d98f26e59b3925ef60d6d2f5fcff7221ff0f0636852e2d70d",
  "depth": 0,
  "children": [
    {
      "name": "反窃密自查风险评估报告_20260929_143532.pdf",
      "saved_path": "/tmp/doc_output/111.doc.unnested/反窃密自查风险评估报告_20260929_143532.pdf",
      "format": "pdf",
      "real_ext": "pdf",
      "mime_type": "application/pdf",
      "extractor": "Ole2Extractor(MS-CFB)",
      "offset": 0,
      "size": 210168,
      "sha256": "05f19110daf1242d7b7f94306f18b45916870659e2079626ae633556d91fbe6d",
      "depth": 1,
      "associated_icon_path": "/tmp/doc_output/111.doc.unnested/Data_image_3.png",
      "children": []
    }
  ]
}
```

---

## 自动化测试

运行内置的 12 项全套单元测试：
```bash
ctest --test-dir build -V
```

覆盖项目：
1. `test_utils_crypto_and_paths`：SHA-256、路径转义、UTF-8/UTF-16/GB18030 编解码测试。
2. `test_opc_office_filtering`：DOCX 附件过滤与图标关联，DOC (111.doc 与 03_legacy_ole2.doc) 1:1 图标精确匹配。
3. `test_ole2_ministream_and_ole10`：CFB MiniStream 与 Ole10Native 拆解。
4. `test_pdf_flate_attachment`：PDF `/EmbeddedFiles` 与 Flate 展开。
5. `test_asar_and_svg_base64`：Chromium ASAR 与 SVG Base64 提取。
6. `test_psd_smart_object`：Photoshop 智能对象与多层嵌入。
7. `test_carving_polyglot_sfx_pyinstaller`：图种、Linux SFX 复合脚本提取。
8. `test_depth_and_size_limits`：递归深度与体积截断防御性测试。
9. `test_ext1_ext2_ole2_substorage_and_odraw_blips`：OLE2 子存储 CFB 独立重打包与 MS-ODRAW Blip 解码。
10. `test_ext3_ext4_ext5_rtf_onenote_multicarve`：RTF、OneNote 及逻辑尺寸自适应多载荷连续雕刻。
11. `test_gaps1_to_5_pyinstaller_indd_psb_oci_disks`：PyInstaller TOC 逆向、InDesign .indd、Photoshop PSB 64-bit、Docker OCI 及 SquashFS/ISO 镜像。
12. `test_ftype_real_format_identification`：集成 `ftype` 检测伪装文件（如 `.docx` 伪装为 `.pdf`、`.png` 伪装为 `.txt`）、真实后缀与 MIME 关联测试。

---

## 许可证

本项目遵循 MIT 协议开源。
