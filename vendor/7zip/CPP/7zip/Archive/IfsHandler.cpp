// IfsHandler.cpp -- Konami IFS image containers (read-only, raw payloads)

#include "StdAfx.h"

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include "../../Common/ComTry.h"
#include "../../Common/MyBuffer.h"
#include "../../Common/MyString.h"
#include "../../Common/IntToString.h"
#include "../../Common/UTFConvert.h"

#include "Md5.h"

#include "../../Windows/PropVariant.h"
#include "../../Windows/TimeUtils.h"

#include "../Common/LimitedStreams.h"
#include "../Common/ProgressUtils.h"
#include "../Common/RegisterArc.h"
#include "../Common/StreamObjects.h"
#include "../Common/StreamUtils.h"

#include "../Compress/CopyCoder.h"

#include "HandlerCont.h"
#include "IArchive.h"

#include "../../../../kbinxml/KbinXmlDecode.h"

#include "../../../../ifs_tex/IfsTexToPng.h"

using namespace NWindows;

namespace NArchive {
namespace NIfs {

static UInt32 ReadUInt32BE(const Byte *p)
{
  return (UInt32)p[0] << 24 | (UInt32)p[1] << 16 | (UInt32)p[2] << 8 | (UInt32)p[3];
}

static UInt16 ReadUInt16BE(const Byte *p)
{
  return (UInt16)((UInt16)p[0] << 8 | (UInt16)p[1]);
}

static const UInt32 kIfsMagic = 0x6CAD8F89;

struct CItem
{
  UString Path;
  UInt64 Offset;
  UInt64 PackSize;
  UInt64 UnpackSize;
  bool HasUnixMTime;
  Int64 UnixMTime;

  bool TexPng = false;
  bool TexAvslz = false;
  UString TexFormat;
  UInt32 TexW = 0;
  UInt32 TexH = 0;
};

static UString FixIfsName(const UString &tag)
{
  // Match ifstools Node.fix_name: walk left-to-right, map _A.._H / __, and
  // a leading '_' before a digit.
  if (tag == L"_info_" || tag == L"_super_")
    return tag;

  UString fixed = tag;
  unsigned start = 0;
  for (;;)
  {
    int idx = -1;
    for (unsigned i = start; i < fixed.Len(); i++)
    {
      if (fixed[i] == L'_')
      {
        idx = (int)i;
        break;
      }
    }
    if (idx < 0)
      break;
    if ((unsigned)idx + 1 >= fixed.Len())
      break;

    const wchar_t key = fixed[(unsigned)idx + 1];
    wchar_t repl = 0;
    if ((unsigned)idx == 0 && key >= L'0' && key <= L'9')
      repl = key;
    else
    {
      switch (key)
      {
        case L'A': repl = L' '; break;
        case L'B': repl = L'$'; break;
        case L'C': repl = L'+'; break;
        case L'D': repl = L'-'; break;
        case L'E': repl = L'.'; break;
        case L'F': repl = L':'; break;
        case L'G': repl = L'@'; break;
        case L'H': repl = L'~'; break;
        case L'_': repl = L'_'; break;
        default:
          // Invalid escape — leave as-is (ifstools raises; we keep packed form).
          start = (unsigned)idx + 1;
          continue;
      }
    }

    UString next;
    next = fixed.Left((unsigned)idx);
    next += repl;
    next += fixed.Mid((unsigned)idx + 2, fixed.Len() - (unsigned)idx - 2);
    fixed = next;
    start = (unsigned)idx + 1;
  }
  return fixed;
}

static bool ScanS64(const UString &text, unsigned &pos, Int64 &out)
{
  while (pos < text.Len() && text[pos] == L' ')
    pos++;
  if (pos >= text.Len())
    return false;
  bool neg = false;
  if (text[pos] == L'-')
  {
    neg = true;
    pos++;
  }
  if (pos >= text.Len() || text[pos] < L'0' || text[pos] > L'9')
    return false;
  UInt64 v = 0;
  while (pos < text.Len() && text[pos] >= L'0' && text[pos] <= L'9')
  {
    v = v * 10 + (UInt64)(text[pos] - L'0');
    pos++;
  }
  if (neg)
  {
    out = -(Int64)v;
    return true;
  }
  out = (Int64)v;
  return true;
}

// Manifest text: "start size" or "start size unix_time" (ifstools GenericFile.from_xml)
static bool TryParseFileEntryText(const UString &text, Int64 &start, Int64 &size,
    bool &hasUnixMTime, Int64 &unixMTime)
{
  unsigned pos = 0;
  if (!ScanS64(text, pos, start))
    return false;
  if (!ScanS64(text, pos, size))
    return false;
  while (pos < text.Len() && text[pos] == L' ')
    pos++;
  if (pos >= text.Len())
  {
    hasUnixMTime = false;
    return true;
  }
  if (!ScanS64(text, pos, unixMTime))
    return false;
  while (pos < text.Len() && text[pos] == L' ')
    pos++;
  if (pos < text.Len())
    return false;
  hasUnixMTime = true;
  return true;
}

static void CollectIfsFiles(CKbinXmlNode *node, const UString &pathPrefix, UInt64 dataBase,
    UInt64 fileSize, CObjectVector<CItem> &items)
{
  for (unsigned i = 0; i < node->Children.Size(); i++)
  {
    CKbinXmlNode *ch = node->Children[i];
    const UString name = FixIfsName(ch->Tag);
    if (name == L"_info_")
      continue;
    if (name == L"_super_")
      continue;

    const UString fullPath = pathPrefix.IsEmpty()
        ? name
        : (pathPrefix + UString(L"/") + name);

    if (ch->Children.Size() > 0)
    {
      CKbinXmlNode *fc = ch->Children[0];
      if (fc->Tag == L"i")
        continue;
      CollectIfsFiles(ch, fullPath, dataBase, fileSize, items);
      continue;
    }

    Int64 start = 0, size = 0;
    bool hasUnixMTime = false;
    Int64 unixMTime = 0;
    if (!TryParseFileEntryText(ch->Text, start, size, hasUnixMTime, unixMTime))
      continue;
    if (size < 0)
      continue;

    const UInt64 off = dataBase + (UInt64)start;
    const UInt64 sz = (UInt64)size;
    if (off < dataBase)
      continue;
    if (off + sz > fileSize || off + sz < off)
      continue;

    CItem &it = items.AddNew();
    it.Path = fullPath;
    it.Offset = off;
    it.PackSize = sz;
    it.UnpackSize = sz;
    it.HasUnixMTime = hasUnixMTime;
    it.UnixMTime = unixMTime;
  }
}

static bool PathEndsWithSuffixCi(const UString &path, const wchar_t *suffix)
{
  const unsigned slen = MyStringLen(suffix);
  if (path.Len() < slen)
    return false;
  for (unsigned i = 0; i < slen; i++)
  {
    const wchar_t a = path[path.Len() - slen + i];
    const wchar_t b = suffix[i];
    if (MyCharUpper(a) != MyCharUpper(b))
      return false;
  }
  return true;
}

static void SplitParentLeaf(const UString &path, UString &parent, UString &leaf)
{
  const int pos = path.ReverseFind_PathSepar();
  if (pos < 0)
  {
    parent.Empty();
    leaf = path;
    return;
  }
  parent = path.Left((unsigned)pos);
  leaf = path.Mid((unsigned)(pos + 1), path.Len() - (unsigned)pos - 1);
}

static HRESULT ReadItemBlob(IInStream *stream, const CItem &it, CByteBuffer &out);
static bool DecodeXmlBlob(const CByteBuffer &blob, CKbinXmlNode *&rootOut);

static void Utf8StringMd5HexLower(const UString &s, AString &hexOut)
{
  AString utf8;
  ConvertUnicodeToUTF8(s, utf8);
  CMd5 md;
  Md5_Init(&md);
  Md5_Update(&md, (const Byte *)(const char *)utf8, utf8.Len());
  Byte digest[MD5_DIGEST_SIZE];
  Md5_Final(&md, digest);
  char buf[MD5_DIGEST_SIZE * 2 + 1];
  ConvertDataToHex_Lower(buf, digest, MD5_DIGEST_SIZE);
  buf[MD5_DIGEST_SIZE * 2] = 0;
  hexOut = buf;
}

static bool FindAttrVal(const CKbinXmlNode *n, const wchar_t *key, UString &out)
{
  for (unsigned i = 0; i < n->Attrs.Size(); i++)
  {
    if (MyStringCompareNoCase(n->Attrs[i].Key, key) == 0)
    {
      out = n->Attrs[i].Val;
      return true;
    }
  }
  return false;
}

// O(1) MD5 leaf lookup: key is "parent_lower\\nleaf_lower" -> item index, or -2 if ambiguous.
struct CMd5LeafIndex
{
  std::unordered_map<std::string, int> Map;

  static void AppendUStringLowerAscii(std::string &out, const UString &s)
  {
    for (unsigned i = 0; i < s.Len(); i++)
    {
      wchar_t c = s[i];
      if (c >= L'A' && c <= L'Z')
        c = (wchar_t)(c - L'A' + L'a');
      out.push_back((char)(unsigned char)c);
    }
  }

  static void AppendAString(std::string &out, const AString &s)
  {
    out.append((const char *)s, s.Len());
  }

  static std::string MakeKeyFromU(const UString &parentLower, const UString &leafLower)
  {
    std::string key;
    key.reserve((size_t)parentLower.Len() + 1 + (size_t)leafLower.Len());
    AppendUStringLowerAscii(key, parentLower);
    key.push_back('\n');
    AppendUStringLowerAscii(key, leafLower);
    return key;
  }

  static std::string MakeKey(const UString &parentLower, const AString &leafLowerAscii)
  {
    std::string key;
    key.reserve((size_t)parentLower.Len() + 1 + (size_t)leafLowerAscii.Len());
    AppendUStringLowerAscii(key, parentLower);
    key.push_back('\n');
    AppendAString(key, leafLowerAscii);
    return key;
  }

  void Build(const CObjectVector<CItem> &items)
  {
    Map.clear();
    Map.reserve((size_t)items.Size());
    for (unsigned i = 0; i < items.Size(); i++)
    {
      UString parent, leaf;
      SplitParentLeaf(items[i].Path, parent, leaf);
      parent.MakeLower_Ascii();
      leaf.MakeLower_Ascii();
      const std::string key = MakeKeyFromU(parent, leaf);
      const std::unordered_map<std::string, int>::iterator it = Map.find(key);
      if (it == Map.end())
        Map.emplace(key, (int)i);
      else
        it->second = -2;
    }
  }

  int LookupExact(const UString &parentLower, const AString &leafLowerAscii) const
  {
    const std::unordered_map<std::string, int>::const_iterator it =
        Map.find(MakeKey(parentLower, leafLowerAscii));
    if (it == Map.end())
      return -1;
    return it->second;
  }

  // parentEqualsCi: exact parent (e.g. L"afp"). Else parent folder is dirPrefix
  // (tex / geo / afp/bsi — flat IFS layout; same as PathHasDirPrefix for those).
  int Find(const wchar_t *parentEqualsCi, const UString &dirPrefix,
      const AString &hashHexLower, bool allowLegacyPng) const
  {
    UString parent;
    if (parentEqualsCi)
      parent = parentEqualsCi;
    else
      parent = dirPrefix;
    parent.MakeLower_Ascii();

    AString hash = hashHexLower;
    hash.MakeLower_Ascii();

    const int a = LookupExact(parent, hash);
    if (!allowLegacyPng)
      return a;

    AString pngLeaf = hash;
    pngLeaf += ".png";
    const int b = LookupExact(parent, pngLeaf);
    if (a == -2 || b == -2)
      return -2;
    if (a >= 0 && b >= 0 && a != b)
      return -2;
    if (a >= 0)
      return a;
    return b;
  }
};

static void ProcessTexImages(CKbinXmlNode *node, const UString &texDir,
    CObjectVector<CItem> &items, const CMd5LeafIndex &index)
{
  if (FixIfsName(node->Tag) == L"image")
  {
    UString nameVal;
    if (FindAttrVal(node, L"name", nameVal))
    {
      AString md5hex;
      Utf8StringMd5HexLower(nameVal, md5hex);
      const int idx = index.Find(NULL, texDir, md5hex, true);
      if (idx >= 0)
        items[(unsigned)idx].Path = texDir + UString(L"/") + nameVal + UString(L".png");
    }
  }
  for (unsigned i = 0; i < node->Children.Size(); i++)
    ProcessTexImages(node->Children[i], texDir, items, index);
}

static void ProcessAfpList(CKbinXmlNode *node, CObjectVector<CItem> &items,
    const CMd5LeafIndex &index)
{
  if (FixIfsName(node->Tag) == L"afp")
  {
    UString afpName;
    if (FindAttrVal(node, L"name", afpName))
    {
      AString md5hex;
      Utf8StringMd5HexLower(afpName, md5hex);
      const int rootIdx = index.Find(L"afp", UString(), md5hex, false);
      if (rootIdx >= 0)
        items[(unsigned)rootIdx].Path = UString(L"afp/") + afpName;
      const int idx = index.Find(NULL, UString(L"afp/bsi"), md5hex, false);
      if (idx >= 0)
        items[(unsigned)idx].Path = UString(L"afp/bsi/") + afpName;

      for (unsigned ci = 0; ci < node->Children.Size(); ci++)
      {
        CKbinXmlNode *ch = node->Children[ci];
        if (FixIfsName(ch->Tag) != L"geo")
          continue;
        unsigned pos = 0;
        for (;;)
        {
          while (pos < ch->Text.Len() && ch->Text[pos] == L' ')
            pos++;
          if (pos >= ch->Text.Len())
            break;
          Int64 shape = 0;
          if (!ScanS64(ch->Text, pos, shape))
            break;
          UString plain = afpName + UString(L"_shape");
          wchar_t shapeStr[32];
          ConvertInt64ToString(shape, shapeStr);
          plain += shapeStr;
          AString ghash;
          Utf8StringMd5HexLower(plain, ghash);
          const int gidx = index.Find(NULL, UString(L"geo"), ghash, false);
          if (gidx >= 0)
            items[(unsigned)gidx].Path = UString(L"geo/") + afpName + UString(L"_shape") + UString(shapeStr);
        }
      }
    }
  }
  for (unsigned i = 0; i < node->Children.Size(); i++)
    ProcessAfpList(node->Children[i], items, index);
}

static CKbinXmlNode *FindChildByFixTagName(CKbinXmlNode *parent, const wchar_t *want)
{
  for (unsigned i = 0; i < parent->Children.Size(); i++)
  {
    CKbinXmlNode *ch = parent->Children[i];
    if (FixIfsName(ch->Tag) == want)
      return ch;
  }
  return NULL;
}

static bool ParseImgRectDimensions(CKbinXmlNode *imageNode, UInt32 &outW, UInt32 &outH)
{
  CKbinXmlNode *rect = FindChildByFixTagName(imageNode, L"imgrect");
  if (!rect)
    return false;
  unsigned pos = 0;
  Int64 v[4];
  for (unsigned i = 0; i < 4; i++)
  {
    if (!ScanS64(rect->Text, pos, v[i]))
      return false;
  }
  const Int64 a0 = v[0] / 2;
  const Int64 a1 = v[1] / 2;
  const Int64 a2 = v[2] / 2;
  const Int64 a3 = v[3] / 2;
  const Int64 dw = a1 - a0;
  const Int64 dh = a3 - a2;
  if (dw <= 0 || dh <= 0)
    return false;
  outW = (UInt32)dw;
  outH = (UInt32)dh;
  return true;
}

struct CTexListEntry
{
  UString ImageName;
  UString Format;
  UInt32 W;
  UInt32 H;
};

static CKbinXmlNode *FindTextureListRoot(CKbinXmlNode *root)
{
  if (!root)
    return NULL;
  if (FixIfsName(root->Tag) == L"texturelist")
    return root;
  for (unsigned i = 0; i < root->Children.Size(); i++)
  {
    CKbinXmlNode *ch = root->Children[i];
    if (FixIfsName(ch->Tag) == L"texturelist")
      return ch;
  }
  return NULL;
}

static void CollectTextureListMeta(CKbinXmlNode *root, UString &compressOut,
    CObjectVector<CTexListEntry> &entriesOut)
{
  CKbinXmlNode *tl = FindTextureListRoot(root);
  if (!tl)
    return;
  compressOut.Empty();
  FindAttrVal(tl, L"compress", compressOut);

  for (unsigned ti = 0; ti < tl->Children.Size(); ti++)
  {
    CKbinXmlNode *texNode = tl->Children[ti];
    if (FixIfsName(texNode->Tag) != L"texture")
      continue;
    UString format;
    if (!FindAttrVal(texNode, L"format", format))
      continue;

    for (unsigned ii = 0; ii < texNode->Children.Size(); ii++)
    {
      CKbinXmlNode *im = texNode->Children[ii];
      if (FixIfsName(im->Tag) != L"image")
        continue;
      UString nameVal;
      if (!FindAttrVal(im, L"name", nameVal))
        continue;
      UInt32 w = 0, h = 0;
      if (!ParseImgRectDimensions(im, w, h))
        continue;

      CTexListEntry &e = entriesOut.AddNew();
      e.ImageName = nameVal;
      e.Format = format;
      e.W = w;
      e.H = h;
    }
  }
}

static HRESULT ApplyIfsTexMetadata(IInStream *stream, CObjectVector<CItem> &items)
{
  for (unsigned ti = 0; ti < items.Size(); ti++)
  {
    if (!PathEndsWithSuffixCi(items[ti].Path, L"texturelist.xml"))
      continue;

    UString parent, leaf;
    SplitParentLeaf(items[ti].Path, parent, leaf);
    if (MyStringCompareNoCase(parent, L"tex") != 0)
      continue;

    CByteBuffer blob;
    RINOK(ReadItemBlob(stream, items[ti], blob))
    CKbinXmlNode *tlRoot = NULL;
    if (!DecodeXmlBlob(blob, tlRoot))
      continue;
    std::unique_ptr<CKbinXmlNode> tlOwner(tlRoot);

    UString compress;
    CObjectVector<CTexListEntry> entries;
    CollectTextureListMeta(tlRoot, compress, entries);

    const bool avslz = (MyStringCompareNoCase(compress, L"avslz") == 0);

    for (unsigned j = 0; j < items.Size(); j++)
    {
      CItem &it = items[j];
      UString pp, lf;
      SplitParentLeaf(it.Path, pp, lf);
      if (MyStringCompareNoCase(pp, L"tex") != 0)
        continue;
      if (!PathEndsWithSuffixCi(lf, L".png"))
        continue;

      UString stem = lf;
      if (stem.Len() >= 4 && PathEndsWithSuffixCi(stem, L".png"))
        stem.DeleteFrom(stem.Len() - 4);

      for (unsigned k = 0; k < entries.Size(); k++)
      {
        if (entries[k].ImageName.IsEmpty())
          continue;
        if (MyStringCompareNoCase(stem, entries[k].ImageName) != 0)
          continue;
        const UString &fmt = entries[k].Format;
        if (!fmt.IsEqualTo_NoCase(L"argb8888rev")
            && !fmt.IsEqualTo_NoCase(L"argb4444")
            && !fmt.IsEqualTo_NoCase(L"dxt1")
            && !fmt.IsEqualTo_NoCase(L"bc1")
            && !fmt.IsEqualTo_NoCase(L"dxt5")
            && !fmt.IsEqualTo_NoCase(L"bc3"))
          continue;

        it.TexPng = true;
        it.TexAvslz = avslz;
        it.TexFormat = entries[k].Format;
        it.TexW = entries[k].W;
        it.TexH = entries[k].H;
        break;
      }
    }

    break;
  }

  return S_OK;
}

static HRESULT ReadItemBlob(IInStream *stream, const CItem &it, CByteBuffer &out)
{
  out.Alloc((size_t)it.PackSize);
  RINOK(InStream_SeekSet(stream, it.Offset))
  return ReadStream_FAIL(stream, out, (size_t)it.PackSize);
}

static bool DecodeXmlBlob(const CByteBuffer &blob, CKbinXmlNode *&rootOut)
{
  // Binary first; on failure try plaintext with trailing-NUL strip (LovePlus /
  // uncompressed manifests). UTF-8 MD5 via Utf8StringMd5HexLower matches
  // ifstools encoding_override='utf8' when the tree does decode.
  if (KbinXmlIsBinaryXml(blob, blob.Size()))
  {
    if (KbinXmlDecodeFromBinary(blob, blob.Size(), rootOut) && rootOut)
      return true;
    rootOut = NULL;
  }
  size_t n = blob.Size();
  const Byte *p = blob;
  while (n > 0 && p[n - 1] == 0)
    n--;
  if (n == 0)
    return false;
  return KbinXmlDecodeFromPlainXml(p, n, rootOut) && rootOut != NULL;
}

static HRESULT ApplyIfsMd5Renames(IInStream *stream, CObjectVector<CItem> &items)
{
  CMd5LeafIndex index;
  index.Build(items);

  for (unsigned i = 0; i < items.Size(); i++)
  {
    if (!PathEndsWithSuffixCi(items[i].Path, L"texturelist.xml"))
      continue;
    UString parent, leaf;
    SplitParentLeaf(items[i].Path, parent, leaf);
    if (MyStringCompareNoCase(parent, L"tex") != 0)
      continue;

    CByteBuffer blob;
    RINOK(ReadItemBlob(stream, items[i], blob))
    CKbinXmlNode *root = NULL;
    if (!DecodeXmlBlob(blob, root))
      continue;
    std::unique_ptr<CKbinXmlNode> rootOwner(root);
    ProcessTexImages(root, UString(L"tex"), items, index);
  }

  for (unsigned i = 0; i < items.Size(); i++)
  {
    if (!PathEndsWithSuffixCi(items[i].Path, L"afplist.xml"))
      continue;
    UString parent, leaf;
    SplitParentLeaf(items[i].Path, parent, leaf);
    if (MyStringCompareNoCase(parent, L"afp") != 0)
      continue;

    CByteBuffer blob;
    RINOK(ReadItemBlob(stream, items[i], blob))
    CKbinXmlNode *root = NULL;
    if (!DecodeXmlBlob(blob, root))
      continue;
    std::unique_ptr<CKbinXmlNode> rootOwner(root);
    ProcessAfpList(root, items, index);
  }

  return S_OK;
}

Z7_class_CHandler_final: public CHandlerCont
{
  Z7_IFACE_COM7_IMP(IInArchive_Cont)

  CObjectVector<CItem> _items;
  UInt64 _fileSize;
  UInt32 _arcUnixTime;

  HRESULT Open2(IInStream *stream, IArchiveOpenCallback *openCallback);

  virtual int GetItem_ExtractInfo(UInt32 index, UInt64 &pos, UInt64 &size) const Z7_override
  {
    if (index >= _items.Size())
      return NExtract::NOperationResult::kDataError;
    const CItem &item = _items[index];
    pos = item.Offset;
    size = item.UnpackSize;
    return NExtract::NOperationResult::kOK;
  }

  virtual HRESULT CreateItemInStream(UInt32 index, UInt64 pos, UInt64 size, ISequentialInStream **stream) Z7_override
  {
    *stream = NULL;
    if (index >= _items.Size())
      return S_FALSE;
    const CItem &item = _items[index];
    if (pos != item.Offset || size != item.UnpackSize)
      return S_FALSE;

    if (item.TexPng)
    {
      // Encode on demand (Open no longer caches PNGs). Used by GetStream /
      // single-file preview; bulk Extract uses the pipelined path below.
      if (item.PackSize == 0)
      {
        Create_BufInStream_WithNewBuffer(NULL, 0, stream);
        return S_OK;
      }
      CByteBuffer packed;
      packed.Alloc((size_t)item.PackSize);
      RINOK(InStream_SeekSet(_stream, item.Offset))
      RINOK(ReadStream_FAIL(_stream, packed, (size_t)item.PackSize))
      CByteBuffer pngOut;
      if (!IfsTexRawToPngBuffer(packed, packed.Size(), item.TexAvslz,
              item.TexFormat, item.TexW, item.TexH, pngOut))
        return S_FALSE;
      Create_BufInStream_WithNewBuffer(pngOut, pngOut.Size(), stream);
      return S_OK;
    }

    if (item.PackSize == 0)
    {
      Create_BufInStream_WithNewBuffer(NULL, 0, stream);
      return S_OK;
    }

    // Detect binary kbin on read (Open no longer expands every XML for Size).
    Byte magic[2];
    if (item.PackSize >= 2)
    {
      RINOK(InStream_SeekSet(_stream, item.Offset))
      RINOK(ReadStream_FAIL(_stream, magic, 2))
      if (KbinXmlIsBinaryXml(magic, 2))
      {
        CByteBuffer packed;
        packed.Alloc((size_t)item.PackSize);
        RINOK(InStream_SeekSet(_stream, item.Offset))
        RINOK(ReadStream_FAIL(_stream, packed, (size_t)item.PackSize))

        CKbinXmlNode *root = NULL;
        if (!KbinXmlDecodeFromBinary(packed, packed.Size(), root) || !root)
          return S_FALSE;
        std::unique_ptr<CKbinXmlNode> rootOwner(root);
        CByteBuffer utf8;
        if (!KbinXmlTreeToUtf8Text(root, utf8))
          return S_FALSE;
        Create_BufInStream_WithNewBuffer(utf8, utf8.Size(), stream);
        return S_OK;
      }
    }

    return CreateLimitedInStream(_stream, item.Offset, item.PackSize, stream);
  }

  Z7_COM7F_IMP(Extract(const UInt32 *indices, UInt32 numItems, Int32 testMode,
      IArchiveExtractCallback *extractCallback))
};

static const Byte kProps[] =
{
  kpidPath,
  kpidSize,
  kpidPackSize,
  kpidMTime
};

static const Byte kArcProps[] =
{
  kpidPhySize,
  kpidMTime
};

IMP_IInArchive_Props
IMP_IInArchive_ArcProps

Z7_COM7F_IMF(CHandler::GetArchiveProperty(PROPID propID, PROPVARIANT *value))
{
  NCOM::CPropVariant prop;
  switch (propID)
  {
    case kpidPhySize: prop = _fileSize; break;
    case kpidMTime:
    {
      FILETIME ft;
      if (NTime::UnixTime64_To_FileTime((Int64)(UInt64)_arcUnixTime, ft))
        prop.SetAsTimeFrom_FT_Prec(ft, k_PropVar_TimePrec_Unix);
      break;
    }
    default: break;
  }
  prop.Detach(value);
  return S_OK;
}

Z7_COM7F_IMF(CHandler::GetProperty(UInt32 index, PROPID propID, PROPVARIANT *value))
{
  NCOM::CPropVariant prop;
  if (index < _items.Size())
  {
    const CItem &item = _items[index];
    switch (propID)
    {
      case kpidPath: prop = item.Path; break;
      case kpidSize: prop = item.UnpackSize; break;
      case kpidPackSize: prop = item.PackSize; break;
      case kpidMTime:
      {
        if (item.HasUnixMTime && item.UnixMTime >= 0)
        {
          FILETIME ft;
          if (NTime::UnixTime64_To_FileTime(item.UnixMTime, ft))
            prop.SetAsTimeFrom_FT_Prec(ft, k_PropVar_TimePrec_Unix);
        }
        break;
      }
      default: break;
    }
  }
  prop.Detach(value);
  return S_OK;
}

HRESULT CHandler::Open2(IInStream *stream, IArchiveOpenCallback *openCallback)
{
  _items.Clear();
  _fileSize = 0;
  _arcUnixTime = 0;

  RINOK(InStream_GetSize_SeekToBegin(stream, _fileSize))
  if (_fileSize < 20)
    return S_FALSE;

  Byte hdr[36];
  RINOK(ReadStream_FAIL(stream, hdr, 20))

  if (ReadUInt32BE(hdr) != kIfsMagic)
    return S_FALSE;

  // ifstools: header u16 is IFSFlags bitfield, not a version number.
  const UInt16 flags = ReadUInt16BE(hdr + 4);
  const UInt16 flagsInv = ReadUInt16BE(hdr + 6);
  if ((UInt16)(flags ^ flagsInv) != 0xFFFF)
    return S_FALSE;

  static const UInt16 kIfsFlag_HasMD5 = 2;

  _arcUnixTime = ReadUInt32BE(hdr + 8);
  /* UInt32 treeSize = */ ReadUInt32BE(hdr + 12);
  const UInt32 manifestEnd = ReadUInt32BE(hdr + 16);

  size_t headerEnd = 20;
  if ((flags & kIfsFlag_HasMD5) != 0)
  {
    if (_fileSize < 36)
      return S_FALSE;
    RINOK(ReadStream_FAIL(stream, hdr + 20, 16))
    headerEnd = 36;
  }

  if (manifestEnd > _fileSize || (UInt64)manifestEnd < headerEnd)
    return S_FALSE;

  const UInt64 dataBase = (UInt64)manifestEnd;
  const size_t manifestLen = (size_t)((UInt64)manifestEnd - (UInt64)headerEnd);
  if (manifestLen > _fileSize || manifestLen == 0)
    return S_FALSE;

  CByteBuffer manifest;
  manifest.Alloc(manifestLen);
  RINOK(InStream_SeekSet(stream, (UInt64)headerEnd))
  RINOK(ReadStream_FAIL(stream, manifest, manifestLen))

  CKbinXmlNode *root = NULL;
  if (!KbinXmlDecodeAuto(manifest, manifest.Size(), root) || !root)
    return S_FALSE;
  std::unique_ptr<CKbinXmlNode> rootOwner(root);

  CollectIfsFiles(root, UString(), dataBase, _fileSize, _items);
  rootOwner.reset();

  // UnpackSize stays PackSize for listing (tex PNG and kbin UTF-8 expand on
  // Extract / GetStream). Avoid reading every .xml blob during Open.
  RINOK(ApplyIfsMd5Renames(stream, _items))
  RINOK(ApplyIfsTexMetadata(stream, _items))

  return _items.IsEmpty() ? (HRESULT)S_FALSE : S_OK;
}

Z7_COM7F_IMF(CHandler::Extract(const UInt32 *indices, UInt32 numItems,
    Int32 testMode, IArchiveExtractCallback *extractCallback))
{
  COM_TRY_BEGIN
  const bool allFilesMode = (numItems == (UInt32)(Int32)-1);
  if (allFilesMode)
  {
    RINOK(GetNumberOfItems(&numItems))
  }
  if (numItems == 0)
    return S_OK;

  // Progress total: packed bytes (tex UnpackSize is a pack-size placeholder).
  UInt64 totalSize = 0;
  for (UInt32 i = 0; i < numItems; i++)
  {
    const UInt32 index = allFilesMode ? i : indices[i];
    if (index < _items.Size())
      totalSize += _items[index].PackSize;
  }
  RINOK(extractCallback->SetTotal(totalSize))

  CMyComPtr2_Create<ICompressProgressInfo, CLocalProgress> lps;
  lps->Init(extractCallback, false);
  CMyComPtr2_Create<ICompressCoder, NCompress::CCopyCoder> copyCoder;

  // Prefetch window: encode the next N textures on workers while the main
  // thread writes earlier results in order.
  unsigned window = (unsigned)std::thread::hardware_concurrency();
  if (window == 0)
    window = 4;
  window = (std::min)(window, 8u);
  window = (std::max)(window, 1u);

  struct TexSlot
  {
    bool Active;
    bool Done;
    bool Ok;
    CByteBuffer Png;
    TexSlot(): Active(false), Done(false), Ok(false) {}
  };

  std::vector<TexSlot> slots((size_t)numItems);
  std::mutex mtx;
  std::condition_variable cv;
  std::atomic<bool> abortFlag(false);

  // Pre-read packed blobs on this thread; hand to workers.
  struct Prefetch
  {
    bool Needed;
    bool Ready;
    CByteBuffer Raw;
    Prefetch(): Needed(false), Ready(false) {}
  };
  std::vector<Prefetch> pref((size_t)numItems);
  for (UInt32 i = 0; i < numItems; i++)
  {
    const UInt32 index = allFilesMode ? i : indices[i];
    if (index >= _items.Size())
      continue;
    const CItem &item = _items[index];
    if (item.TexPng)
      pref[(size_t)i].Needed = true;
  }

  std::atomic<UInt32> nextPrefetch(0);
  std::mutex prefMtx;

  auto ensurePrefetched = [&](UInt32 upToExclusive) -> HRESULT
  {
    for (;;)
    {
      UInt32 i = nextPrefetch.load(std::memory_order_relaxed);
      if (i >= upToExclusive || i >= numItems)
        break;
      if (!nextPrefetch.compare_exchange_weak(i, i + 1, std::memory_order_relaxed))
        continue;
      if (!pref[(size_t)i].Needed)
        continue;
      const UInt32 index = allFilesMode ? i : indices[i];
      const CItem &item = _items[index];
      CByteBuffer raw;
      if (item.PackSize != 0)
      {
        raw.Alloc((size_t)item.PackSize);
        RINOK(InStream_SeekSet(_stream, item.Offset))
        RINOK(ReadStream_FAIL(_stream, raw, (size_t)item.PackSize))
      }
      {
        std::lock_guard<std::mutex> lock(prefMtx);
        pref[(size_t)i].Raw = raw;
        pref[(size_t)i].Ready = true;
      }
      cv.notify_all();
    }
    return S_OK;
  };

  std::atomic<UInt32> nextToEncode(0);
  const unsigned numWorkers = window;

  auto workerFn = [&]()
  {
    for (;;)
    {
      if (abortFlag.load(std::memory_order_relaxed))
        break;
      const UInt32 i = nextToEncode.fetch_add(1, std::memory_order_relaxed);
      if (i >= numItems)
        break;
      if (!pref[(size_t)i].Needed)
        continue;

      // Wait until main thread has prefetched this slot's raw bytes.
      {
        std::unique_lock<std::mutex> lock(prefMtx);
        cv.wait(lock, [&]() {
          return abortFlag.load(std::memory_order_relaxed) || pref[(size_t)i].Ready;
        });
      }
      if (abortFlag.load(std::memory_order_relaxed))
        break;

      const UInt32 index = allFilesMode ? i : indices[i];
      const CItem &item = _items[index];
      CByteBuffer raw;
      {
        std::lock_guard<std::mutex> lock(prefMtx);
        raw = pref[(size_t)i].Raw;
        pref[(size_t)i].Raw.Free();
      }

      CByteBuffer png;
      bool ok = true;
      if (item.PackSize != 0)
        ok = IfsTexRawToPngBuffer(raw, raw.Size(), item.TexAvslz,
            item.TexFormat, item.TexW, item.TexH, png);
      raw.Free();

      {
        std::lock_guard<std::mutex> lock(mtx);
        slots[(size_t)i].Active = true;
        slots[(size_t)i].Ok = ok;
        slots[(size_t)i].Png = png;
        slots[(size_t)i].Done = true;
      }
      cv.notify_all();
    }
  };

  // Kick prefetch for the first window, then start workers.
  RINOK(ensurePrefetched((std::min)(numItems, (UInt32)window)))

  std::vector<std::thread> workers;
  workers.reserve((size_t)numWorkers);
  for (unsigned w = 0; w < numWorkers; w++)
    workers.emplace_back(workerFn);

  UInt64 completedPack = 0;
  HRESULT failHr = S_OK;

  for (UInt32 i = 0; i < numItems; i++)
  {
    // Keep prefetch window ahead of the write cursor.
    {
      const UInt32 ahead = i + (UInt32)window + 1;
      const HRESULT phr = ensurePrefetched((std::min)(numItems, ahead));
      if (phr != S_OK)
      {
        failHr = phr;
        abortFlag.store(true, std::memory_order_relaxed);
        cv.notify_all();
        break;
      }
    }

    lps->InSize = completedPack;
    lps->OutSize = completedPack;
    {
      const HRESULT phr = lps->SetCur();
      if (phr != S_OK)
      {
        failHr = phr;
        abortFlag.store(true, std::memory_order_relaxed);
        cv.notify_all();
        break;
      }
    }

    CMyComPtr<ISequentialOutStream> outStream;
    const Int32 askMode = testMode ?
        NExtract::NAskMode::kTest :
        NExtract::NAskMode::kExtract;
    const UInt32 index = allFilesMode ? i : indices[i];

    {
      const HRESULT phr = extractCallback->GetStream(index, &outStream, askMode);
      if (phr != S_OK)
      {
        failHr = phr;
        abortFlag.store(true, std::memory_order_relaxed);
        cv.notify_all();
        break;
      }
    }

    int opRes = NExtract::NOperationResult::kDataError;
    UInt64 packForProgress = 0;
    if (index < _items.Size())
      packForProgress = _items[index].PackSize;
    completedPack += packForProgress;

    if (!testMode && !outStream)
    {
      // Skip write but still wait for any in-flight encode to free memory.
      if (index < _items.Size() && _items[index].TexPng)
      {
        std::unique_lock<std::mutex> lock(mtx);
        cv.wait(lock, [&]() {
          return abortFlag.load(std::memory_order_relaxed) || slots[(size_t)i].Done;
        });
        slots[(size_t)i].Png.Free();
      }
      continue;
    }

    {
      const HRESULT phr = extractCallback->PrepareOperation(askMode);
      if (phr != S_OK)
      {
        failHr = phr;
        abortFlag.store(true, std::memory_order_relaxed);
        cv.notify_all();
        break;
      }
    }

    if (index >= _items.Size())
    {
      RINOK(extractCallback->SetOperationResult(opRes))
      continue;
    }

    const CItem &item = _items[index];

    if (item.TexPng)
    {
      {
        std::unique_lock<std::mutex> lock(mtx);
        cv.wait(lock, [&]() {
          return abortFlag.load(std::memory_order_relaxed) || slots[(size_t)i].Done;
        });
      }
      if (abortFlag.load(std::memory_order_relaxed) && !slots[(size_t)i].Done)
        break;

      if (!slots[(size_t)i].Ok)
        opRes = NExtract::NOperationResult::kDataError;
      else
      {
        CMyComPtr<ISequentialInStream> inStream;
        Create_BufInStream_WithReference(slots[(size_t)i].Png, slots[(size_t)i].Png.Size(),
            NULL, &inStream);
        const HRESULT codeHr = copyCoder.Interface()->Code(inStream, outStream, NULL, NULL, lps);
        const UInt64 wrote = copyCoder->TotalSize;
        slots[(size_t)i].Png.Free();
        if (codeHr != S_OK)
          opRes = NExtract::NOperationResult::kDataError;
        else if (wrote == 0 && item.PackSize != 0)
          opRes = NExtract::NOperationResult::kDataError;
        else
          opRes = NExtract::NOperationResult::kOK;
      }
    }
    else
    {
      CMyComPtr<ISequentialInStream> inStream;
      const HRESULT cr = CreateItemInStream(index, item.Offset, item.UnpackSize, &inStream);
      if (cr != S_OK || !inStream)
        opRes = NExtract::NOperationResult::kDataError;
      else
      {
        const HRESULT codeHr = copyCoder.Interface()->Code(inStream, outStream, NULL, NULL, lps);
        // UnpackSize may be a pack-size placeholder for binary kbin; accept
        // whatever length the decode/copy actually wrote.
        if (codeHr != S_OK)
          opRes = NExtract::NOperationResult::kDataError;
        else
          opRes = NExtract::NOperationResult::kOK;
      }
    }

    outStream.Release();
    {
      const HRESULT phr = extractCallback->SetOperationResult(opRes);
      if (phr != S_OK)
      {
        failHr = phr;
        abortFlag.store(true, std::memory_order_relaxed);
        cv.notify_all();
        break;
      }
    }
  }

  abortFlag.store(true, std::memory_order_relaxed);
  cv.notify_all();
  for (size_t w = 0; w < workers.size(); w++)
    workers[w].join();

  if (failHr != S_OK)
    return failHr;
  return S_OK;
  COM_TRY_END
}

Z7_COM7F_IMF(CHandler::Open(IInStream *inStream,
    const UInt64 * /* maxCheckStartPosition */,
    IArchiveOpenCallback *openArchiveCallback))
{
  COM_TRY_BEGIN
  Close();
  try
  {
    const HRESULT res = Open2(inStream, openArchiveCallback);
    if (res != S_OK)
      return res;
    _stream = inStream;
  }
  catch (...)
  {
    return S_FALSE;
  }
  return S_OK;
  COM_TRY_END
}

Z7_COM7F_IMF(CHandler::Close())
{
  _stream.Release();
  _items.Clear();
  _fileSize = 0;
  _arcUnixTime = 0;
  return S_OK;
}

Z7_COM7F_IMF(CHandler::GetNumberOfItems(UInt32 *numItems))
{
  *numItems = _items.Size();
  return S_OK;
}

static const Byte k_Signature[] =
{
  0x6C, 0xAD, 0x8F, 0x89
};

API_FUNC_static_IsArc IsArc_Ifs(const Byte *p, size_t size)
{
  if (size < 4)
    return k_IsArc_Res_NEED_MORE;
  if (p[0] == 0x6C && p[1] == 0xAD && p[2] == 0x8F && p[3] == 0x89)
    return k_IsArc_Res_YES;
  return k_IsArc_Res_NO;
}
}

REGISTER_ARC_I(
    "IFS",
    "ifs",
    NULL,
    0xC1,
    k_Signature,
    0,
    0,
    IsArc_Ifs)

}}
