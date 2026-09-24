// ArcHandler.cpp -- DDR/Konami-style .arc (LZ77-compressed payloads, read-only)

#include "StdAfx.h"

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <mutex>
#include <thread>
#include <vector>

#include "../../Common/ComTry.h"
#include "../../Common/MyString.h"
#include "../../Common/UTFConvert.h"

#include "../../Windows/PropVariant.h"

#include "../Common/LimitedStreams.h"
#include "../Common/ProgressUtils.h"
#include "../Common/RegisterArc.h"
#include "../Common/StreamObjects.h"
#include "../Common/StreamUtils.h"

#include "../Compress/CopyCoder.h"

#include "HandlerCont.h"

#include "DdrLz77.h"

using namespace NWindows;

namespace NArchive {
namespace NArc {

static UInt32 ReadUInt32LE(const Byte *p)
{
  return (UInt32)p[0]
      | ((UInt32)p[1] << 8)
      | ((UInt32)p[2] << 16)
      | ((UInt32)p[3] << 24);
}

static const UInt32 kDdrArcMagic = 0x19751120;

struct CItem
{
  UString Path;
  UInt64 PackOffset;
  UInt64 PackSize;
  UInt64 UnpackSize;
};

static void NormalizePath(UString &s)
{
  for (;;)
  {
    if (s.IsEmpty())
      break;
    const wchar_t c = s[0];
    if (c == L'.' || c == L'\\')
      s.DeleteFrontal(1);
    else
      break;
  }
  s.Replace(L'\\', L'/');
}

static HRESULT ReadUtf8PathAt(IInStream *stream, UInt64 strOffset, UInt64 fileSize, UString &path)
{
  if (strOffset >= fileSize)
    return S_FALSE;
  RINOK(InStream_SeekSet(stream, strOffset))
  AString a;
  for (;;)
  {
    Byte b = 0;
    RINOK(ReadStream_FAIL(stream, &b, 1))
    if (b == 0)
      break;
    a += (char)b;
    if (a.Len() > 4096)
      return S_FALSE;
  }
  if (!ConvertUTF8ToUnicode(a, path))
    path.Empty();
  return S_OK;
}

Z7_class_CHandler_final: public CHandlerCont
{
  Z7_IFACE_COM7_IMP(IInArchive_Cont)

  CObjectVector<CItem> _items;
  UInt64 _fileSize;

  HRESULT Open2(IInStream *stream);

  virtual int GetItem_ExtractInfo(UInt32 index, UInt64 &pos, UInt64 &size) const Z7_override
  {
    if (index >= _items.Size())
      return NExtract::NOperationResult::kDataError;
    const CItem &item = _items[index];
    pos = item.PackOffset;
    size = item.UnpackSize;
    return NExtract::NOperationResult::kOK;
  }

  virtual HRESULT CreateItemInStream(UInt32 index, UInt64 pos, UInt64 size, ISequentialInStream **stream) Z7_override
  {
    *stream = NULL;
    if (index >= _items.Size())
      return S_FALSE;
    const CItem &item = _items[index];
    if (pos != item.PackOffset || size != item.UnpackSize)
      return S_FALSE;

    if (item.PackSize == 0)
    {
      if (item.UnpackSize != 0)
        return S_FALSE;
      Create_BufInStream_WithNewBuffer(NULL, 0, stream);
      return S_OK;
    }

    // Stored payload: stream the packed bytes. LZ77 stays a one-file decode for
    // GetStream / preview; bulk Extract pipelines it below.
    if (item.PackSize == item.UnpackSize)
      return CreateLimitedInStream(_stream, item.PackOffset, item.PackSize, stream);

    CByteBuffer packed;
    packed.Alloc((size_t)item.PackSize);
    RINOK(InStream_SeekSet(_stream, item.PackOffset))
    RINOK(ReadStream_FAIL(_stream, packed, (size_t)item.PackSize))

    std::vector<uint8_t> dec = util::lz77::decompress(packed, (size_t)item.PackSize,
        (size_t)item.UnpackSize);
    if (dec.size() != (size_t)item.UnpackSize)
      return S_FALSE;
    Create_BufInStream_WithNewBuffer(dec.empty() ? NULL : &dec[0], dec.size(), stream);
    return S_OK;
  }

  Z7_COM7F_IMP(Extract(const UInt32 *indices, UInt32 numItems, Int32 testMode,
      IArchiveExtractCallback *extractCallback))
};

static const Byte kProps[] =
{
  kpidPath,
  kpidSize,
  kpidPackSize
};

static const Byte kArcProps[] =
{
  kpidPhySize
};

IMP_IInArchive_Props
IMP_IInArchive_ArcProps

Z7_COM7F_IMF(CHandler::GetArchiveProperty(PROPID propID, PROPVARIANT *value))
{
  NCOM::CPropVariant prop;
  switch (propID)
  {
    case kpidPhySize: prop = _fileSize; break;
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
      default: break;
    }
  }
  prop.Detach(value);
  return S_OK;
}

HRESULT CHandler::Open2(IInStream *stream)
{
  _items.Clear();
  _fileSize = 0;

  RINOK(InStream_GetSize_SeekToBegin(stream, _fileSize))
  if (_fileSize < 16)
    return S_FALSE;

  Byte hdr[16];
  RINOK(ReadStream_FAIL(stream, hdr, sizeof(hdr)))
  if (ReadUInt32LE(hdr) != kDdrArcMagic)
    return S_FALSE;

  const UInt32 fileCount = ReadUInt32LE(hdr + 8);
  if (fileCount == 0 || fileCount > 1000000)
    return S_FALSE;

  const UInt64 tableEnd = 16 + (UInt64)fileCount * 16;
  if (tableEnd > _fileSize)
    return S_FALSE;

  struct CEnt
  {
    UInt32 strOff;
    UInt32 fileOff;
    UInt32 unp;
    UInt32 pack;
  };

  CObjectVector<CEnt> ents;
  ents.ClearAndReserve(fileCount);
  for (UInt32 i = 0; i < fileCount; i++)
  {
    Byte rec[16];
    RINOK(ReadStream_FAIL(stream, rec, sizeof(rec)))
    CEnt e;
    e.strOff = ReadUInt32LE(rec);
    e.fileOff = ReadUInt32LE(rec + 4);
    e.unp = ReadUInt32LE(rec + 8);
    e.pack = ReadUInt32LE(rec + 12);
    ents.Add(e);
  }

  for (unsigned i = 0; i < ents.Size(); i++)
  {
    const CEnt &e = ents[i];
    if ((UInt64)e.strOff >= _fileSize)
      return S_FALSE;
    if ((UInt64)e.fileOff + (UInt64)e.pack > _fileSize)
      return S_FALSE;

    UString path;
    RINOK(ReadUtf8PathAt(stream, e.strOff, _fileSize, path))
    NormalizePath(path);

    CItem &it = _items.AddNew();
    it.Path = path;
    it.PackOffset = e.fileOff;
    it.PackSize = e.pack;
    it.UnpackSize = e.unp;
  }

  return _items.IsEmpty() ? (HRESULT)S_FALSE : S_OK;
}

Z7_COM7F_IMF(CHandler::Open(IInStream *inStream,
    const UInt64 * /* maxCheckStartPosition */,
    IArchiveOpenCallback * /* openArchiveCallback */))
{
  COM_TRY_BEGIN
  Close();
  try
  {
    const HRESULT res = Open2(inStream);
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
  return S_OK;
}

Z7_COM7F_IMF(CHandler::GetNumberOfItems(UInt32 *numItems))
{
  *numItems = _items.Size();
  return S_OK;
}

static bool ArcItemIsLz77(const CItem &item)
{
  return item.PackSize != item.UnpackSize && item.PackSize != 0;
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

  UInt64 totalSize = 0;
  for (UInt32 i = 0; i < numItems; i++)
  {
    const UInt32 index = allFilesMode ? i : indices[i];
    if (index < _items.Size())
      totalSize += _items[index].UnpackSize;
  }
  RINOK(extractCallback->SetTotal(totalSize))

  CMyComPtr2_Create<ICompressProgressInfo, CLocalProgress> lps;
  lps->Init(extractCallback, false);
  CMyComPtr2_Create<ICompressCoder, NCompress::CCopyCoder> copyCoder;

  unsigned window = (unsigned)std::thread::hardware_concurrency();
  if (window == 0)
    window = 4;
  window = (std::min)(window, 8u);
  window = (std::max)(window, 1u);

  struct Slot
  {
    bool Needed;
    bool Ready;
    bool Done;
    bool Ok;
    std::vector<Byte> Packed;
    std::vector<uint8_t> Dec;
    Slot(): Needed(false), Ready(false), Done(false), Ok(false) {}
  };

  std::vector<Slot> slots((size_t)numItems);
  for (UInt32 i = 0; i < numItems; i++)
  {
    const UInt32 index = allFilesMode ? i : indices[i];
    if (index < _items.Size() && ArcItemIsLz77(_items[index]))
      slots[(size_t)i].Needed = true;
  }

  std::mutex mtx;
  std::condition_variable cv;
  std::atomic<bool> abortFlag(false);
  std::atomic<UInt32> nextPrefetch(0);
  std::atomic<UInt32> nextToDecode(0);

  auto ensurePrefetched = [&](UInt32 upToExclusive) -> HRESULT
  {
    for (;;)
    {
      UInt32 i = nextPrefetch.load(std::memory_order_relaxed);
      if (i >= upToExclusive || i >= numItems)
        break;
      if (!nextPrefetch.compare_exchange_weak(i, i + 1, std::memory_order_relaxed))
        continue;
      if (!slots[(size_t)i].Needed)
        continue;
      const UInt32 index = allFilesMode ? i : indices[i];
      const CItem &item = _items[index];
      std::vector<Byte> packed((size_t)item.PackSize);
      RINOK(InStream_SeekSet(_stream, item.PackOffset))
      RINOK(ReadStream_FAIL(_stream, packed.data(), packed.size()))
      {
        std::lock_guard<std::mutex> lock(mtx);
        slots[(size_t)i].Packed.swap(packed);
        slots[(size_t)i].Ready = true;
      }
      cv.notify_all();
    }
    return S_OK;
  };

  auto workerFn = [&]()
  {
    for (;;)
    {
      if (abortFlag.load(std::memory_order_relaxed))
        break;
      const UInt32 i = nextToDecode.fetch_add(1, std::memory_order_relaxed);
      if (i >= numItems)
        break;
      if (!slots[(size_t)i].Needed)
        continue;

      std::vector<Byte> packed;
      {
        std::unique_lock<std::mutex> lock(mtx);
        cv.wait(lock, [&]() {
          return abortFlag.load(std::memory_order_relaxed) || slots[(size_t)i].Ready;
        });
        if (abortFlag.load(std::memory_order_relaxed) && !slots[(size_t)i].Ready)
          break;
        packed.swap(slots[(size_t)i].Packed);
      }

      const UInt32 index = allFilesMode ? i : indices[i];
      const CItem &item = _items[index];
      std::vector<uint8_t> dec;
      bool ok = false;
      try
      {
        dec = util::lz77::decompress(packed.empty() ? NULL : packed.data(),
            packed.size(), (size_t)item.UnpackSize);
        ok = dec.size() == (size_t)item.UnpackSize;
      }
      catch (...)
      {
        ok = false;
        dec.clear();
      }
      packed.clear();

      {
        std::lock_guard<std::mutex> lock(mtx);
        slots[(size_t)i].Ok = ok;
        slots[(size_t)i].Dec.swap(dec);
        slots[(size_t)i].Done = true;
      }
      cv.notify_all();
    }
  };

  RINOK(ensurePrefetched((std::min)(numItems, (UInt32)window)))

  std::vector<std::thread> workers;
  workers.reserve((size_t)window);
  for (unsigned w = 0; w < window; w++)
    workers.emplace_back(workerFn);

  UInt64 completed = 0;
  HRESULT failHr = S_OK;

  for (UInt32 i = 0; i < numItems; i++)
  {
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

    lps->InSize = completed;
    lps->OutSize = completed;
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

    const Int32 askMode = testMode ?
        NExtract::NAskMode::kTest :
        NExtract::NAskMode::kExtract;
    const UInt32 index = allFilesMode ? i : indices[i];

    CMyComPtr<ISequentialOutStream> outStream;
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

    UInt64 unpackSize = 0;
    if (index < _items.Size())
      unpackSize = _items[index].UnpackSize;
    completed += unpackSize;

    if (!testMode && !outStream)
    {
      if (slots[(size_t)i].Needed)
      {
        std::unique_lock<std::mutex> lock(mtx);
        cv.wait(lock, [&]() {
          return abortFlag.load(std::memory_order_relaxed) || slots[(size_t)i].Done;
        });
        slots[(size_t)i].Dec.clear();
        slots[(size_t)i].Packed.clear();
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

    int opRes = NExtract::NOperationResult::kDataError;
    if (index >= _items.Size())
    {
      const HRESULT phr = extractCallback->SetOperationResult(opRes);
      if (phr != S_OK)
      {
        failHr = phr;
        abortFlag.store(true, std::memory_order_relaxed);
        cv.notify_all();
        break;
      }
      continue;
    }

    const CItem &item = _items[index];
    if (item.PackSize == 0 && item.UnpackSize != 0)
      opRes = NExtract::NOperationResult::kDataError;
    else if (slots[(size_t)i].Needed)
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
        std::vector<uint8_t> &dec = slots[(size_t)i].Dec;
        Create_BufInStream_WithReference(dec.empty() ? NULL : dec.data(), dec.size(),
            NULL, &inStream);
        const HRESULT codeHr = copyCoder.Interface()->Code(inStream, outStream, NULL, NULL, lps);
        const UInt64 wrote = copyCoder->TotalSize;
        dec.clear();
        if (codeHr != S_OK)
          opRes = NExtract::NOperationResult::kDataError;
        else if (wrote == item.UnpackSize)
          opRes = NExtract::NOperationResult::kOK;
        else if (wrote < item.UnpackSize)
          opRes = NExtract::NOperationResult::kUnexpectedEnd;
        else
          opRes = NExtract::NOperationResult::kDataError;
      }
    }
    else
    {
      CMyComPtr<ISequentialInStream> inStream;
      const HRESULT cr = CreateLimitedInStream(_stream, item.PackOffset, item.PackSize, &inStream);
      if (cr != S_OK || !inStream)
        opRes = NExtract::NOperationResult::kDataError;
      else
      {
        const HRESULT codeHr = copyCoder.Interface()->Code(inStream, outStream, NULL, NULL, lps);
        const UInt64 wrote = copyCoder->TotalSize;
        if (codeHr != S_OK)
          opRes = NExtract::NOperationResult::kDataError;
        else if (wrote == item.UnpackSize)
          opRes = NExtract::NOperationResult::kOK;
        else if (wrote < item.UnpackSize)
          opRes = NExtract::NOperationResult::kUnexpectedEnd;
        else
          opRes = NExtract::NOperationResult::kDataError;
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

static const Byte k_Signature[] =
{
  (Byte)0x20, (Byte)0x11, (Byte)0x75, (Byte)0x19
};

API_FUNC_static_IsArc IsArc_DdrArc(const Byte *p, size_t size)
{
  if (size < 4)
    return k_IsArc_Res_NEED_MORE;
  if (p[0] == 0x20 && p[1] == 0x11 && p[2] == 0x75 && p[3] == 0x19)
    return k_IsArc_Res_YES;
  return k_IsArc_Res_NO;
}
}

REGISTER_ARC_I(
    "DDR ARC",
    "arc",
    NULL,
    0xC0,
    k_Signature,
    0,
    0,
    IsArc_DdrArc)

}}
