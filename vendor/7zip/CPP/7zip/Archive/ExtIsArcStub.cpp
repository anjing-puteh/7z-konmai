// ExtIsArcStub.cpp -- stub for NExt::IsArc_Ext when ExtHandler.cpp is not linked.
// HandlerCont.cpp references IsArc_Ext for image-container auto-detection.

#include "StdAfx.h"

#include "IArchive.h"

namespace NArchive {
namespace NExt {

API_FUNC_IsArc IsArc_Ext(const Byte * /* p */, size_t /* size */)
{
  return k_IsArc_Res_NO;
}

}}
