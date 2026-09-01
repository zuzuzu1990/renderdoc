/******************************************************************************
 * The MIT License (MIT)
 *
 * Copyright (c) 2015-2026 Baldur Karlsson
 * Copyright (c) 2014 Crytek
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 ******************************************************************************/

// win32_libentry.cpp : Defines the entry point for the DLL
#include <tchar.h>
#include <windows.h>
#include "common/common.h"
#include "core/core.h"
#include "hooks/hooks.h"
#include "strings/string_utils.h"

static HANDLE zzzdocInternalTestMarker = NULL;

extern "C" __declspec(dllexport) const char *ZZZDOC_InternalTestBuild()
{
  return "ZZZDocInternalTest/v1";
}

static BOOL add_hooks()
{
  wchar_t curFile[512];
  GetModuleFileNameW(NULL, curFile, 512);

  RDCLOG("[ZZZDocGlobalHook] stage=dll_attach process=%ls", curFile);

  rdcstr f = get_basename(strlower(StringFormat::Wide2UTF8(curFile)));

  // bail immediately if we're in a system process. We don't want to hook, log, anything -
  // this instance is being used for a shell extension.
  if(f == "dllhost.exe" || f == "explorer.exe")
  {
#if ENABLED(RDOC_RELEASE)
    OutputDebugStringA(
        "Detecting shell process! Disabling hooking in dllhost.exe or explorer.exe\n");
#endif
    return TRUE;
  }

  // The public replay marker keeps its historical RenderDoc name. Also accept the branded name so
  // replay applications remain detectable when the capture DLL is renamed.
  if(LibraryHooks::Detect("renderdoc__replay__marker") ||
     LibraryHooks::Detect(STRINGIZE(RDOC_BASE_NAME) "__replay__marker"))
  {
    RDCDEBUG("Not creating hooks - in replay app");

    RenderDoc::Inst().SetReplayApp(true);

    RenderDoc::Inst().Initialise();

    zzzdocInternalTestMarker =
        CreateEventA(NULL, TRUE, FALSE, "Local\\ZZZDocInternalTest_v1");

    LibraryHooks::ReplayInitialise();

    return true;
  }

  RDCLOG("[ZZZDocGlobalHook] stage=core_initialise_begin");
  RenderDoc::Inst().Initialise();
  RDCLOG("[ZZZDocGlobalHook] stage=core_initialise_complete");

  zzzdocInternalTestMarker =
      CreateEventA(NULL, TRUE, FALSE, "Local\\ZZZDocInternalTest_v1");

  RDCLOG("Loading into %ls", curFile);

  RDCLOG("[ZZZDocGlobalHook] stage=register_hooks_call");
  LibraryHooks::RegisterHooks();
  RDCLOG("[ZZZDocGlobalHook] stage=dll_attach_complete");

  return TRUE;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
  if(ul_reason_for_call == DLL_PROCESS_ATTACH)
  {
    BOOL ret = add_hooks();
    SetLastError(0);
    return ret;
  }

  if(ul_reason_for_call == DLL_PROCESS_DETACH && zzzdocInternalTestMarker)
  {
    RDCLOG("[ZZZDocGlobalHook] stage=dll_detach reason=%s",
           lpReserved ? "process_termination" : "free_library");
    CloseHandle(zzzdocInternalTestMarker);
    zzzdocInternalTestMarker = NULL;
  }

  return TRUE;
}
