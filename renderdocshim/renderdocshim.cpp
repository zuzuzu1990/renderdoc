/******************************************************************************
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2026 Baldur Karlsson
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

// This project deliberately references only kernel32.dll (ie. not even the CRT)
// so that when inserted into an application it has as small an overhead/impact
// as possible. Ideally it would be present only to be a pass-through hook and
// the first time only to allocate a little, check if this process should be hooked
// and load the renderdoc dll.
//
// The no-CRT restriction causes some awkward bits and pieces but the dll is simple
// enough that it's not a big issue.

#include "renderdocshim.h"
#include <windows.h>

struct CaptureOptions;
typedef void(__cdecl *pINTERNAL_SetCaptureOptions)(const CaptureOptions *opts);
typedef void(__cdecl *pINTERNAL_SetCaptureFile)(const char *logfile);
typedef void(__cdecl *pINTERNAL_SetDebugLogFile)(const char *logfile);

static DWORD StringLength(const char *text)
{
  DWORD length = 0;
  while(text[length])
    length++;
  return length;
}

static void AppendDiagnosticLog(const ShimData *data, const char *text)
{
  if(data == NULL || data->debuglog[0] == 0)
    return;

  wchar_t *logpath = (wchar_t *)VirtualAlloc(NULL, 2048 * sizeof(wchar_t),
                                             MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
  if(logpath == NULL)
    return;

  logpath[0] = 0;
  if(MultiByteToWideChar(CP_UTF8, 0, data->debuglog, -1, logpath, 2048) == 0)
  {
    VirtualFree(logpath, 0, MEM_RELEASE);
    return;
  }

  HANDLE logfile = CreateFileW(logpath, FILE_APPEND_DATA,
                               FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                               OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if(logfile == INVALID_HANDLE_VALUE)
  {
    VirtualFree(logpath, 0, MEM_RELEASE);
    return;
  }

  DWORD written = 0;
  WriteFile(logfile, text, StringLength(text), &written, NULL);
  FlushFileBuffers(logfile);
  CloseHandle(logfile);
  VirtualFree(logpath, 0, MEM_RELEASE);
}

static void AppendError(const ShimData *data, DWORD error)
{
  char errorText[512];
  errorText[0] = 0;
  DWORD length = FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL,
                                error, 0, errorText, 511, NULL);
  if(length > 0)
    AppendDiagnosticLog(data, errorText);
}

#if defined(RELEASE)
#define LOGPRINT(txt) \
  do                  \
  {                   \
  } while(0)
#else
// define this to something to get logging
// #define LOGPRINT(txt) OutputDebugStringW(txt)
#define LOGPRINT(txt) \
  do                  \
  {                   \
  } while(0)
#endif

void CheckHook()
{
  ShimData *data = NULL;

  HANDLE datahandle = OpenFileMappingA(FILE_MAP_READ, FALSE, GLOBAL_HOOK_DATA_NAME);

  if(datahandle == NULL)
  {
    LOGPRINT(L"renderdocshim: can't open global data\n");
    return;
  }

  data = (ShimData *)MapViewOfFile(datahandle, FILE_MAP_READ, 0, 0, sizeof(ShimData));

  if(data == NULL)
  {
    CloseHandle(datahandle);
    LOGPRINT(L"renderdocshim: can't map global data\n");
    return;
  }

  if(data->pathmatchstring[0] == 0 || data->pathmatchstring[1] == 0 ||
     data->pathmatchstring[2] == 0 || data->pathmatchstring[3] == 0)
  {
    LOGPRINT(L"renderdocshim: invalid pathmatchstring: '");
    LOGPRINT(data->pathmatchstring);
    LOGPRINT(L"'\n");

    UnmapViewOfFile(data);
    CloseHandle(datahandle);
    return;
  }

  // no new[], need to use VirtualAlloc
  const int exepathLen = 1024;
  wchar_t *exepath = (wchar_t *)VirtualAlloc(NULL, exepathLen * sizeof(wchar_t),
                                             MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

  if(exepath)
  {
    // no memset :).
    for(int i = 0; i < exepathLen; i++)
      exepath[i] = 0;

    GetModuleFileNameW(NULL, exepath, exepathLen - 1);

    // no str*cmp functions
    int find = FindStringOrdinal(FIND_FROMSTART, exepath, -1, data->pathmatchstring, -1, TRUE);

    if(find >= 0)
    {
      AppendDiagnosticLog(data, "[ZZZDocGlobalHook][shim] stage=path_matched\r\n");
      LOGPRINT(L"renderdocshim: Hooking into '");
      LOGPRINT(exepath);
      LOGPRINT(L"', based on '");
      LOGPRINT(data->pathmatchstring);
      LOGPRINT(L"'\n");

      AppendDiagnosticLog(data, "[ZZZDocGlobalHook][shim] stage=load_core_begin\r\n");
      HMODULE mod = LoadLibraryW(data->rdocpath);

      if(mod)
      {
        AppendDiagnosticLog(data, "[ZZZDocGlobalHook][shim] stage=load_core_success\r\n");
        pINTERNAL_SetCaptureOptions setopts =
            (pINTERNAL_SetCaptureOptions)GetProcAddress(mod, "INTERNAL_SetCaptureOptions");
        pINTERNAL_SetCaptureFile setcapturefile =
            (pINTERNAL_SetCaptureFile)GetProcAddress(mod, "INTERNAL_SetCaptureFile");
        pINTERNAL_SetDebugLogFile setdebuglog =
            (pINTERNAL_SetDebugLogFile)GetProcAddress(mod, "INTERNAL_SetDebugLogFile");

        if(setopts)
          setopts((const CaptureOptions *)data->opts);

        if(setcapturefile && data->capfile[0])
          setcapturefile(data->capfile);

        if(setdebuglog && data->debuglog[0])
          setdebuglog(data->debuglog);

        AppendDiagnosticLog(data, "[ZZZDocGlobalHook][shim] stage=configuration_applied\r\n");
      }
      else
      {
        DWORD loadError = GetLastError();
        AppendDiagnosticLog(data, "[ZZZDocGlobalHook][shim] stage=load_core_failed error=");
        AppendError(data, loadError);
      }
    }
    else
    {
      LOGPRINT(L"renderdocshim: NOT Hooking into '");
      LOGPRINT(exepath);
      LOGPRINT(L"', based on '");
      LOGPRINT(data->pathmatchstring);
      LOGPRINT(L"'\n");
    }

    VirtualFree(exepath, 0, MEM_RELEASE);
  }
  else
  {
    LOGPRINT(L"renderdocshim: Failed to allocate exepath\n");
  }

  UnmapViewOfFile(data);
  CloseHandle(datahandle);
}

DWORD WINAPI CheckHookThread(LPVOID param)
{
  CheckHook();

  // this makes sure that we remove the reference to the shim dll and unload from
  // the target process. That minimises the impact of having the dll inserted into
  // every process
  FreeLibraryAndExitThread((HMODULE)param, 0);
  return 0;
}

BOOL APIENTRY dll_entry(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
  if(ul_reason_for_call == DLL_PROCESS_ATTACH)
  {
    DisableThreadLibraryCalls(hModule);

    // create a thread so that we can perform more complex actions (DllMain must be minimal
    // in size, even this is a bit dodgy).
    CreateThread(NULL, 0, CheckHookThread, (LPVOID)hModule, 0, NULL);
  }

  return TRUE;
}
