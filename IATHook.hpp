// IATHook 
//
// Copyright (c) 2023 sxck1337
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#ifndef IAT_HOOK_H
#define IAT_HOOK_H

#include <Windows.h>
#include <vector>

#if !(defined _M_IX86) && !(defined _M_X64) && !(defined __i386__) && !(defined __x86_64__)
#error IAT_HOOK only supports x86/x64.
#endif

enum IAT_STATUS
{
	IAT_UNKNOWN = -1,		// used internally
	IAT_OK,				// success 
	IAT_PROTECT,		// failed to protect
	IAT_RESTORE,		// failed to restore old protection
	IAT_NOTFOUND,		// module name or function not found
	IAT_DUPLICATE,		// function name already hooked
	IAT_NOENTRY			// no hook found with that name
};

struct IAT_ENTRY
{
	LPCSTR module_name;
	LPCSTR function_name;
	LPVOID detour;
	LPVOID original;
	LPCSTR target_module;
};

class IAT_HOOK
{
public:
	// creates a hook for the specified detour
	// parameters:
	//   module_name      [in]  name of the module containing the function.      
	//
	//   function_name    [in]  name of the function to hook.        
	//
	//   detour           [in]  pointer to your hook.          
	//
	//   original	      [out] pointer of the original function. (this parameter can be NULL if not needed)
	//						
	//   target_module    [in]  name of the module you want to target. (NULL by default, targets the main module of the process)
	static IAT_STATUS Create( LPCSTR module_name, LPCSTR function_name, LPVOID detour, LPVOID* original, LPCSTR target_module = NULL );

	// restores a previously hooked function to its original.
	// parameters:
	//   function_name    [in]  name of the function to restore.
	static IAT_STATUS Restore( LPCSTR function_name );
private:
	static std::vector<IAT_ENTRY> hooks;
	static IAT_STATUS HookAPI( LPCSTR module_name, LPCSTR function_name, LPVOID detour, LPVOID* original, LPCSTR target_module = NULL, int type = 0 );
};

#endif
