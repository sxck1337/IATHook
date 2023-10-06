# IAT Hooking Library

## Overview

IATHook is a lightweight and easy-to-use IAT (Import Address Table) Hooking library for both x64 and x86. It allows you to intercept and redirect function calls with minimal effort. The library is designed to be straightforward for integration into your projects.

## Example Usage

```cpp
#include <Windows.h>
#include <iostream>

#include "IATHook.hpp"

typedef int(__stdcall* MessageBox_t)(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);
MessageBox_t MessageBoxOriginal;

int MessageBoxDetour(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType)
{
    printf("MessageBoxA hook has been called! \n");

    return MessageBoxOriginal(NULL, "Captain Hook!", "IAT_HOOK", 0);
}

int main()
{
    MessageBoxA(NULL, "Before hooking!", "Test", NULL);

    // create hook
    if (IAT_HOOK::Create("user32.dll", "MessageBoxA", &MessageBoxDetour, (void**)&MessageBoxOriginal) != IAT_OK)
        printf("Error while hooking MessageBoxA! \n");

    MessageBoxA(NULL, "After hooking!", "Test", NULL);

    // restore hook
    if (IAT_HOOK::Restore("MessageBoxA"))
        printf("Error while restoring MessageBoxA! \n");

    MessageBoxA(NULL, "After restoring!", "Test", NULL);

    return 0;
}
```

## License

This library is released under the [MIT License](LICENSE).

Feel free to contribute, report issues, or make suggestions!
