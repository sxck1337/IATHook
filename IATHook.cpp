#include "IATHook.hpp"

std::vector<IAT_ENTRY> IAT_HOOK::hooks;

IAT_STATUS IAT_HOOK::HookAPI( LPCSTR module_name, LPCSTR function_name, LPVOID detour, LPVOID* original, LPCSTR target_module, int type )
{
	LPVOID image_base = GetModuleHandleA( target_module );
	PIMAGE_DOS_HEADER dos_headers = (PIMAGE_DOS_HEADER)image_base;
	PIMAGE_NT_HEADERS nt_headers = (PIMAGE_NT_HEADERS)((uintptr_t)image_base + dos_headers->e_lfanew);

	IMAGE_DATA_DIRECTORY imports_directory = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	PIMAGE_IMPORT_DESCRIPTOR import_descriptor = (PIMAGE_IMPORT_DESCRIPTOR)(imports_directory.VirtualAddress + (uintptr_t)image_base);

	while (import_descriptor->Name != NULL)
	{
		LPCSTR library_name = (LPCSTR)import_descriptor->Name + (uintptr_t)image_base;

		if (_stricmp( library_name, module_name ) != NULL)
		{
			import_descriptor++;
			continue;
		}

		PIMAGE_THUNK_DATA image_org_thunk_data = (PIMAGE_THUNK_DATA)((uintptr_t)image_base + import_descriptor->OriginalFirstThunk);
		PIMAGE_THUNK_DATA image_thunk_data = (PIMAGE_THUNK_DATA)((uintptr_t)image_base + import_descriptor->FirstThunk);

		while (image_org_thunk_data->u1.AddressOfData != NULL)
		{
			PIMAGE_IMPORT_BY_NAME import_data = (PIMAGE_IMPORT_BY_NAME)((uintptr_t)image_base + image_org_thunk_data->u1.AddressOfData);

			if (_stricmp( function_name, import_data->Name ) == NULL)
			{
				DWORD unused_protect = 0;
				MEMORY_BASIC_INFORMATION mbi;

				VirtualQuery( image_thunk_data, &mbi, sizeof( MEMORY_BASIC_INFORMATION ) );
				if (!VirtualProtect( mbi.BaseAddress, mbi.RegionSize, PAGE_READWRITE, &mbi.Protect ))
					return IAT_PROTECT;

				LPVOID orig_func = (LPVOID)image_thunk_data->u1.Function;

				image_thunk_data->u1.Function = (uintptr_t)detour;

				if (!VirtualProtect( mbi.BaseAddress, mbi.RegionSize, mbi.Protect, &unused_protect ))
					return IAT_RESTORE;

				if (type == 0)
				{
					if (original != NULL)
						*original = orig_func;

					IAT_ENTRY new_entry{};
					new_entry.detour = detour;
					new_entry.function_name = function_name;
					new_entry.module_name = module_name;
					new_entry.original = orig_func;
					new_entry.target_module = target_module;

					hooks.push_back( new_entry );
				}
				else
				{
					hooks.erase( std::remove_if( hooks.begin( ), hooks.end( ),
						[&function_name]( const IAT_ENTRY& entry ) {
							return entry.function_name == function_name;
						}
					) );
				}

				return IAT_OK;
			}

			image_org_thunk_data++;
			image_thunk_data++;
		}

		import_descriptor++;
	}

	return IAT_UNKNOWN;
}

IAT_STATUS IAT_HOOK::Create( LPCSTR module_name, LPCSTR function_name, LPVOID detour, LPVOID* original, LPCSTR target_module )
{
	if (!hooks.empty( ))
	{
		for (auto& entry : hooks)
		{
			if (_stricmp( entry.function_name, function_name ) == NULL)
				return IAT_DUPLICATE;
		}
	}

	IAT_STATUS status = HookAPI( module_name, function_name, detour, original, target_module );

	if (status != IAT_UNKNOWN)
		return status;

	return IAT_NOTFOUND;
}

IAT_STATUS IAT_HOOK::Restore( LPCSTR function_name )
{
	if (hooks.empty( ))
		return IAT_NOENTRY;

	for (auto& entry : hooks)
	{
		if (_stricmp( entry.function_name, function_name ) == NULL)
		{
			IAT_STATUS status = HookAPI( entry.module_name, entry.function_name, entry.original, NULL, entry.target_module, 1 );

			if (status != IAT_UNKNOWN)
				return status;

			return IAT_NOTFOUND;
		}
	}

	return IAT_NOENTRY;
}
