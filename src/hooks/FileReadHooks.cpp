#include "main.h"

HANDLE OpenBulkHook(void* device, const char* path, __int64* a3)
{
	//logger::write("mods", "OpenBulk - %s",  path);
	HANDLE FileW;
	WCHAR WideCharStr[256];

	*a3 = 0;

	MultiByteToWideChar(0xFDE9u, 0, path, -1, WideCharStr, 256);

	FileW = CreateFileW((L"mods/" + std::wstring(WideCharStr)).c_str(), 0x80000000, 1u, 0, 3, 0x80, 0);

	if (FileW == (HANDLE)-1)
		FileW = CreateFileW(WideCharStr, 0x80000000, 1u, 0, 3, 0x80, 0);
	else
	{
		logger::write("mods", "[%s] Found mods/%s", __FUNCTION__, path);
	}

	return FileW;
}

FILETIME GetFileTimeHook(void* device, const char* path)
{
	WCHAR WideCharStr[256];
	WIN32_FILE_ATTRIBUTE_DATA FileInformation;

	MultiByteToWideChar(0xFDE9u, 0, path, -1, WideCharStr, 256);

	if (GetFileAttributesExW((L"mods/" + std::wstring(WideCharStr)).c_str(), GetFileExInfoStandard, &FileInformation))
	{
		logger::write("mods", "[%s] Found mods/%s", __FUNCTION__, path);
		return FileInformation.ftLastWriteTime;
	}
	else if (GetFileAttributesExW(WideCharStr, GetFileExInfoStandard, &FileInformation))
		return FileInformation.ftLastWriteTime;
	else
		return (FILETIME)0;
}

uint64_t GetFileSizeHook(void* device, const char* path)
{
	WCHAR WideCharStr[256];
	WIN32_FILE_ATTRIBUTE_DATA FileInformation;

	MultiByteToWideChar(0xFDE9u, 0, path, -1, WideCharStr, 256);

	if (GetFileAttributesExW((L"mods/" + std::wstring(WideCharStr)).c_str(), GetFileExInfoStandard, &FileInformation))
	{
		logger::write("mods", "[%s] Found mods/%s", __FUNCTION__, path);
		return FileInformation.nFileSizeLow | (static_cast<size_t>(FileInformation.nFileSizeHigh) << 32);
	}
	else if (GetFileAttributesExW(WideCharStr, GetFileExInfoStandard, &FileInformation))
		return FileInformation.nFileSizeLow | (static_cast<size_t>(FileInformation.nFileSizeHigh) << 32);
	else
		return 0;
}

uint64_t GetAttributesHook(void* device, const char* path)
{
	WCHAR WideCharStr[256];
	DWORD FileAttributesW;

	MultiByteToWideChar(0xFDE9u, 0, path, -1, WideCharStr, 256);

	FileAttributesW = GetFileAttributesW((L"mods/" + std::wstring(WideCharStr)).c_str());

	if (FileAttributesW == -1)
		FileAttributesW = GetFileAttributesW(WideCharStr);
	else
	{
		logger::write("mods", "[%s] Found mods/%s", __FUNCTION__, path);
	}
	return FileAttributesW;
}

static memory::InitFuncs FileReadHooks([] {
	// disable rpf.cache
	memory::scan("48 8D 74 24 70 48 89 F2 41 B8 00 01 00 00").add(-23).rip().put("lol.cache");

	//hooks for reading files
	memory::scan("48 81 EC 98 04 00 00 44 89 C3").add(-5)
		.make_jmp_ret(OpenBulkHook);
		
	memory::scan("48 81 EC 70 02 00 00 66 C7 44 24 60 00 00").add(-3)
		.make_jmp_ret(GetFileTimeHook);

	memory::scan("48 81 EC 70 02 00 00 66 C7 44 24 60 00 00").add(-3)
		.make_jmp_ret(GetFileSizeHook);

	memory::scan("48 81 EC 98 04 00 00 66 C7 44 24 38 00 00").add(-5)
		.make_jmp_ret(GetAttributesHook);
});