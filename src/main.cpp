#include "main.h"
#include "processthreadsapi.h"

static bool bInited = false;
void (*origGetSystemTimeAsFileTime)(LPFILETIME lpSystemTimeAsFileTime);
void HookGetSystemTimeAsFileTime(LPFILETIME lpSystemTimeAsFileTime)
{
	if (!bInited)
	{
		logger::write("info", "Starting ClosedIV Init!");
		bInited = true;
		memory::init();

		//don't hide the console
		memory::scan("FF 15 ? ? ? ? 48 85 C0 74 ? 48 89 C1").nop(6);

		memory::InitFuncs::run();

		logger::write("info", "ClosedIV Inited!");
	}
	GetSystemTimeAsFileTime(lpSystemTimeAsFileTime);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  dwReason, LPVOID lpReserved)
{
    if(dwReason == DLL_PROCESS_ATTACH)
	{
		DisableThreadLibraryCalls(hModule);

		config::load();
		
		logger::init();

		if (config::get_config<bool>("console"))
		{
			AllocConsole();

			FILE* unused = nullptr;
			freopen_s(&unused, "CONIN$", "r", stdin); 
			freopen_s(&unused, "CONOUT$", "w", stdout);
			freopen_s(&unused, "CONOUT$", "w", stderr);
		}

		//compatibility for any asi loader, as OpenIV supports only the one made by Alexander Blade
		if (!memory::HookIAT("kernel32.dll", "GetSystemTimeAsFileTime", (PVOID)HookGetSystemTimeAsFileTime, (PVOID*)&origGetSystemTimeAsFileTime)) {
			logger::write("info", "Hooking failed error (%ld)", GetLastError());
		}
    }
    return TRUE;
}