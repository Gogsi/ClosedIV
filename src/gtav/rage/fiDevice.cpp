#include "main.h"

bool rage::fiDevice::Mount(const char* mountPoint)
{
	static auto func = memory::scan("48 89 5C 24 ? 57 48 81 EC ? ? ? ? 44 8A 81 ? ? ? ? 48 8B DA 48 8B F9 48 8B D1 48 8B CB E8 ? ? ? ? 84 C0 74 64 48 8D 4C 24 ? 33 D2 41 B8")
		.as<bool(*)(void*, const char*)>();

	return func(this, mountPoint);
}

void rage::fiDevice::SetPath(const char* path, bool allowRoot, rage::fiDevice* parent)
{
	static auto func = memory::scan("48 89 5C 24 ? 48 89 74 24 ? 57 48 81 EC ? ? ? ? 83 64 24 ? ? 49 8B F9")
		.as<void(*)(void*, const char*, bool, rage::fiDevice*)>();

	func(this, path, allowRoot, parent);
}