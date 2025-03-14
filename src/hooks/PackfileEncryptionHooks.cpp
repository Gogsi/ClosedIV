#include "main.h"

uint32_t currentEncryption;
bool FindEncryptionHook(uint32_t encryption)
{
	currentEncryption = encryption;
	return (encryption & 0xFF00000) == 0xFE00000;
}

void(*DecryptHeaderOrig)(uint32_t, char*, int);
void DecryptHeaderHook(uint32_t salt, char* entryTable, int size)
{
	if (currentEncryption == 0x4E45504F) //OPEN
	{
		logger::write("mods", "not encrypted RPF found");
		return;
	}
	DecryptHeaderOrig(salt, entryTable, size);
}

void(*DecryptHeader2Orig)(uint32_t, uint32_t, char*, int);
void DecryptHeader2Hook(uint32_t encryption, uint32_t salt, char* header, int nameTableLen)
{
	if (encryption == 0x4E45504F) //OPEN
	{
		logger::write("mods", "not encrypted RPF found");
		return;
	}
	DecryptHeader2Orig(encryption, salt, header, nameTableLen);
}

bool(*ParseHeaderOrig)(rage::fiPackfile*, const char*, bool, void*);
bool ParseHeaderHook(rage::fiPackfile* a1, const char* name, bool readHeader, void* customHeader)
{
	//logger::write("rpf", "Parsing header for %s", name);

	bool ret = ParseHeaderOrig(a1, name, readHeader, customHeader);
	if (ret)
	{
		for (int i = 0; i < a1->filesCount; ++i)
		{
			Entry* v21 = (Entry*)(a1->entryTable + 16 * i);
			if (v21->IsBinary() && v21->bin.nameOffset > 0 && v21->bin.isEncrypted)
			{
				if (currentEncryption == 0x4E45504F) //OPEN
					v21->bin.isEncrypted = 0xFEFFFFF;
			}
		}

		if (currentEncryption == 0x4E45504F) //OPEN
			a1->currentFileOffset = 0xFEFFFFF;
	}
	return ret;
}

static memory::InitFuncs PackfileEncryptionHooks([] {
	//allow unencrypted RPFs
	//memory::scan("89 8E BC 00 00 00 E8 ? ? ? ? 80 7C").add(6).set_call(FindEncryptionHook);

	auto mem = memory::scan("74 0F 48 8B 56 28 44 89 E1").add(12);
	DecryptHeaderOrig = mem.add(1).rip().as<decltype(DecryptHeaderOrig)>();
	mem.set_call(DecryptHeaderHook);

	mem = memory::scan("8B 8E BC 00 00 00  44 89 E2 4D 89 F8").add(12);
	DecryptHeader2Orig = mem.add(1).rip().as<decltype(DecryptHeader2Orig)>();
	mem.set_call(DecryptHeader2Hook);

	mem = memory::scan("C6 86 B0 00 00 00 00 48 89 F1").add(19);
	ParseHeaderOrig = mem.add(1).rip().as<decltype(ParseHeaderOrig)>();
	mem.set_call(ParseHeaderHook);
});