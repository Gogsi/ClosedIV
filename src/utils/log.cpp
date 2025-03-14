#include "main.h"

void logger::init()
{
	if(std::filesystem::exists("C:\\Logs\\ClosedIV.log"))
	{
		std::filesystem::remove("C:\\Logs\\ClosedIV.log");
	}
}

void logger::write(const char* type, const char* msg, ...)
{
	char buffer[256]{ 0 };

	va_list args;
	va_start(args, msg);

	sprintf(buffer, "[%s]", type);
	vsprintf(&buffer[strlen(buffer)], msg, args);
	//vprintf(msg, args);
	printf("%s\n", buffer);
	va_end(args);

	if (config::get_log(type))
	{
		std::ofstream logFile("C:\\Logs\\ClosedIV.log", std::ofstream::out | std::ofstream::app);
		logFile.write(buffer, strlen(buffer));
		logFile.write("\n", 1);
		logFile.flush();
		logFile.close();
		_flushall(); // Ensures all streams are flushed (Windows-specific)
	}
}