#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <string>

struct InfoForExtension
{
	const char* propertyName;
	int propertyValue;
	InfoForExtension* nextProperty;
};

// Traverses linked list to find info.
int GetProperty(const char* propertyName, const InfoForExtension* miscInfo)
{
	const InfoForExtension* miscInfoTraverser = miscInfo;
	while (miscInfoTraverser != nullptr)
		if (strcmp(propertyName, miscInfoTraverser->propertyName) == 0) return miscInfoTraverser->propertyValue;
		else miscInfoTraverser = miscInfoTraverser->nextProperty;

	return 0;
}