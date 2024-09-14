/*
This file is part of Darling.

Copyright (C) 2012-2020 Lubos Dolezel

Darling is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Darling is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Darling.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <CoreServices/FileManager.h>
#include <cstdlib>
#include <string>
#include <cstring>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <algorithm>
#include <memory>
#include <errno.h>
#include <iconv.h>
#include <alloca.h>
#include <libgen.h>
#include <sstream>
#include <fstream>
#include <map>
#include <regex.h>
#include <fcntl.h>
#include <vector>
#include <CarbonCore/DateTimeUtils.h>
#include <errno.h>
#include <darling/emulation/syscall/linux/ext/file_handle.h>

#define STUB() // TODO

// Is the current user member of the specified group?
static bool hasgid(gid_t gid);

OSStatus FSPathMakeRef(const uint8_t* path, FSRef* fsref, Boolean* isDirectory)
{
	return FSPathMakeRefWithOptions(path, kFSPathMakeRefDoNotFollowLeafSymlink, fsref, isDirectory); 
}

OSStatus FSPathMakeRefWithOptions(const uint8_t* path, long options, FSRef* fsref, Boolean* isDirectory)
{
	if (!path || !fsref)
		return paramErr;

	int flags = 1;
	if (options & kFSPathMakeRefDoNotFollowLeafSymlink)
		flags = 0;

	int err = linux_name_to_handle((const char*) path, (RefData*) fsref, flags);
	if (err != 0)
		return fnfErr;

	if (isDirectory)
	{
		struct stat st;

		if (options & kFSPathMakeRefDoNotFollowLeafSymlink)
			err = lstat((const char*) path, &st);
		else
			err = stat((const char*) path, &st);

		if (err == 0)
			*isDirectory = S_ISDIR(st.st_mode);
		else
			*isDirectory = 0;
	}

	return noErr; 
}

bool FSRefMakePath(const FSRef* fsref, std::string& out)
{
	char name[4096];
	int ret = linux_handle_to_name((RefData*) fsref, name);
	if (ret != 0)
		return false;

	out = name;
	return true;
}

bool FSRefParamMakePath(const FSRefParam* param, std::string& out)
{
	std::string dir;
	CFStringRef str;
	std::unique_ptr<char[]> buf;
	size_t bufsize;
	Boolean success;
	
	if (!FSRefMakePath(param->ref, dir))
		return false;
	
	out = dir;
	if (out.back() != '/')
		out += '/';
	
	str = CFStringCreateWithCharacters(NULL, param->name, param->nameLength);
	bufsize = CFStringGetLength(str)*4+1;
	buf.reset(new char[bufsize]);
	
	success = CFStringGetCString(str, buf.get(), bufsize, kCFStringEncodingUTF8);
	CFRelease(str);
	
	if (success)
	{
		out += buf.get();
		return true;
	}
	else
		return false;
}

OSStatus FSDeleteObject(const FSRef* fsref)
{
	std::string path;
	if (FSRefMakePath(fsref, path))
	{
		if (::unlink(path.c_str()) == -1)
			return makeOSStatus(errno);
		return noErr;
	}
	return fnfErr;
}

OSStatus FSRefMakePath(const FSRef* fsref, uint8_t* path, uint32_t maxSize)
{
	std::string rpath;

	if (!fsref || !path || !maxSize)
		return paramErr;

	if (!FSRefMakePath(fsref, rpath))
		return fnfErr;

	strncpy((char*) path, rpath.c_str(), maxSize);
	path[maxSize-1] = 0;

	return noErr;
}

OSStatus FSGetCatalogInfo(const FSRef* ref, uint32_t infoBits, FSCatalogInfo* infoOut, HFSUniStr255* nameOut, FSSpecPtr fsspec, FSRef* parentDir)
{
	std::string path;

	if (!FSRefMakePath(ref, path))
		return fnfErr;

	if (nameOut)
	{
		CFStringRef cfstr = CFStringCreateWithCString(NULL, path.c_str(), kCFStringEncodingUTF8);
		nameOut->length = std::min<size_t>(path.length(), 255);
		CFStringGetCharacters(cfstr, CFRangeMake(0, nameOut->length), nameOut->unicode);
		CFRelease(cfstr);
	}

	if (parentDir)
	{
		/*
		memcpy(parentDir, ref, sizeof(FSRef));
		ino_t* last = std::find(parentDir->inodes, parentDir->inodes+FSRef_MAX_DEPTH, 0);

		if (last != parentDir->inodes)
			*(last-1) = 0;
		*/
		// TODO
	}

	if (infoOut && infoBits != kFSCatInfoNone)
	{
		struct stat st;

		memset(infoOut, 0, sizeof(*infoOut));

		if (::stat(path.c_str(), &st) != 0)
			return makeOSStatus(errno);

		if (infoBits & kFSCatInfoNodeFlags)
		{
			if (S_ISDIR(st.st_mode))
				infoOut->nodeFlags = 4;
		}
	
		if (infoBits & (kFSCatInfoParentDirID|kFSCatInfoNodeID))
		{
			/*
			if (infoBits & kFSCatInfoNodeID)
				infoOut->nodeID = ref->inodes[0];
			for (int i = FSRef_MAX_DEPTH-1; i > 0; i--)
			{
				if (ref->inodes[i] == 0)
					continue;
				
				if (infoBits & kFSCatInfoParentDirID)
					infoOut->parentDirID = ref->inodes[i-1];
				if (infoBits & kFSCatInfoNodeID)
					infoOut->nodeID = ref->inodes[i];
			}
			*/
			// TODO
		}

		if (infoBits & kFSCatInfoDataSizes)
		{
			infoOut->dataLogicalSize = st.st_size;
			infoOut->dataPhysicalSize = st.st_blocks*512;
		}
		
		int uaccess;
		
		if (st.st_uid == getuid())
			uaccess = st.st_mode & 0700;
		else if (hasgid(st.st_gid))
			uaccess = st.st_mode & 070;
		else
			uaccess = st.st_mode & 07;

		if (infoBits & kFSCatInfoPermissions)
		{
			const uid_t uid = getuid();

			infoOut->fsPermissionInfo.userID = st.st_uid;
			infoOut->fsPermissionInfo.groupID = st.st_gid;
			infoOut->fsPermissionInfo.mode = st.st_mode & 07777;
			infoOut->fsPermissionInfo.userAccess = uaccess;
		}

		if (infoBits & kFSCatInfoUserPrivs)
		{
			if (!(uaccess & 2))
				infoOut->userPrivileges |= 0x4; // kioACUserNoMakeChangesMask
			if (getuid() != st.st_uid)
				infoOut->userPrivileges |= 0x80; // kioACUserNotOwnerMask
		}
		if (infoBits & kFSCatInfoCreateDate)
			infoOut->createDate = Darling::time_tToUTC(st.st_ctime);
		if (infoBits & kFSCatInfoContentMod)
			infoOut->attributeModDate = infoOut->contentModDate = Darling::time_tToUTC(st.st_mtime);
		if (infoBits & kFSCatInfoAccessDate)
			infoOut->accessDate = Darling::time_tToUTC(st.st_atime);
	}

	return noErr;
}

bool hasgid(gid_t gid)
{
	gid_t* gids;
	int count;

	if (getegid() == gid)
		return true;

	while (true)
	{
		count = getgroups(0, nullptr);
		if (count == -1 && errno == EINVAL)
			continue;

		gids = (gid_t*) alloca(sizeof(gid_t)*count);
		if (getgroups(count, gids) != count)
		{
			count = 0;
			break;
		}
	}

	return std::find(gids, gids+count, gid) != (gids+count);
}

static std::string getUserDirsConfigPath()
{
	std::stringstream ss;
	const char *home, *config;
	
	config = getenv("XDG_CONFIG_HOME");
	
	if (!config)
	{
		home = getenv("HOME");
		if (!home)
			return std::string();
	
		ss << home << "/.config";
	}
	else
		ss << config;
	ss << "user-dirs.dirs";
	
	return ss.str();
}

static std::string extractXDGValue(const char* home, const std::string& line)
{
	regmatch_t matches[2];
	static regex_t regexp = []() -> regex_t {
		regex_t re;
		regcomp(&re, "=\"([^\"]+)\"", REG_EXTENDED);
		return re;
	}();
	
	if (regexec(&regexp, line.c_str(), 2, matches, 0) == 0)
	{
		std::string value = line.substr(matches[1].rm_so, matches[1].rm_eo - matches[1].rm_so);
		size_t pos = value.find("$HOME");
		
		if (pos != std::string::npos)
			value.replace(pos, 5, home);
		return value;
	}
	
	return std::string();
}

// TODO: Test this function!
OSStatus FSFindFolder(long vRefNum, OSType folderType, Boolean createFolder, FSRef* location)
{
	if (folderType == kTemporaryFolderType)
	{
		const char* tmpdir = getenv("TMPDIR");
		
		if (!tmpdir)
			tmpdir = "/tmp";
		
		FSPathMakeRef((const uint8_t*) tmpdir, location, nullptr);
		
		if (createFolder && access(tmpdir, F_OK) != 0)
			mkdir(tmpdir, 0777);
		
		return noErr;
	}
	else if (folderType == kDesktopFolderType || folderType == kSystemDesktopFolderType)
	{
		std::string xdgConfig = getUserDirsConfigPath();
		std::ifstream cfg(xdgConfig.c_str());
		std::string line, desktop;
		const char* home = getenv("HOME");
		
		desktop = home;
		desktop += "/Desktop";
	
		if (cfg.is_open())
		{
			while (std::getline(cfg, line))
			{
				if (line.compare(0, 17, "XDG_DESKTOP_DIR=\"") == 0)
				{
					std::string d = extractXDGValue(home, line);
					if (!d.empty())
						desktop = d;
					
					break;
				}
			}
		}
		
		FSPathMakeRef((const uint8_t*) desktop.c_str(), location, nullptr);
		
		if (createFolder && access(desktop.c_str(), F_OK) != 0)
			mkdir(desktop.c_str(), 0777);
		
		return noErr;
	}
	else
		return unimpErr;
}

OSErr PBCreateDirectoryUnicodeSync(FSRefParam* paramBlock)
{
	std::string path;
	
	if (!FSRefParamMakePath(paramBlock, path))
		return fnfErr;
	if (mkdir(path.c_str(), 0777) == -1)
		return makeOSStatus(errno);
	
	if (paramBlock->newRef)
		FSPathMakeRef((uint8_t*) path.c_str(), paramBlock->newRef, nullptr);
	
	return noErr;
}

OSErr PBCreateFileUnicodeSync(FSRefParam* paramBlock)
{
	std::string path;
	
	if (!FSRefParamMakePath(paramBlock, path))
		return fnfErr;
	if (open(path.c_str(), O_CREAT|O_EXCL, 0666) == -1)
		return makeOSStatus(errno);
	
	if (paramBlock->newRef)
		FSPathMakeRef((uint8_t*) path.c_str(), paramBlock->newRef, nullptr);
	
	return noErr;
}

OSErr PBGetCatalogInfoSync(FSRefParam *paramBlock)
{
	STUB();
	return unimpErr;
}

OSErr PBMakeFSRefUnicodeSync(FSRefParam *paramBlock)
{
	std::string path;
	
	if (!paramBlock->newRef)
		return paramErr;
	if (!FSRefParamMakePath(paramBlock, path))
		return fnfErr;
	FSPathMakeRef((uint8_t*) path.c_str(), paramBlock->newRef, nullptr);
	
	return noErr;
}

OSErr PBOpenForkSync(FSForkIOParam *paramBlock)
{
	STUB();
	return unimpErr;
}

OSErr PBReadForkSync(FSForkIOParam *paramBlock)
{
	STUB();
	return unimpErr;
}

OSErr PBWriteForkSync(FSForkIOParam *paramBlock)
{
	STUB();
	return unimpErr;
}

OSErr PBIterateForksSync(FSForkIOParam *paramBlock)
{
	STUB();
	return unimpErr;
}

OSErr PBCloseForkSync(FSForkIOParam *paramBlock)
{
	STUB();
	return unimpErr;
}

