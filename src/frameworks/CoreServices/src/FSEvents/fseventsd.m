/*
 This file is part of Darling.

 Copyright (C) 2020 Lubos Dolezel

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

#include <sys/socket.h>
#include <sys/un.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <darling/emulation/syscall/linux/ext/fanotify.h>
#include <darling/emulation/syscall/linux/ext/file_handle.h>
#include "./linux/fanotify.h"
#include <dispatch/dispatch.h>
#include <CoreServices/FileManager.h>
#import <Foundation/NSObjCRuntime.h>
#import <Foundation/NSDictionary.h>
#include "fseventsd.h"

int g_listenSocket, g_fanotify;

void setupListenSocket(void);
void handleNewConnection(int fd);
void setupFANotify(void);

int main()
{
	setupListenSocket();
	setupFANotify();

	dispatch_main();
	return 0;
}

void setupListenSocket(void)
{
	struct sockaddr_un sa;
	sa.sun_family = AF_UNIX;

	strcpy(sa.sun_path, FSEVENTSD_SOCKET_PATH);
	unlink(FSEVENTSD_SOCKET_PATH);

	g_listenSocket = socket(AF_UNIX, SOCK_SEQPACKET, 0);
	if (g_listenSocket == -1)
	{
		perror("bind");
		exit(EXIT_FAILURE);
	}

	int rv = bind(g_listenSocket, (const struct sockaddr *) &sa, sizeof(sa));
	if (rv == -1)
	{
		perror("bind");
		exit(EXIT_FAILURE);
	}

	rv = listen(g_listenSocket, 5);
	if (rv == -1)
	{
		perror("listen");
		exit(EXIT_FAILURE);
	}

	dispatch_source_t listenerSource = dispatch_source_create(DISPATCH_SOURCE_TYPE_READ, g_listenSocket, 0, dispatch_get_main_queue());
	dispatch_source_set_event_handler(listenerSource, ^{
		struct sockaddr_un sa;
		sa.sun_family = AF_UNIX;

		socklen_t len = sizeof(sa);

		int rv = accept(g_listenSocket, (struct sockaddr*) &sa, &len);
		if (rv >= 0)
			handleNewConnection(rv);
	});
	dispatch_resume(listenerSource);
}

void handleClientCommand(int fd, const fseventsd_monitor_t* cmd)
{

}

void handleNewConnection(int fd)
{
	dispatch_source_t socketSource = dispatch_source_create(DISPATCH_SOURCE_TYPE_READ, fd, 0, dispatch_get_main_queue());

	dispatch_source_set_event_handler(socketSource, ^{
		fseventsd_monitor_t cmd;
		struct msghdr msg;
		struct iovec iov = {
			.iov_base = &cmd,
			.iov_len = sizeof(cmd)
		};

		memset(&msg, 0, sizeof(msg));
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;

		recvmsg(fd, &msg, 0);
		int rv = read(fd, &cmd, sizeof(cmd));

		if (rv == sizeof(cmd))
			handleClientCommand(fd, &cmd);
	});

	dispatch_resume(socketSource);
}

void fileHandleToFSRef(const struct file_handle* fh, FSRef* ref)
{
	static FSRef rootRef;
	static dispatch_once_t once;

	dispatch_once(&once, ^{
		FSPathMakeRef((const UInt8*) "/", &rootRef, NULL);
	});

	RefData* refData = (RefData*) ref;
	refData->mount_id = ((RefData*)&rootRef)->mount_id;

	memcpy(&refData->fh, fh, sizeof(FSRef) - sizeof(refData->mount_id));
}

void setupFANotify(void)
{
	// FAN_REPORT_FID = provide file handles
	// Linux file handle = FSRef in Darling
	g_fanotify = linux_fanotify_init(FAN_REPORT_FID, 0);
	if (g_fanotify == -1)
	{
		perror("linux_fanotify_init");
		exit(EXIT_FAILURE);
	}

	int rv = linux_fanotify_mark(g_fanotify, FAN_MARK_ADD | FAN_MARK_FILESYSTEM,
		FAN_CREATE | FAN_DELETE | FAN_MOVED_FROM | FAN_MOVED_TO | FAN_MODIFY | FAN_ONDIR, AT_FDCWD, "/");
	if (rv == -1)
	{
		perror("linux_fanotify_mark");
		exit(EXIT_FAILURE);
	}

	dispatch_source_t faSource = dispatch_source_create(DISPATCH_SOURCE_TYPE_READ, g_fanotify, 0, dispatch_get_main_queue());

	dispatch_source_set_event_handler(faSource, ^{
		char events_buf[4096];
		int len = read(g_fanotify, events_buf, sizeof(events_buf));
		printf("Read %d bytes of event data\n", len);

		for (struct fanotify_event_metadata* metadata = (struct fanotify_event_metadata *) events_buf;
            FAN_EVENT_OK(metadata, len);
            metadata = FAN_EVENT_NEXT(metadata, len))
		{
			printf("Event mask: 0x%x\n", metadata->mask);
			struct fanotify_event_info_fid* fid = (struct fanotify_event_info_fid *) (metadata + 1);
			if (fid->hdr.info_type == FAN_EVENT_INFO_TYPE_FID)
			{
				struct file_handle* fh = (struct file_handle *) fid->handle;
				FSRef fsref;

				printf("fileHandleToFSRef: bytes: %d, type: %d\n", fh->handle_bytes, fh->handle_type);
				fileHandleToFSRef(fh, &fsref);

				char pathbuf[1024];
				printf("FSRefMakePath\n");
				if (FSRefMakePath(&fsref, (UInt8*)pathbuf, sizeof(pathbuf)) != 0)
					puts("FSRefMakePath failed");
				else
					printf("Event on %s\n", pathbuf);
			}
			else
			{
				puts("Not a FID");
			}
			printf("---\n");
		}
	});

	dispatch_resume(faSource);
}
