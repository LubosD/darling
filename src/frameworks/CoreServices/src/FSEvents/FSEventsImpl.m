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

#import "FSEventsImpl.h"
#import <Foundation/NSDictionary.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <darling/emulation/syscall/linux/ext/sys/inotify.h>

static dispatch_queue_t g_fsEventsQueue = NULL;

static void rlPerform(void* info)
{
	FSEventsImpl* fse = (FSEventsImpl*) info;
	[fse _doCallback];
}

@implementation FSEventsImpl

-(instancetype)initWithPaths:(NSArray*)pathsToWatch
					flags:(FSEventStreamCreateFlags)flags
					context:(FSEventStreamContext*)context
					callback:(FSEventStreamCallback)callback
{
	_pathsToWatch = [[NSArray alloc] initWithArray:pathsToWatch];
	_flags = flags;
	_callback = callback;
	_fd = inotify_init1(IN_NONBLOCK);

	if (_fd == -1)
	{
		[self release];
		return nil;
	}

	if (context)
	{
		_context = *context;
		if (_context.retain)
			_context.info = (void*) _context.retain(_context.info);
	}

	CFRunLoopSourceContext rlcontext = {0};
	rlcontext.info = self;
	rlcontext.perform = rlPerform;

	_rlSource = CFRunLoopSourceCreate(NULL, 0, &rlcontext);
	NSMutableDictionary* wdmap = [[NSMutableDictionary alloc] initWithCapacity: [_pathsToWatch count]];

	for (NSString* path in _pathsToWatch)
	{
		int wd = inotify_add_watch(_fd, [path UTF8String], IN_ATTRIB | IN_CREATE | IN_DELETE | IN_DELETE_SELF | IN_MODIFY | IN_MOVE);
		[wdmap setObject: path
				forKey: [NSNumber numberWithInt: wd]];
	}
	_wdMap = [[NSDictionary alloc] initWithDictionary: wdmap];
	[wdmap release];

	static dispatch_once_t once;
	dispatch_once(&once, ^{
		g_fsEventsQueue = dispatch_queue_create("FSEvents queue", DISPATCH_QUEUE_SERIAL);
	});

	_source = dispatch_source_create(DISPATCH_SOURCE_TYPE_READ, _fd, 0, g_fsEventsQueue);
	dispatch_source_set_event_handler(_source, ^{
		[self _readEvents];
	});

	_pathArray = [[NSMutableArray alloc] init];
	_runloops = CFBagCreateMutable(NULL, 0, &kCFTypeBagCallBacks);

	return self;
}

-(void) dealloc
{
	if (_context.release)
		_context.release(_context.info);

	if (_source)
	{
		dispatch_suspend(_source);
		dispatch_release(_source);
	}
	if (_rlSource)
		CFRelease(_rlSource);
	if (_runloops)
		CFRelease(_runloops);

	[self invalidate];

	if (_fd != -1)
		close(_fd);

	[_pathsToWatch release];
	[_pathArray release];
	[_wdMap release];
	free(_flagArray);
	free(_idArray);
	[super dealloc];
}

-(NSArray*)copyPathsToWatch
{
	return [_pathsToWatch retain];
}

-(void)setDispatchQueue:(dispatch_queue_t)queue
{
	if (_queue)
	{
		dispatch_release(_queue);
		_queue = NULL;
	}
	if (queue)
	{
		_queue = queue;
		dispatch_retain(_queue);
	}
}

-(void)scheduleWithRunLoop:(CFRunLoopRef)rl
					mode:(CFStringRef)rlMode
{
	@synchronized(self)
	{
		CFBagAddValue(_runloops, rl);
	}
	CFRunLoopAddSource(rl, _rlSource, rlMode);
}

-(void)unscheduleWithRunLoop:(CFRunLoopRef)rl
					mode:(CFStringRef)rlMode
{
	@synchronized(self)
	{
		CFBagRemoveValue(_runloops, rl);
	}
	CFRunLoopRemoveSource(rl, _rlSource, rlMode);
}

-(void)invalidate
{
	[self setDispatchQueue: NULL];
	CFRunLoopSourceInvalidate(_rlSource);
}

-(void)start
{
	if (!_running)
	{
		dispatch_resume(_source);
		_running = TRUE;
	}
}

-(void)stop
{
	if (_running)
	{
		dispatch_suspend(_source);
		_running = FALSE;
	}
}

-(FSEventStreamEventId)lastEventID
{
	return _lastEventID;
}

-(void)_readEvents
{
	const size_t bytes = sizeof(struct inotify_event) + 4096 + 1;
	struct inotify_event* evt = (struct inotify_event*) malloc(bytes);

	while (1)
	{
		int rd = read(_fd, evt, bytes);
		if (rd < 0)
		{
			if (errno == EINTR)
				continue;
			else if (errno == EAGAIN || errno == EWOULDBLOCK)
				break;
			else
			{
				[self stop];
				break;
			}
		}
		else
		{
			[self _processSingleEvent: evt];
		}
	}

	free(evt);
	[self _dispatchEvents];
}

-(void)_processSingleEvent:(struct inotify_event*)evt
{
	FSEventStreamEventFlags flags = 0;
	NSString* fullPath;

	NSString* watchPath = [_wdMap objectForKey: [NSNumber numberWithInt: evt->wd]];
	if (!watchPath)
		return;

	if (!(_flags & kFSEventStreamCreateFlagFileEvents))
	{
		fullPath = watchPath;
	}
	else
	{
		if (evt->mask & IN_ISDIR)
			flags |= kFSEventStreamEventFlagItemIsDir;
		else
			flags |= kFSEventStreamEventFlagItemIsFile; // TODO: symlinks
		
		if (evt->mask & (IN_DELETE|IN_DELETE_SELF))
			flags |= kFSEventStreamEventFlagItemRemoved;
		if (evt->mask & (IN_MOVE_SELF|IN_MOVED_FROM|IN_MOVED_TO))
			flags |= kFSEventStreamEventFlagItemRenamed;
		if (evt->mask & (IN_MODIFY))
			flags |= kFSEventStreamEventFlagItemModified;
		if (evt->mask & (IN_CREATE))
			flags |= kFSEventStreamEventFlagItemCreated;
		if (evt->mask & IN_ATTRIB)
			flags |= kFSEventStreamEventFlagItemChangeOwner | kFSEventStreamEventFlagItemXattrMod;

		if (evt->len == 0)
			fullPath = watchPath;
		else
			fullPath = [NSString stringWithFormat: @"%s/%s", [watchPath UTF8String], evt->name];
	}

	[_pathArray addObject: fullPath];
	const int newCount = [_pathArray count];

	_flagArray = (FSEventStreamEventFlags*) realloc(_flagArray, sizeof(*_flagArray) * newCount);
	_flagArray[newCount-1] = flags;

	_idArray = (FSEventStreamEventId*) realloc(_idArray, sizeof(*_idArray) * newCount);
	_idArray[newCount-1] = ++_lastEventID;
}

-(void)_dispatchEvents
{
	if (_queue)
	{
		[self retain];
		dispatch_async(_queue, ^{
			[self _doCallback];
		});
	}
	else
	{
		[self retain];
		CFRunLoopSourceSignal(_rlSource);

		@synchronized(self)
		{
			CFBagApplyFunction(_runloops, (CFBagApplierFunction) CFRunLoopWakeUp, NULL);
		}
	}
}

-(void)_doCallback
{
	void* ptrToPass = _pathArray;
	char** cpathArray = NULL;
	NSArray<NSDictionary*>* dicts = NULL;

	dispatch_suspend(_source);
	dispatch_sync(g_fsEventsQueue, ^{});
	
	if (!(_flags & kFSEventStreamCreateFlagUseCFTypes))
	{
		@autoreleasepool
		{
			cpathArray = (char**) malloc(sizeof(char*) * [_pathArray count]);
			for (int i = 0; i < [_pathArray count]; i++)
				cpathArray[i] = strdup([[_pathArray objectAtIndex: i] UTF8String]);
		}
		ptrToPass = cpathArray;
	}
	else if (_flags & kFSEventStreamCreateFlagUseExtendedData)
	{
		NSDictionary** dd = (NSDictionary**) malloc(sizeof(NSDictionary*) * [_pathArray count]);

		for (int i = 0; i < [_pathArray count]; i++)
		{
			dd[i] = @{
				((NSString*) kFSEventStreamEventExtendedDataPathKey) : [_pathArray objectAtIndex: i]
			};
		}

		dicts = [[NSArray alloc] initWithObjects:dd
										count: [_pathArray count]];
		free(dd);
		ptrToPass = dicts;
	}

	_callback((ConstFSEventStreamRef) self, _context.info,
		[_pathArray count],
		ptrToPass,
		_flagArray, _idArray);

	if (cpathArray != NULL)
	{
		for (int i = 0; i < [_pathArray count]; i++)
			free(cpathArray[i]);
		free(cpathArray);
	}

	if (dicts)
		[dicts release];

	free(_flagArray);
	_flagArray = NULL;

	free(_idArray);
	_idArray = NULL;

	[_pathArray removeAllObjects];
	dispatch_resume(_source);
	[self release];
}

@end
