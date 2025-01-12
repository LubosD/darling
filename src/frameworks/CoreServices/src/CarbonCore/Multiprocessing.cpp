/*
This file is part of Darling.

Copyright (C) 2012-2013 Lubos Dolezel

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

#include <CarbonCore/Multiprocessing.h>
#include <unistd.h>
#include <ctime>
#include <pthread.h>
#include <CarbonCore/MacErrors.h>

Boolean _MPIsFullyInitialized()
{
	return true;
}

OSStatus MPDelayUntil(AbsoluteTime* time)
{
	struct timespec ts = { time_t(*reinterpret_cast<uint64_t*>(time) / 1000000000ll), long(*reinterpret_cast<uint64_t*>(time) % 1000000000ll) };
	nanosleep(&ts, nullptr);
	return noErr;
}

unsigned long MPProcessors()
{
	return sysconf(_SC_NPROCESSORS_ONLN);
}

OSStatus MPCreateCriticalRegion(MPCriticalRegionID* criticalRegion)
{
	pthread_mutex_t* pp = new pthread_mutex_t;
	pthread_mutexattr_t attr;

	pthread_mutexattr_init(&attr);
	pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
	*criticalRegion = pp;
	
	pthread_mutex_init(pp, &attr);
	return noErr;
}

OSStatus MPDeleteCriticalRegion(MPCriticalRegionID criticalRegion)
{
	pthread_mutex_t* pp = (pthread_mutex_t*) criticalRegion;
	
	if (pp != nullptr)
	{
		pthread_mutex_destroy(pp);
		delete pp;
	}
	
	return noErr;
}

OSStatus MPEnterCriticalRegion(MPCriticalRegionID criticalRegion, Duration timeout)
{
	pthread_mutex_t* pp = (pthread_mutex_t*) criticalRegion;
	
	if (!pp)
		return paramErr;
	
	if (timeout == kDurationForever)
	{
		pthread_mutex_lock(pp);
		return noErr;
	}
	else
	{
		do
		{
			if (pthread_mutex_trylock(pp) == 0)
				return noErr;
			
			if (timeout > 0)
			{
				usleep(10*1000);
				timeout -= 10;
			}
		}
		while (timeout > 0);
		
		return kMPTimeoutErr;
	}
}

OSStatus MPExitCriticalRegion(MPCriticalRegionID criticalRegion)
{
	pthread_mutex_t* pp = (pthread_mutex_t*) criticalRegion;
	
	if (pp != nullptr)
	{
		pthread_mutex_unlock(pp);
		return noErr;
	}
	else
		return paramErr;
}
