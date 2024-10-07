#include <iostream>
#include <unistd.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <stdio.h>
#include <cstring>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/shm.h>

struct Clock
{
    int seconds;
    int nanoseconds;
};

struct Message
{
    long msgtype; //type of msg
    pid_t pid;
    int x; //1 continue 0 terminate
}

const int SH_KEY = 74821;

int main(int argc, char *argv[])
{
    int maxSec = std::atoi(argv[1]);
    int maxNsec = std::atoi(argv[2]);

    //https://stackoverflow.com/questions/55833470/accessing-key-t-generated-by-ipc-private
    int shmid = shmget(SH_KEY, sizeof(Clock), 0666); //<-----
    if (shmid == -1)
    {
        std::cerr << "Worker: Error: Shared memory get failed" << std::endl;
        return 1;
    }

    //attach shared mem
    Clock *shared_clock = static_cast<Clock*>(shmat(shmid, nullptr, 0));
    if (shared_clock == (void*)-1)
    {
        std::cerr << "Worker: Error: shmat" << std::endl;
        return 1;
    }

    int termSec = shared_clock -> seconds + maxSec;
    int termNsec = shared_clock -> nanoseconds + maxNsec;

    if (termNsec >= 1000000000)
    {
        termSec += termNsec / 1000000000;
        termNsec = termNsec % 1000000000;
    }

    std::cout << "\n\nWorker PID: " << getpid() << " PPID: " << getppid() <<
    " SysClockS: " << shared_clock -> seconds <<  " SysClockNano: " << shared_clock -> nanoseconds <<
    " TermTimeS: " << termSec << " TermTimeNano: " << termNsec <<
    "\n Starting.......\n\n" << std::endl;

    int lastSec = shared_clock -> seconds;
    int startSec = shared_clock -> seconds;

    while (shared_clock -> seconds < termSec ||
    (shared_clock -> seconds == termSec && shared_clock -> nanoseconds < termNsec))
    {
        if (shared_clock -> seconds != lastSec)
        {
            int elapsedSec = shared_clock -> seconds - startSec;
            //print info again
            lastSec = shared_clock -> seconds;
            std::cout << "\n\nWorker PID: " << getpid() << " PPID: " << getppid() <<
            " SysClockS: " << shared_clock -> seconds <<  " SysClockNano: " << shared_clock -> nanoseconds <<
            " TermTimeS: " << termSec << " TermTimeNano: " << termNsec << std::endl;
            std::cout << "--" << elapsedSec << " seconds have passed since starting" << std::endl;
        }
    }

    std::cout << "\n\nWorker PID: " << getpid() << " PPID: " << getppid() <<
    " SysClockS: " << shared_clock -> seconds <<  " SysClockNano: " << shared_clock -> nanoseconds <<
    " TermTimeS: " << termSec << " TermTimeNano: " << termNsec << std::endl;

    if (shmdt(shared_clock) == -1)
    {
        std::cerr << "Worker: error: shmdt" << std::endl;
        return 1;
    }

    std::cout << "\n Terminating.......\n\n" << std::endl;

    return 0;
}
