#include <iostream>
#include <unistd.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <stdio.h>
#include <cstring>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/msg.h>

const int SH_KEY = 74821;
const int MSG_KEY = 49174;
const int PERMS = 0644;
const int BILLION = 1000000000;

struct Clock
{
    int seconds;
    int nanoseconds;
};

struct Message
{
    long msgtype; //type of msg
    pid_t pid; //pid of sender
    int action; //0 for terminate 1 for run
};

int main(int argc, char *argv[])
{
    int maxSec = std::atoi(argv[1]);
    int maxNsec = std::atoi(argv[2]);

    //https://stackoverflow.com/questions/55833470/accessing-key-t-generated-by-ipc-private
    int shmid = shmget(SH_KEY, sizeof(Clock), PERMS); //<-----
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

    //get our message queue with 0644 perms
    int msgid;
    if ((msgid = msgget(MSG_KEY, PERMS)) == -1)
    {
        std::cerr << "Error: msgget in worker" << std::endl;
        exit(1);
    }

    int termSec = shared_clock -> seconds + maxSec;
    int termNsec = shared_clock -> nanoseconds + maxNsec;

    if (termNsec >= BILLION)
    {
        termSec += termNsec / BILLION;
        termNsec = termNsec % BILLION;
    }

    std::cout << "\n\nWorker PID: " << getpid() << " PPID: " << getppid() <<
    " SysClockS: " << shared_clock -> seconds <<  " SysClockNano: " << shared_clock -> nanoseconds <<
    " TermTimeS: " << termSec << " TermTimeNano: " << termNsec <<
    "\n Starting.......\n\n" << std::endl;

    Message msg;
    int iterationCount = 0;

    //do while loop from proj specs
    do
    {
        //message rcv from oss
        if (msgrcv(msgid, &msg, sizeof(msg) - sizeof(long), getpid(), 0) == -1)
        {
            std::cerr << "Worker: Error: msgrcv failed" << std::endl;
            return 1;
        }

        iterationCount++;

        //check if we're out of time (reversed from other project to break if opp true
        if (shared_clock -> seconds > termSec ||
        (shared_clock -> seconds == termSec && shared_clock -> nanoseconds >= termNsec))
        {
            //print info again
            std::cout << "\n\nWorker PID: " << getpid() << " PPID: " << getppid() <<
            " SysClockS: " << shared_clock -> seconds <<  " SysClockNano: " << shared_clock -> nanoseconds <<
            " TermTimeS: " << termSec << " TermTimeNano: " << termNsec << std::endl;
            std::cout << "Terminating after sending message back to oss after" << iterationCount << " iteration(s) has/have passed" << std::endl;

            msg.msgtype = 1;
            msg.pid = getpid();
            msg.action = 0;
            if (msgsnd(msgid, &msg, sizeof(msg) - sizeof(long), 0) ==-1)
            {
                std::cerr << "Worker: Error: msgsnd failed" << std::endl;
                return 1;
            }
            //determine if it is time to terminate
            break;
        }
        else
        {
            std::cout << "\n\nWorker PID: " << getpid() << " PPID: " << getppid() <<
            " SysClockS: " << shared_clock -> seconds <<  " SysClockNano: " << shared_clock -> nanoseconds <<
            " TermTimeS: " << termSec << " TermTimeNano: " << termNsec << std::endl;
            std::cout << "--" << iterationCount << " iteration(s) has/have passed since starting" << std::endl;


            msg.msgtype = 1;
            msg.pid = getpid();
            msg.action = 1;

            if (msgsnd(msgid, &msg, sizeof(msg) - sizeof(long), 0) ==-1)
            {
                std::cerr << "Worker: Error: msgsnd failed" << std::endl;
                return 1;
            }
        }

    } while (true);

    if (shmdt(shared_clock) == -1)
    {
        std::cerr << "Worker: error: shmdt" << std::endl;
        return 1;
    }

    return 0;
}
