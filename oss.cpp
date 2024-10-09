#include <iostream>
#include <unistd.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <stdio.h>
#include <cstring>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <signal.h>
#include <iomanip>
#include <ctime>
#include <cstdlib>
#include <fstream>
#include <sys/msg.h>

//https://forum.arduino.cc/t/when-to-use-const-int-int-or-define/668071
const int PERMS = 0644;
const int SH_KEY = 74821;
const int MSG_KEY = 49174;
const int BILLION = 1000000000;
const int MAX_PROCESSES = 20;

std::string logFile = "logfile";

struct PCB
{
    int occupied; // either true or false
    pid_t pid; // process id of this child
    int startSeconds; // time when it was forked
    int startNano; // time when it was forked
};

PCB pcb_table[MAX_PROCESSES];

struct Clock
{
    int seconds;
    int nanoseconds;
};

//https://stackoverflow.com/questions/41988823/is-this-how-message-queues-are-supposed-to-work
struct Message
{
    long msgtype; //type of msg
    pid_t pid; //pid of sender
    int action; //0 for terminate 1 for run
};

void signal_handler(int sig)
{
    std::cerr << "Timeout... terminating..." << std::endl;
    // code to send kill signal to all children based on their PIDs in process table
    for (int i = 0; i < MAX_PROCESSES; i++)
    {
        if (pcb_table[i].occupied == 1)
        {
            kill(pcb_table[i].pid, SIGKILL);
        }
    }

    // code to free up shared memory
    int shmid = shmget(SH_KEY, sizeof(Clock), 0);
    if (shmid != -1)
    {
        shmctl(shmid, IPC_RMID, nullptr);
    }

    msgctl(MSG_KEY, IPC_RMID, nullptr);
    exit(1);
}

void increment_clock(Clock *shared_clock, int activeChildren)
{
    if (activeChildren > 0)
    {
        shared_clock -> nanoseconds += 250000000 / activeChildren;
    }
    else
    {
        shared_clock -> nanoseconds += 250000000;
    }

    //increment seconds if nanoseconds = second
    if (shared_clock -> nanoseconds >= BILLION)
    {
        shared_clock -> nanoseconds -= BILLION;
        shared_clock -> seconds++;
    }
}

void output_to_log(const std::string &message)
{
    std::ofstream logFileStream(logFile, std::ios::app);
    if (logFileStream)
    {
        logFileStream << message << std::endl;
    }
    else
    {
        std::cerr << "Error: unable to open file." << std::endl;
    }
}

void send_message(int msgid, pid_t pid, Clock *shared_clock)
{
    Message msg;
    msg.msgtype = 1;
    msg.pid = pid;

    if (msgsnd(msgid, &msg, sizeof(msg) - sizeof(long), 0) == -1)
    {
        std::cerr << "Error: msgnd failed." << std::endl;
    }
    //output to log
    std::string log_message = "OSS: Sending message to worker " + std::to_string(msg.pid) +
    " at time " + std::to_string(shared_clock -> seconds) + ":" +
    std::to_string(shared_clock -> nanoseconds);

    std::cout << log_message << std::endl;
    output_to_log(log_message);
}

Message receive_message(int msgid, Clock *shared_clock)
{
    Message msg;
    if (msgrcv(msgid, &msg, sizeof(msg) - sizeof(long), 0, 0) ==-1)
    {
        std::cerr << "Error: msgrcv failed." << std::endl;
    }
    //output to log
    std::string log_message = "OSS: Receiving message from worker " + std::to_string(msg.pid) +
    " at time " + std::to_string(shared_clock -> seconds) + ":" +
    std::to_string(shared_clock -> nanoseconds);

    std::cout << log_message << std::endl;
    output_to_log(log_message);

    return msg;
}

void print_process_table(PCB pcb_table[], Clock* shared_clock)
{
    std::cout << "OSS PID: " << getpid() <<
    " SysClockS: " << shared_clock -> seconds <<
    " SysCLockNano: " << shared_clock -> nanoseconds <<
    "\nProcess Table:" <<
    "\n--------------------------------------------------------" << std::endl;
    std::cout << std::setw(10) << "Entry" <<
    std::setw(10) << "Occupied" <<
    std::setw(10) << "PID" <<
    std::setw(10) << "StartS" <<
    std::setw(10) << "StartN" <<
    std::endl;

    for (int i = 0; i < MAX_PROCESSES; i++)
    {
        std::cout << std::setw(10) << i <<
        std::setw(10) << pcb_table[i].occupied <<
        std::setw(10) << pcb_table[i].pid <<
        std::setw(10) << pcb_table[i].startSeconds <<
        std::setw(10) << pcb_table[i].startNano <<
        std::endl;
    }
    std::cout << "--------------------------------------------------------" << std::endl;
}

int main(int argc, char* argv[])
{
    //use time and pid to generate random number
    //https://stackoverflow.com/questions/322938/recommended-way-to-initialize-srand
    srand((time(nullptr) + getpid()));

    //set up alarm
    signal(SIGALRM, signal_handler);
    alarm(60);

    //initialize variables for getopt
    int opt;
    int numChildren = 1;
    int numSim = 1;
    int timeLimSec = 1;
    int intervalMs = 100;

    while((opt = getopt(argc, argv, ":hn:s:t:i:f:")) != -1) //set optional args
        {
            switch(opt)
            {
                //help menu
                case 'h':
                    std::cout << "Help menu:\n" ;
                    std::cout << "**********************\n" ;
                    std::cout << "-h: display help menu\n" ;
                    std::cout << "-n: set number of child processes\n" ;
                    std::cout << "-s: set number of simultaneous children\n" ;
                    std::cout << "-t: set time limit for children in seconds\n" ;
                    std::cout << "-i: set interval in ms between launching children\n" ;
		    std::cout << "-f: choose file for oss output\n" ;
                    std::cout << "**********************\n" ;
                    std::cout << "Example invocation: \n" ;
                    std::cout << "./oss -n 5 -s 3 -t 7 -i 100\n" ;
                    std::cout << "Example will launch 5 child processes, with time limit between 1s and 7s,";
                    std::cout << "\nwith a time delay between new children of 100 ms\n" ;
                    std::cout << "\nand never allow more than 3 child processes to run simultaneously.\n" ;
                    return 0;
                case 'n':
                    numChildren = atoi(optarg); //assign arg value to numChildren
                    break;
                case 's':
                    numSim = atoi(optarg); //assign arg value to numSim
                    break;
                case 't':
                    timeLimSec = atoi(optarg);
                    break;
                case 'i':
                    intervalMs = atoi(optarg);
                    break;
		case 'f':
		    logFile = optarg;
		    break;
                default:
                    std::cerr << "Please choose an option!\n" ;
                    std::cout << "Example invocation: \n" ;
                    std::cout << "./oss -n 5 -s 3 -t 7 -i 100\n" ;
                    return 1;
            }
        }

        if (numChildren <=0 || numSim <= 0 || timeLimSec <=0 || intervalMs <= 0)
        {
            std::cerr << "Please choose a valid number greater than 0." << std::endl;
            return 1;
        }
        if (numChildren > 20 || numSim > 20 || timeLimSec >= 60 || intervalMs >= 60000)
        {
            std::cerr << "Please choose a reasonable number. Max time: 60." << std::endl;
            return 1;
        }

    long long launchIntervalSeconds = intervalMs / 1000;
    long long launchIntervalNs = (intervalMs / 1000) * 1000000;

    //create shared mem: 0644 r/w to owner
    int shmid = shmget(SH_KEY, sizeof(Clock), PERMS | IPC_CREAT);
    if (shmid == -1)
    {
        std::cerr << "Error: Shared memory get failed" << std::endl;
        return 1;
    }

    //attach shared mem
    Clock *shared_clock = static_cast<Clock*>(shmat(shmid, nullptr, 0));
    if (shared_clock == (void*)-1)
    {
        std::cerr << "Error: shmat" << std::endl;
        return 1;
    }

    //set clock nano/seconds to 0
    shared_clock -> seconds = 0;
    shared_clock -> nanoseconds = 0;

    // create our message queue with 0644 perms
    int msgid;
    if ((msgid = msgget(MSG_KEY, PERMS | IPC_CREAT)) == -1)
    {
        std::cerr << "Error: msgget in parent" << std::endl;
        exit(1);
    }

    //for loops
    int activeChildren = 0;
    int launchedChildren = 0;
    long lastPrintTime = 0;

    long long nextLaunchTimeNs = shared_clock -> nanoseconds + launchIntervalNs;
	long long nextLaunchTimeSec = shared_clock -> seconds + launchIntervalSeconds;

    while (true)
    {
        increment_clock(shared_clock, activeChildren);

        long long currentTime = static_cast<long long>(shared_clock->seconds) * BILLION + shared_clock->nanoseconds;

        //check for terminated processes
        int status;
        pid_t pid = waitpid(-1, &status, WNOHANG);

        //clear out unoccupied lines in pcb table
        if (pid > 0)
        {
            for (int i = 0; i < MAX_PROCESSES; i++)
            {
                if (pcb_table[i].pid == pid)
                {
                    pcb_table[i].occupied = 0;
                    pcb_table[i].pid = 0;
                    pcb_table[i].startSeconds = 0;
                    pcb_table[i].startNano = 0;
                    activeChildren--;
                    break;
                }
            }
        }

        if (msgid != -1)
        {
            Message msg = receive_message(msgid, shared_clock);
        }

        if (currentTime - lastPrintTime >= 500000000)
        {
            print_process_table(pcb_table, shared_clock);
            lastPrintTime = currentTime;
        }
        //launch new children under simultaneous limit
        //launch new children if under simultaneous limit
        if (activeChildren < numSim && launchedChildren < numChildren &&
        (shared_clock->seconds > nextLaunchTimeSec ||
        (shared_clock->seconds == nextLaunchTimeSec && shared_clock->nanoseconds >= nextLaunchTimeNs)))
        {
            //check to make sure it's not more than 20 at a time, add to table
            for (int i = 0; i < MAX_PROCESSES; i++)
            {
                //make sure the pcb table line isn't occupied
                if (!pcb_table[i].occupied)
                {
                    pid_t new_pid = fork();

                    if (new_pid < 0)
                    {
                        std::cerr << "Error: fork issue." << std::endl;
                        return 1;
                    }
                    else if (new_pid == 0)
                    {
                        //child process

                        //assign random value between 1 and input
                        int randomSec = rand() % timeLimSec + 1;
                        int randomNano = rand() % BILLION;

                        std::string randomSecStr = std::to_string(randomSec);
                        std::string randomNanoStr = std::to_string(randomNano);

                        execl("./worker", "worker", randomSecStr.c_str(), randomNanoStr.c_str(), nullptr);
                        std::cerr << "Error: execl failed" << std::endl;
                        return 1;
                    }
                    else
                    {
                        //parent process
                        pcb_table[i].occupied = 1;
                        pcb_table[i].pid = new_pid;
                        pcb_table[i].startSeconds = shared_clock -> seconds;
                        pcb_table[i].startNano = shared_clock -> nanoseconds;
                        activeChildren++;
                        launchedChildren++;

                        send_message(msgid, new_pid, shared_clock);

                        break;
                    }
                }
            }
            //update next launch time
            nextLaunchTimeSec = shared_clock->seconds + launchIntervalSeconds;
            nextLaunchTimeNs = shared_clock->nanoseconds + launchIntervalNs;
            if (nextLaunchTimeNs >= BILLION)
            {
                nextLaunchTimeSec++;
                nextLaunchTimeNs -= BILLION;
            }
        }
        if (launchedChildren >= numChildren && activeChildren == 0)
        {
            break;
        }
    }

    shmdt(shared_clock);
    shmctl(shmid, IPC_RMID, nullptr);
    return 0;
}
