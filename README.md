Author: S. England
Date: 10/11/24

Usage:
./oss -h [help] -n [# of children] -s [# of simultaneous child processes] -i [interval between launches] -t [random time cap] -f [logfile]

ISSUE:
worker: msgrcv fails no matter what. I have tried changing it to a static variable. I rewrote the entire oss main function using the pseudocode provided.
I used IPC_WAIT in the oss call to see if non-blocking would fix it for testing. This worked and after one iteration 
oss and worker could send messages. However this priject requires blocking.
I added debugging statements to try to figure out if something else was going wrong. i am not sure why worker cannot receive messages.
oss uses the msgtype of the pid of the child to send the message, and worker should be using its own pid to check. when i use output statements,
this is confirmed, however the msgrcv call still fails.

Git log:

made some final changes 7england 5 minutes ago
made some final changes 7england 36 minutes ago
Merge remote-tracking branch 'origin/main' 7england 56 minutes ago
oss: edited msgrcv and msgsnd calls worker: edited msgrcv and msgsnd calls issue: worker hangs when waiting for message from oss 7england 56 minutes ago
oss: rewrote main function to match pseudocode more closely... issue: forks but then is able to immediately send messages in infinite loop to child and print pcb table indefinitely before child actually execs S. England* Yesterday 11:46 PM
oss: rewrote main function to match pseudocode more closely... issue: forks but then is able to immediately send messages in infinite loop to child and print pcb table indefinitely before child actually execs S. England Yesterday 11:46 PM
oss: placement of send and receive functions, termination logic adjusted worker: fixed infinite loop in main S. England 10/9/2024 12:42 AM
OSS: quick fixes S. England 10/8/2024 9:35 PM
OSS: update increment function to increment by 250 ms divided by num of children, cleaned up global variables using const int worker: implemented messaging, updated look to check for termination condition and msg info to oss, changed output statements, do while loop iterations for output instead of based on time S. England 10/8/2024 9:34 PM
added message queue creation in main using MSG_KEY, added msg send and receive calls in main loop, finalized output to log function S. England 10/7/2024 8:35 PM
added Message struct OSS: added send and receive functions, print log function S. England 10/6/2024 10:30 PM
Update oss.cpp 7england* 9/27/2024 6:01 PM
Update worker.cpp 7england* 9/27/2024 5:52 PM
Update oss.cpp 7england* 9/27/2024 5:51 PM
Create worker.cpp 7england* 9/27/2024 5:50 PM
Create oss.cpp 7england* 9/27/2024 5:49 PM
Create makefile 7england* 9/27/2024 5:49 PM

https://github.com/7england/opsys-p3
