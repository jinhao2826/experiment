This is my project of middlepolice. 

Congratulation! It has published in ACM CCS 16

At First, please see my architecture.pdf

Secondly, Please read the MiddlePolice Experiments that tell you how to build the topology and how to set the environments.

NOTE: Please Use the mbox_official.c victim_official.c. THESE ARE LATEST VERSION.
THE LOG IS reocrded in /var/log/syslog.
You also can see my log example /var/log/syslog.

Limitation:
ABOUT KVM VIRTUAL MACHINE

I have try on KVM Virtual machines. We meet some problem in Virtual Machines.
The main problems is we can not get the linear sk_buff. This problem is probably caused by TSO and GSO in my opinion.
