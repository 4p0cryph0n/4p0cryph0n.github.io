---
title: "OT Security: IEC 104 Attack and Defend"
header:
  teaser: /assets/images/iec104.png
  teaser_home_page: true
categories:
  - OT Security
classes: wide
tags:
  - OT-Security
toc: true
toc_label: Contents
---
## Objective ##

In the ever-evolving landscape of cyber threats, let us have a look at a rapidly developing domain in cyber-security; Operational Technology (OT) Security. In this post, we will be engaging in an attack and defend exercise targeting IEC 104 - a communication protocol used by various types of OT/ICS systems.

## Threats towards OT Systems - A Quick Introduction

In order for us to understand the importance of OT security and the ever-growing threat landscape, let's take a look at a geo-political warfare case.

During the Russia-Ukraine war, [Mandiant](https://cloud.google.com/blog/topics/threat-intelligence/sandworm-disrupts-power-ukraine-operational-technology/) documented a coordinated cyber campaign by Russian state-sponsored threat groups. A key aggressor in this campaign was an APT tracked as Sandworm (a.k.a APT44), which has been attributed to Russian intelligence (GRU).

Sandworm utilized custom OT/ICS malware, namely INDUSTROYER.V2, to perform targeted attacks on Ukraine energy infrastructure. These attacks were coordinated with physical missile and drone attacks on substations to increase damage and gain tactical advantage, especially since this war was going on during the winters.

This case, among many, shows the rapid evolution of OT threats and how they fit into the bigger pictures such as cyberwarfare. It also highlights the importance of shifting our glance as an industry to securing these OT/ICS systems in order to ensure that critical infrastructure stays secure and provides continuous services during wars and other disturbances.

![Source: Mandiant Blog](/assets/images/mandiant_ot.png)

## IEC 104 - Overview

IEC 104 (IEC-60870-5-104) is a communication protocol that is utilized by many types of OT/ICS and SCADA systems especially those that are a part of energy and power infrastructure. 

It facilitates remote control and monitoring over TCP/IP and is usually used for connecting control centers (client/master) to RTU/IEDs and substations (server/slave). Using this protocol, several data points such as breaker status, tank levels, etc. can be monitored, ingested, and controlled.

## Target Lab Setup

To simulate an IEC 104 setup, I will be using an open-source OT security lab project called [Conpot](http://conpot.org/) along with Kali Linux. Conpot is a OT systems honeypot that contains multiple templates for security templates, one of which is the IEC 104 template. 

Conpot can be installed using Docker as such:

```bash
docker pull conpot/conpot 
```

And can be run using the command:

```bash
docker run -it -p 80:80 -p 102:102 -p 502:502 -p 161:161/udp --network=bridge honeynet/conpot:latest /bin/sh
```

The Conpot binary is in `.local/bin`. To run it with the IEC 104 template, we do:

```bash
~/.local/bin $ ./conpot -f -t IEC104
```

This will spin up a good IEC 104 testing environment with one substation.

## Red Team - Attack

Let's go over the Red Team part of this exercise. Our main objective would be to compromise the substation and tamper with critical resources by sending malicious control commands in order to cause cyber/physical damage.

### Target Reconnaissance

First, we will conduct some reconnaissance on the target IP. We will be using `nmap` for this, and will be using the flags `-Pn` and `-p-` to skip the ping check and scan all ports.

```bash
kali:iec104_testing:% nmap 172.17.0.2 -Pn -p- 
Starting Nmap 7.94 ( https://nmap.org ) at 2025-05-09 08:13 EDT
Nmap scan report for 172.17.0.2
Host is up (0.000034s latency).
Not shown: 65534 closed tcp ports (conn-refused)
PORT     STATE SERVICE
2404/tcp open  iec-104

Nmap done: 1 IP address (1 host up) scanned in 7.85 seconds
```

From the output, we can see that the service `iec-104` is running on port `2404` of our Conpot instance. But this only confirms that the service is running. In order to interact with it, we need to go through substations that are connected to the master.

>An Application Service Data Unit (ASDU) is a message wrapper that facilitates communication and the transmission of data points between a Remote Terminal Unit (RTU) and the master.  Each ASDU has a common address, known as an ASDU Common Address which is unique to each RTU.

`nmap` has a neat script to discover these ASDU addresses, which is called `iec-identify.nse`. Let's utilize this:

```bash
kali:iec104_testing:% nmap 172.17.0.2 -Pn -p 2404 --script iec-identify.nse
Starting Nmap 7.94 ( https://nmap.org ) at 2025-05-11 08:44 EDT
Nmap scan report for 172.17.0.2
Host is up (0.00047s latency).

PORT     STATE SERVICE
2404/tcp open  iec-104
| iec-identify: 
|   ASDU address: 7720
|_  Information objects: 59

Nmap done: 1 IP address (1 host up) scanned in 8.78 seconds
```

The output shows one ASDU address connected to the master, which is `7720` and will come in handy during further stages of the attack. Another notable observation is the number of information objects.

>An Information Object is a data point that is contained within an ASDU. Information Objects relay a variety of information from the master, for example, breaker status, sensor readings, etc. 

>Each Information Object has an Information Object Address (IOA), which is the address of the data point within the ASDU. Along with the IOA, the value of each data point can also be observed.

### IOA Discovery

Let's conduct our second-stage reconnaissance, in which we will now focus on discovering the various Information Objects and their respective addresses to pick our targets for manipulation.

While Metasploit comes with a handy module for this, we are going to rather rise above that script kiddie mindset to better understand the hierarchical structure of ASDUs, Information Objects, and Information Object Addresses (IOAs) in relation to the master. Let's start scripting!

#### IOA Discovery Script

Using the neat [lib60870-C](https://github.com/mz-automation/lib60870) library for, we can interact with our IEC-104 instance. You can find the build instructions on the GitHub page. Below is a script that I have written for IOA discovery:

```c
#include "cs104_connection.h"
#include "hal_thread.h"
#include "hal_time.h"

#include <stdio.h>
#include <stdlib.h>

static int running = 1;

static void
connectionHandler(void* parameter, CS104_Connection connection, CS104_ConnectionEvent event)
{
    switch (event) {
        case CS104_CONNECTION_OPENED:
            printf("[+] Connection established\n");
            break;
        case CS104_CONNECTION_CLOSED:
            printf("[-] Connection closed\n");
            running = 0;
            break;
        case CS104_CONNECTION_FAILED:
            printf("[-] Connection failed\n");
            running = 0;
            break;
        default:
            break;
    }
}

static bool
asduHandler(void* parameter, int address, CS101_ASDU asdu)
{
    printf("[>] Received ASDU: Type=%s (%d), Elements=%d\n",
        TypeID_toString(CS101_ASDU_getTypeID(asdu)),
        CS101_ASDU_getTypeID(asdu),
        CS101_ASDU_getNumberOfElements(asdu));

    for (int i = 0; i < CS101_ASDU_getNumberOfElements(asdu); i++) {
        InformationObject io = CS101_ASDU_getElement(asdu, i);
        int ioa = InformationObject_getObjectAddress(io);

        switch (CS101_ASDU_getTypeID(asdu)) {
            case C_IC_NA_1: {
   		 printf("    IOA: %d | Type: C_IC_NA_1 | [General Interrogation Command]\n", ioa);
    		 break;
	     }		
            case M_SP_NA_1: {
                SinglePointInformation spi = (SinglePointInformation) io;
                printf("    IOA: %d | Type: M_SP_NA_1 | Value: %d\n",
                    ioa, SinglePointInformation_getValue(spi));
                break;
            }
            case M_DP_NA_1: {
                DoublePointInformation dpi = (DoublePointInformation) io;
                printf("    IOA: %d | Type: M_DP_NA_1 | Value: %d\n",
                    ioa, DoublePointInformation_getValue(dpi));
                break;
            }
            case M_ME_NB_1: {
                MeasuredValueScaled mvs = (MeasuredValueScaled) io;
                printf("    IOA: %d | Type: M_ME_NB_1 | Value: %d\n",
                    ioa, MeasuredValueScaled_getValue(mvs));
                break;
            }
            case M_ME_NC_1: {
                MeasuredValueShort mvs = (MeasuredValueShort) io;
                printf("    IOA: %d | Type: M_ME_NC_1 | Value: %.2f\n",
                    ioa, MeasuredValueShort_getValue(mvs));
                break;
            }
            default:
                printf("    IOA: %d | Type: %d | [Unparsed type]\n",
                    ioa, CS101_ASDU_getTypeID(asdu));
                break;
        }

        InformationObject_destroy(io);
    }

    return true;
}


int main(void)
{
    const char* ip = "172.17.0.2";
    int port = 2404;
    int asdu = 7720;

    printf("[*] Connecting to %s:%d (ASDU %d)\n", ip, port, asdu);

    CS104_Connection con = CS104_Connection_create(ip, port);

    CS104_Connection_setConnectionHandler(con, connectionHandler, NULL);
    CS104_Connection_setASDUReceivedHandler(con, asduHandler, NULL);

    if (CS104_Connection_connect(con)) {
        CS104_Connection_sendStartDT(con);

        Thread_sleep(500);

        printf("[>] Sending general interrogation (C_IC_NA_1)...\n");
        CS104_Connection_sendInterrogationCommand(con, CS101_COT_ACTIVATION, asdu, IEC60870_QOI_STATION);

        Thread_sleep(5000);
    } else {
        printf("[-] Failed to connect to target\n");
    }

    CS104_Connection_destroy(con);
    return 0;
}
```

In this script, I have accounted for the most common Information Object types, the explanations for which you can find below:

| **Case**    | **Type ID** | **IEC 104 Name**                  | **Meaning**                                                     | **What the code does**                       |
| ----------- | ----------- | --------------------------------- | --------------------------------------------------------------- | -------------------------------------------- |
| `C_IC_NA_1` | 100         | General Interrogation Command     | Request or indication to get all current values from a device   | Prints IOA + “General Interrogation Command” |
| `M_SP_NA_1` | 1           | Single Point Information          | Boolean on/off status of a single device (e.g., breaker)        | Prints IOA + value (`0=off`, `1=on`)         |
| `M_DP_NA_1` | 3           | Double Point Information          | Two-bit state info (e.g., intermediate, on, off, indeterminate) | Prints IOA + DPI value                       |
| `M_ME_NB_1` | 11          | Measured Value, Scaled Integer    | Analog value represented as a scaled integer                    | Prints IOA + integer value                   |
| `M_ME_NC_1` | 13          | Measured Value, Short Floating Pt | Analog value represented as 32-bit IEEE 754 float               | Prints IOA + float value                     |
| **default** | —           | Unknown/Other                     | Any unhandled ASDU type                                         | Prints IOA + “Unparsed type”                 |

Running the script, we get an output of all the available Information Objects associated with this Application Service Data Unit (ASDU):

```sh
[*] Connecting to 172.17.0.2:2404 (ASDU 7720)
[+] Connection established
[>] Sending general interrogation (C_IC_NA_1)...
[>] Received ASDU: Type=C_IC_NA_1 (100), Elements=1
    IOA: 0 | Type: C_IC_NA_1 | [General Interrogation Command]
[>] Received ASDU: Type=M_SP_NA_1 (1), Elements=16
    IOA: 3348 | Type: M_SP_NA_1 | Value: 1
    IOA: 3349 | Type: M_SP_NA_1 | Value: 0
    IOA: 3350 | Type: M_SP_NA_1 | Value: 0
    IOA: 3352 | Type: M_SP_NA_1 | Value: 1
    IOA: 3353 | Type: M_SP_NA_1 | Value: 1
    IOA: 3360 | Type: M_SP_NA_1 | Value: 1
    IOA: 3361 | Type: M_SP_NA_1 | Value: 1
    IOA: 3362 | Type: M_SP_NA_1 | Value: 1
    IOA: 3363 | Type: M_SP_NA_1 | Value: 1
    IOA: 3364 | Type: M_SP_NA_1 | Value: 1
    IOA: 3365 | Type: M_SP_NA_1 | Value: 1
    IOA: 3366 | Type: M_SP_NA_1 | Value: 1
    IOA: 3367 | Type: M_SP_NA_1 | Value: 1
    IOA: 3368 | Type: M_SP_NA_1 | Value: 0
    IOA: 3369 | Type: M_SP_NA_1 | Value: 1
    IOA: 3370 | Type: M_SP_NA_1 | Value: 0
[>] Received ASDU: Type=M_DP_NA_1 (3), Elements=10
    IOA: 8450 | Type: M_DP_NA_1 | Value: 1
    IOA: 8451 | Type: M_DP_NA_1 | Value: 2
    IOA: 8452 | Type: M_DP_NA_1 | Value: 1
    IOA: 8453 | Type: M_DP_NA_1 | Value: 2
    IOA: 8454 | Type: M_DP_NA_1 | Value: 2
    IOA: 8455 | Type: M_DP_NA_1 | Value: 1
    IOA: 8456 | Type: M_DP_NA_1 | Value: 1
    IOA: 8457 | Type: M_DP_NA_1 | Value: 1
    IOA: 8458 | Type: M_DP_NA_1 | Value: 1
    IOA: 8459 | Type: M_DP_NA_1 | Value: 1
[>] Received ASDU: Type=M_ME_NB_1 (11), Elements=11
    IOA: 25612 | Type: M_ME_NB_1 | Value: 103
    IOA: 25613 | Type: M_ME_NB_1 | Value: 31
    IOA: 25651 | Type: M_ME_NB_1 | Value: -49
    IOA: 25708 | Type: M_ME_NB_1 | Value: 28871
    IOA: 25709 | Type: M_ME_NB_1 | Value: 13781
    IOA: 25778 | Type: M_ME_NB_1 | Value: 119
    IOA: 25779 | Type: M_ME_NB_1 | Value: 219
    IOA: 25790 | Type: M_ME_NB_1 | Value: 1009
    IOA: 25791 | Type: M_ME_NB_1 | Value: -2
    IOA: 25792 | Type: M_ME_NB_1 | Value: 701
    IOA: 25793 | Type: M_ME_NB_1 | Value: 441
[>] Received ASDU: Type=M_ME_NC_1 (13), Elements=22
    IOA: 27395 | Type: M_ME_NC_1 | Value: 16.20
    IOA: 27469 | Type: M_ME_NC_1 | Value: 15.90
    IOA: 27470 | Type: M_ME_NC_1 | Value: 512.10
    IOA: 27471 | Type: M_ME_NC_1 | Value: 433.40
    IOA: 27482 | Type: M_ME_NC_1 | Value: 344.40
    IOA: 27522 | Type: M_ME_NC_1 | Value: -0.44
    IOA: 27523 | Type: M_ME_NC_1 | Value: 43.00
    IOA: 27524 | Type: M_ME_NC_1 | Value: 41.20
    IOA: 27533 | Type: M_ME_NC_1 | Value: 12.10
    IOA: 27592 | Type: M_ME_NC_1 | Value: 91.00
    IOA: 27593 | Type: M_ME_NC_1 | Value: 98.80
    IOA: 27594 | Type: M_ME_NC_1 | Value: 110.00
    IOA: 27595 | Type: M_ME_NC_1 | Value: 85.10
    IOA: 27596 | Type: M_ME_NC_1 | Value: 85.20
    IOA: 27597 | Type: M_ME_NC_1 | Value: 410.00
    IOA: 27598 | Type: M_ME_NC_1 | Value: 592.00
    IOA: 27599 | Type: M_ME_NC_1 | Value: 1.50
    IOA: 27600 | Type: M_ME_NC_1 | Value: 44.70
    IOA: 27601 | Type: M_ME_NC_1 | Value: 11.90
    IOA: 27602 | Type: M_ME_NC_1 | Value: 221.45
    IOA: 27603 | Type: M_ME_NC_1 | Value: 13.40
    IOA: 27604 | Type: M_ME_NC_1 | Value: 0.00
[>] Received ASDU: Type=C_IC_NA_1 (100), Elements=1
    IOA: 0 | Type: C_IC_NA_1 | [General Interrogation Command]
[-] Connection closed
```

Corresponding the results with the different types of Information Objects, we can see that there are multiple different values that we can play around with to cause destruction.

For instance, let's take the type `M_SP_NA_1 (1)`, which either has the value on (1) or off (0). Let's say if we set the value of all of these to off, this could potentially cause a major outage or service disruption, assuming that these are either breakers and/or critical devices.

### Turn Off Breakers/Devices

Let's write a script that turns off all critical devices/breakers. To do this, we will be sending a single command control ASDU, which is basically `C_SC_NA_1` which will be false (off)

