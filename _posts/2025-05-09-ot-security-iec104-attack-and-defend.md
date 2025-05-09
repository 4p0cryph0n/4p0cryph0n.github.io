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

### Target Discovery

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

A substation is known as an Application Service Data Unit (ASDU), which is essentially a Remote Terminal Unit (RTU) that is used to communicate with the master. Each ASDU has a common address, known as an ASDU Common Address which is a unique identifier.

