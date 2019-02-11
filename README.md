# Overview
This is a simple botnet that I created in order to understand how they function. It is designed with a client/server infrastructure, and it utilizes many of the same methods used in qBot and Mirai. It targets poorly-secured linux devices that have telnet open and python 2.7 installed (very similar to Mirai's attack targets). It was created purely for educational purposes; I have no intentions of using it maliciously, though it is definitely capable of being used that way. Please use it in the same manner. This document will discuss how to set everything up, some precautionary measures to avoid harming yourself and others unintentionally, and suggestions one may take in order to improve or innovate upon this project. I will not be accepting any PRs for this repository, but I am open to suggestions or bugs if you wish to open up a new issue. Do note, this project is not complete. It is not set up so you can just clone the repository, run the code, and call it good. It requires some effort on the user's part to make the modifications necessary to make everything function the way you want it to work. In addition, I haven't truly gone all out in testing this project at a large scale since I am not interested in going to jail, so you may find that you need to add some code of your own for everything to work. I made this entirely as a proof-of-concept to show that a botnet can be made in python; I also made this out of pure curiosity as to how real malware works.

# Setting up the CNC servers

As noted in the code, you can set up the CNC servers in whichever fashion you choose. This section will explain the bare minimum utilities you need to have installed as well as how to operate the scripts. Regardless of the configuration you choose, you must be able to host a database for storing bot information, listen for incoming bot credentials to be stored in that database, host the bot in order to download it onto vulnerable devices, and run attacks using all the bots in the database. The scripts are already available for you to use; they just need to be modified to fit your likings.

## Prerequisites

* python 2.7 - runs and executes the server
* sqlite3 - stores bot data on the server
* tar - used for zipping up the bot folder to be copied onto vulnerable hosts

## Initializing the database

Before you can enlist any bots into the botnet, you need a database in which to store them. To create it, `cd` to the `db/` directory and run `./init_database.sh`. This will create an empty database for you labeled `bots.db`.

The table used for storing bot credentials is called 'Bots' and is structured as follows:
* addr - IPv4 address of vulnerable device
* port - port that was broken into
* username - username used to brute-login the port
* password - password used to brute-login the port.

The program uses SQLite, which is fine for a start, but for a more scalable solution, something more suitable such as MySQL is recommended.

## Adding bots

The module `listen.py` listens for incoming bots to connect and deliver their credentials. These will then be stored in the database. By default, this module listens on address `0.0.0.0` on port `4444`; these values can be changed in the `defs.py` module.

## Initiating attacks

The module `command.py` is run with arguments and is used to issue commands to all bots in the database e.g. `python command.py -a syn_flood -d 5 -t 8.8.8.8`. This example command will tell all bots to initiate a syn flood attack on `8.8.8.8` for a duration of 5 seconds. The command module makes calls to the `attack.py` module to initiate the attacks. This program will access the database in order to find the bot credentials to log in; it will then use the open session to run the attacks. As will be discussed later, this is because the attack scripts remain on the client under a subfolder called `attacks` and are downloaded to each vulnerable host. Therefore, the server need simply establish a connection and run the scripts remotely on the device itself. As with the bot, the server currently only supports telnet, but it can be modified to handle other protocols. There are only two possible attack types currently: syn flood and ping flood; however, more attack scripts can be created and added to the list. By default, the CNC server address is set to `10.0.0.1` and the port is set to `4444`. Again, these values can be changed in the `defs.py` module.

# Understanding the bot

The bot operates in several distinct steps in order to infect machines. The most important thing to note is the `DEBUG` flag that is set in `defs.py`. This limits the actions that the bot is able to take. When the `DEBUG` flag is set, the bot is prevented from scanning other devices and instead only scans the address specified by `TEST_ADDR`, which is set to the loopback address `127.0.0.1`. In addition, it prevents spreading the bot to other hosts. By default, the `DEBUG` flag is set to true. This can be modified to remove or add limits as needed for testing. If the flag is set to False, then the program will go all out and attempt to enlist as many vulnerable devices as possible. This is fine if you're serious about putting the botnet into motion. Just don't say I didn't warn you.

The bot must be run as root since the program deals with raw sockets that require administrative privileges. Unfortunately, this limitation also prevents the bot from being run on Windows devices, since raw sockets are handled idiosyncratically on different operating systems. When the bot breaks into vulnerable devices, it should gain root access anyway since most of the usernames are root, admin, or some other variant, so this shouldn't be a problem.

Here are the steps the bot takes to attack other hosts:

1. The bot begins by first generating a random public IP address. The method takes care to avoid crafting an IPv4 address that is either private, invalid, or belonging in the blacklist (Department of Defense, HP, IANA reserved, etc.). This program as a whole can only understand and interpret IPv4 addresses. As mentioned before, if the `DEBUG` flag is set, this method will not be used and instead the target will always be `TEST_ADDR`.
2. With the target selected, the program then enters the scanning phase, in which the target device is scanned to see if any ports listed in `ATTACK_PORTS` are open. Only port 23 (TELNET) is in the list because this is the only protocol the program knows how to handle; however, the program can easily be extended to handle more protocols if desired. The scanner uses raw sockets to send SYN packets to the target and then waits for a response. It does this to avoid making a full 3-way TCP handshake, making the process both stealthier and quicker. If there is no response, the scanner attempts to scan a variable number of times as defined by `MAX_SCANS` to ensure that the port is not filtered or blocked by a firewall. If the port is filtered or closed, it gives up and repeats step 1.
3. Next, the bot enters into a brute-force login phase, in which it tries to log into telnet using a list of common usernames and passwords contained in `auth.txt` (these auth combos are identical to the ones used in Mirai). It leverages the `telnetlib` library, which is only present in python 2.7 and higher, which is why the bot is limited in the hosts it can infect. If no username or password match, step 1 is repeated.
4. If the bot is able to break in, it checks to see if a working version of python is installed on the device as defined by `PYTHON_WORKING_VERSIONS`. If it doesn't have a working version of python, step 1 is repeated since the device would not be able to spread or launch attacks; it would therefore be pointless to hold it for future use. If a working version of python is available, the bot proceeds to download a copy of itself from the CNC server using the `wget` utility and tries to execute it. The location of the bot is defined by `CNC_SERV_ADDR` and may be configured however you like; this is another decision that will have to be made when setting up the CNC servers. If the bot is successfully downloaded, the program will `cd` into the directory and attempt to execute itself. If this entire process succeeds, the bot has found yet another avenue to spread itself. Even if the bot is unable to spread, having a working version of python is still a plus, as it can still be enlisted and used by the command module to launch attacks against other victims.
5. The final step involves the vulnerable device establishing a connection to the CNC server and sending its credentials.

To run the bot, type `sudo python bot.py`. The `sudo` part can be omitted if you are already running as root.
WARNING: DO NOT TURN OFF THE DEBUG FLAG UNLESS YOU WANT TO LAUNCH A COMPLETE ATTACK AND RISK CRIMINAL CHARGES

# Notes

* This is merely one method of writing a botnet
* This solution does not handle IPv6 addresses whatsoever, but could be adapted to do so
* This program does not work in python 3 simply because of the methods used to calculate the checksums in `ip.py`
* You may opt to roll your own telnet client or whatever other client you want to avoid being restricted to telnetlib
* The program checks only for the existence of the username since the password may be nonexistent
* SQLite is not a good long-term solution, as it is not sufficient for handling very large amounts of data
* This was made as a learning experience; please do not use this on other people
* And again, please understand what the code is doing before you run anything
