# t2e_integrity_check

 Apple Thunderbolt to Ethernet PCI Option ROM Integrity Checker
 - Xeno Kovah - xeno@legbacore.com
 - With thanks to Trammel Hudson, and Corey Kallenberg

 PCI Option ROMs (OROMs, also known as Expansion ROMs) are a
 known source of attacks[1][2][3][4] on computing systems.

 In [2][4][5] it was shown in particular that the Apple
 thunderbolt-to-ethernet (t2e) adapter could be used to attack Macs.

 However, the OROM for every t2e adapter we have looked at has
 been basically the same (with the exception of the MAC and
 a checksum.) Therefore integrity checking is highly tractable.
 However, we have had a limited set of devices on which to test.
 If this program generates an alert, it may be a false positive
 due to you having an image that is valid, but simply was not
 seen during our testing. Send all alerts/errors to the
 email(s) listed at the top of this file.

 This is not meant to be a highly-trustworthy tool. It is not
 currently know whether the firmware that the Broadcom chip
 on these devices runs can lie about the contents of the OROM.
 However it is suspected they may be able to.

 While this tool may check a single OROM, there is still a world
 of *other* OROMs out there which can be used to attack people.
 The only way the situation will improve is if customers start
 telling security vendors that they want them to protect against
 firmware-borne attacks. If enough people actually talk to their
 vendors, they will start to listen.

[1] "Implementing and Detecting a PCI Rootkit",
 John Heasman, http://www.blackhat.com/presentations/
 bh-dc-07/Heasman/Paper/bh-dc-07-Heasman-WP.pdf

[2] "DE MYSTERIIS DOM JOBSIVS: MAC EFI ROOTKITS", Loukas K.,
 http://ho.ax/downloads/De_Mysteriis_Dom_Jobsivs_Black_Hat_Slides.pdf

[3] "UEFI and PCI Bootkits", Pierre Chifflier, https://pacsec.jp/
 psj13/psj2013-day2_Pierre_pacsec-uefi-pci.pdf

[4] "Thunderstrike: EFI firmware bootkits for Apple MacBooks",
 Trammell Hudson, Larry Rudolph, https://dl.acm.org/
 citation.cfm?id=2757673

[5] "Thunderstrike 2: Sith Strike", Trammel Hudson, Xeno Kovah,
Corey Kallenberg, http://trmm.net/Thunderstrike_2

#Other code

The binary version of DirectHW.kext was compiled from Trammell Hudson's https://github.com/osresearch/rwmem

The binary version of tg3-eeprom was compiled from Trammell Hundson's https://github.com/osresearch/b57tool

#Usage:

sudo chmod -R 700 DirectHW.kext/

sudo chown -R root:wheel DirectHW.kext/

sudo kextload DirectHW.kext

sudo ./tg3-eeprom > my.orom

 (it must be named "my.orom")

python t2e_integrity_check.py

If your OROM is intact, a message to that effect will print.

If not, send any alerts/errors to xeno@legbacore.com
