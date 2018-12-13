# FIIN - Firmware Inspector v0.2
(c) 2001,2002 Jacek Lipkowski <sq5bpf@lipkowski.org>

Note: this was originally written in 2001, and was the first generally 
avaliable tool to decompress firmware images (binwalk was released a few 
years later). I'm making it avaliable again on github for historical 
purposes. Original README follows:


This (lame/badly written) utility tries to find compressed files in
firmware images, and writes them out to files. It was written while trying
to inspect strings present in certain firmware.

The program tries to find magic strings within the inspected file, when
the magic strings are found, the suspected archive is verified with a real
decompressor, currently unzip, gzip, bzip2, unarj and lha are supported.
Others can be easily added.

So far it has been tested with Cisco IOS images, Avaya VPNOS and Avaya
Cajun firmware (also works on compressed Linux kernels btw :).

### Compilation

Running make should be sufficient.  Please note, that there is a
documentation bug in the system(3) manpage under linux, if your system
behaves as the manpage documents, comment out the SHIFT_SYSTEM define in
the source.

### Usage

fiin <options>
options:
-u always unlink (delete files after checking them)
-v verbose (use twice for more junk on the screen)
-h help
-w method - without method (gzip, unzip, bzip2, lha, unarj)
-f input file
-o outfile basename (equals input file if not specified)


Example usage (on cisco router firmware):

Run fiin:

sq5bpf@hash:~$ fiin -f c1700-y-mz.120-1.XA3 -o plik -w unarj
FIIN v0.2, Copyright (C) 2001 Jacek Lipkowski <sq5bpf@andra.com.pl>
FIIN comes with ABSOLUTELY NO WARRANTY
This is free software, and you are welcome to redistribute it
under the GPL version 2 license. Please see the file LICENSE for details.


*** image at offset 0x3fac saved as plik-0.zip ***

sq5bpf@hash:~$ unzip -v -l plik-0.zip
Archive:  plik-0.zip
 Length   Method    Size  Ratio   Date   Time   CRC-32    Name
--------  ------  ------- -----   ----   ----   ------    ----
 6263180  Defl:N  2426074  61%  11-13-98 16:07  cc8fba6e  C1700-Y-.BIN
--------          -------  ---                            -------
 6263180          2426074  61%                            1 file

Unpack the resulting archive:

sq5bpf@hash:~$ unzip plik-0.zip
Archive:  plik-0.zip
  inflating: C1700-Y-.BIN

Launch our sophisticated forensic tool:

sq5bpf@hash:~$ strings C1700-Y-.BIN |less -i
enjoy :)

Please be warned that some unnamed vendor might have named the file inside
the a zip archive called ../../../../../../../etc/passwd for example. This
is the reason why fiin doesn't decompress the files itself.


If you've tried it on any other compressed firmware then please send me a
note to sq5bpf@lipkowski.org


### Where to get it

The latest version should be avaliable at:
https://github.com/sq5bpf/fiin

### License

This software is licensed under the GPL version 2 license avaliable in the
file LICENSE accompanying this software and under the followin url:
http://www.gnu.org/copyleft/gpl.html
