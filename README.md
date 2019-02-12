# freevulnaudit

This bash script automates and simplifies vulnerability scanning using NMAP. The NMAP NSE script freevulnsearch.nse can also be used for the scan. With this script CVEs can be detected by the application CPE via the public API of circl.lu. Read more about this in the respository https://github.com/OCSAF/freevulnsearch.

## Installation:

The freevulnaudit.sh is tested in KALI LINUX™.

    Simply copy the NSE script freevulnsearch.nse (https://github.com/OCSAF/freevulnsearch) into
    the corresponding script directory of the NMAP installation.
    In KALI LINUX for example: /usr/share/nmap/scripts/

    apt-get install xlstproc
    apt-get install wkhtmltopdf

## Usage:

The application is simple, just use the -h parameter to display the HELP.

    ./freevulnaudit.sh -h

Special thanks to Christian Kiß and the open source community for many useful ideas that accelerated the creation of this script! Further ideas and suggestions for improvement are very welcome.


KALI LINUX™ is a trademark of Offensive Security.

Translated with www.DeepL.com/Translator - Thanks:-)
