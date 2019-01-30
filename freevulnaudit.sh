#!/bin/bash

###########################################################################
################### OCSAF FREE Vulnerability Auditor ####################
###########################################################################

#########################################################################################################################
#  FROM THE FREECYBERSECURITY.ORG TESTING-PROJECT (GNU-GPLv3) - https://freecybersecurity.org                           #
#  This script is used to perform an automated security audit and point out weaknesses.                                 #
#  To achieve this, security intelligence (OSINT) and security scanning techniques are used and                         #
#  combined with collective intelligence.                                                                               #
#                                                                                                                       #
#  Use only with legal authorization and at your own risk! ANY LIABILITY WILL BE REJECTED!                              #
#                                                                                                                       #
#  Script coding by Mathias Gut and Christian Kiss, Netchange Informatik GmbH under GNU-GPLv3                           #
#  Special thanks to the community and also for your personal project support.                                          #
#########################################################################################################################

###################################
### TOOL DEPENDENCIES           ###
###                             ###
### XML to HTML:                ###
### apt-get install xsltproc    ###
###                             ###   
### HTML to PDF:                ###
### apt-get install wkhtmltopdf ###
###################################

###################
### TOOL USAGE  ###
###################

usage() {
	echo "From the Free OCSAF project (https://freecybersecurity.org)"
	echo "OCSAF FREE Vulnerability Auditor 1.0 - GPLv3"
	echo "Use only with legal authorization and at your own risk!"
       	echo "ANY LIABILITY WILL BE REJECTED!"
       	echo ""	
	echo "USAGE:" 
	echo "  ./freevulnauditor.sh -i <IP or host>"
       	echo "  ./freevulnauditor.sh -l <host_list>"	
       	echo "  ./freevulnauditor.sh -n <nmap_parameters>"	
       	echo ""	
	echo "EXAMPLE:"
       	echo "  ./freevulnauditor.sh -i 10.10.10.10"
       	echo "  ./freevulnauditor.sh -l ./targets.txt"
       	echo "  ./freevulnauditor.sh -n -pN -sV -h 10.10.10.10"
       	echo ""	
	echo "OPTIONS:"
	echo "  -h, help - this beautiful text"
	echo "  -a - standard scripts for auditing"
	echo "  -i <IP or host> - scanning target"
	echo "  -l <host_list> - scanning targets from list"
	echo "  -n <nmap_parameters> - individual NMAP parameters"
	echo "  -o - NMAP-Parameter -O for OS-Detection"
	echo "  -p - Ports"
	echo "  -u - Scans UDP-Ports, default only TCP-Ports for higher scan speed"
	echo "  -q - Quick-Audit - Only the specially selected scripts"
       	echo ""
	echo "NOTES:"
	echo "#Always generates a html and a pdf file"
	echo "#See also the MAN PAGE - https://freecybersecurity.org"
}


###############################
### GETOPTS - TOOL OPTIONS  ###
###############################

while getopts "n:l:i:p:halouqvw" opt; do
	case ${opt} in
		h) usage; exit 1;;
		a) audit="1";;
		i) ip="$OPTARG"; opt_arg1=1;;
		l) list="$OPTARG"; opt_arg2=1;;
		n) nmap="$OPTARG";;
		o) os="-O";;
		p) port="$OPTARG";;
		u) udp="1";;
		q) quickaudit="1";;
		v) vuln="1";;
		w) udplight="1";;
		\?) echo "**Unknown option**" >&2; echo ""; usage; exit 1;;
        	:) echo "**Missing option argument**" >&2; echo ""; usage; exit 1;;
		*) usage; exit 1;;
  	esac
  	done
	shift $(( OPTIND - 1 ))

#Check if opt_arg1 or opt_arg2 is set
if [ "$opt_arg1" == "" ] && [ "$opt_arg2" == "" ]; then
	echo "**No argument set**"
	echo ""
	usage
	exit 1
fi

################### functions ####################

# Function to find vulnerabilities using the NMAP tool

funcVulnAudit() {
	
	local reportpath="./"
	local lvuln
	local lquickaudit
	local llist=
	local lip=$ip
	local los=$os
	local ltcp="-sT"
	local lport="-"
	local lscan="-sV"
	local timestamp=`date '+%Y%m%d_%H%M%S'`
	local filename="freevulnauditor_${timestamp}"
	local audithtml
	local quickhtml
	local vulnhtml

	#Check if vulnreport folder exists and create otherwise
	if ! [ -d "$reportpath/vulnreport/" ]; then
                mkdir ${reportpath}/vulnreport
        fi
	
	if [ ! -z "${list}" ]; then
		llist="-iL $list"
	fi
	
	if [ ! -z "${port}" ]; then
		lport="${port}"
	fi
	
	if [ ! -z "${audit}" ]; then
            	echo "running audit scan, this may take a while.."
		echo ""
		
		if [ ! -z "${udp}" ]; then
			nmap --privileged -vv -A -p${lport} --script "safe and not external"  \
		       		-oX "./vulnreport/audit_${filename}.xml" ${lip} ${llist}
		else
			nmap --privileged -vv -A -p T:${lport} --script "safe and not external"  \
		       		-oX "./vulnreport/audit_${filename}.xml" ${lip} ${llist}
		fi
		
		xsltproc "./vulnreport/audit_${filename}.xml" -o "./vulnreport/audit_${filename}.html"
		wkhtmltopdf "./vulnreport/audit_${filename}.html" "./vulnreport/audit_${filename}.pdf"
		audithtml="./vulnreport/audit_${filename}.html" 
	fi
	
	if [ ! -z "${quickaudit}" ]; then
		lquickaudit=$(echo "--script=http-cookie-flags --script=ssl-cert --script=ssl-enum-ciphers, \
			--script=http-enum, --script=http-security-headers, --script=ike-version")
		
            	echo "running quickaudit scan, this may take a while.."
		echo ""
		
		if [ ! -z "${udp}" ]; then
			nmap --privileged -vv -Pn -sV ${los} -p${lport} ${lquickaudit} \
		       		-oX "./vulnreport/quick_${filename}.xml" ${lip} ${llist}
		elif [ ! -z "${udplight}" ]; then
			nmap --privileged -vv -Pn -sV ${los} -p T:${lport},U:500,4500,123,53 ${lquickaudit} \
		       		-oX "./vulnreport/quick_${filename}.xml" ${lip} ${llist}
		else
			nmap --privileged -vv -Pn -sTV ${los} -p ${lport} ${lquickaudit} \
		       		-oX "./vulnreport/quick_${filename}.xml" ${lip} ${llist}
		fi
		
		xsltproc "./vulnreport/quick_${filename}.xml" -o "./vulnreport/quick_${filename}.html"
		wkhtmltopdf "./vulnreport/quick_${filename}.html" "./vulnreport/quick_${filename}.pdf"
		quickhtml="./vulnreport/quick_${filename}.html" 
	fi
	
	if [ ! -z "${vuln}" ]; then
		lvuln="--script=freevulnsearch.nse --script-args=xmlhtml"
		
            	echo "running vuln scan, this may take a while.."
		echo ""
		
		if [ ! -z "${udp}" ]; then
			nmap --privileged -vv -Pn -sV ${los} -p${lport} ${lvuln} \
		       		-oX "./vulnreport/vuln_${filename}.xml" ${lip} ${llist}
		else
			nmap --privileged -vv -Pn -sTV ${los} -p${lport} ${lvuln} \
		       		-oX "./vulnreport/vuln_${filename}.xml" ${lip} ${llist}
		fi
		
		xsltproc "./vulnreport/vuln_${filename}.xml" -o "./vulnreport/vuln_${filename}.html"
		wkhtmltopdf "./vulnreport/vuln_${filename}.html" "./vulnreport/vuln_${filename}.pdf"
		vulnhtml="./vulnreport/vuln_${filename}.html" 
	fi

		firefox ${vulnhtml} ${audithtml} ${quickhtml}
}


####### MAIN PROGRAM #######

echo ""
echo "############################################"
echo "####  OCSAF FREE Vulnerability Auditor  ####"
echo "############################################"
echo ""

if [ "$opt_arg1" == "1" ]; then
	funcVulnAudit $ip
	echo ""
elif [ "$opt_arg2" == "1" ]; then
	funcVulnAudit $list
	echo ""
fi

################### END ###################