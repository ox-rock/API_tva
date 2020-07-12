#!/bin/bash

declare -A value=()
declare -a IP=()

addIP() {
    IP+=("$1")
    value["$1_openDNS"]="$2"
    value["$1_cloudflareDNS"]="$3"
    value["$1_adguardDNS"]="$4"
    value["$1_whois"]="$5"
    value["$1_whoiscymru"]="$6"
    value["$1_sni"]="$7"	
}

for protocol in udp tcp; do
    tshark -r 2020_07_07_180408.pcap -qz conv,$protocol | head -n -1 | tail -n +6 | {

    echo "\"Address A\",\"Port A\",\"Address B\",\"Port B\",\"Packets B → A\",\"Bytes B → A\",\"Packets A → B\",\"Bytes A → B\",\"Total Packets\",\"Total Bytes\",\"OpenDNS\",\"Cloudflare DNS\",\"AdGuard  DNS\",\"WhoIs\",\"WhoIs (Cymru)\",\"SNI\"" >> ${protocol}_conv.txt
    while IFS=' ' read -r Address_PortA f2 AddressB_PortB B_A_Frames B_A_Bytes A_B_Frames A_B_Bytes Total_Frames Total_bytes f10; do
        printf "${Address_PortA//':'/,},${AddressB_PortB//':'/,},$B_A_Frames,$B_A_Bytes,$A_B_Frames,$A_B_Bytes,$Total_Frames,$Total_bytes"

	AddressB=$(echo $AddressB_PortB | cut -f1 -d:)

	bool="false"
	for x in "${IP[@]}"; do
	    if [ "$x" == "$AddressB" ]; then 
                bool="true"
	        break 
	    fi
	done

	if [ "$bool" == "false" ]; then 
            openDNS=$(dig +short @208.67.222.222 -x ${AddressB})
	    if [ -z "$openDNS" ]; then 
                openDNS="null"
	    fi
	    cloudflareDNS=$(dig +short @1.1.1.1 -x ${AddressB})
	    if [ -z "$cloudflareDNS" ]; then 
                cloudflareDNS="null"
	    fi
	    adguardDNS=$(dig +short @176.103.130.130 -x ${AddressB})
	    if [ -z "$adguardDNS" ]; then 
                adguardDNS="null"
	    fi

	    whois=$(whois ${AddressB} | grep -i "org-name" | cut -f2 -d:)
	    if [ -z "$whois" ]; then  
                whois=$(whois ${AddressB} | grep -i "OrgName" | cut -f2 -d:)
 		if [ -z "$whois" ]; then
                    whois=$(whois 5.9.13.67 | grep -i "descr" | head -n 1 | cut -f2 -d:)
		    if [ -z "$whois" ]; then
                        whois="null"
		    fi
	        fi
	    fi
	    
            whoiscymru=$(whois -h whois.cymru.com ${AddressB} | tail -n 1 | cut -f3 -d'|')
	    
	    sni=$(tshark -r 2020_07_07_180408.pcap -T fields -e ssl.handshake.extensions_server_name ip.dst==${AddressB} and ssl.handshake.extensions_server_name | tail -n 1)
            if [ -z "$sni" ]; then
                sni="null"
	    fi
	    
            addIP $AddressB "$openDNS" "$cloudflareDNS" "$adguardDNS" "$whois" "$whoiscymru" $sni 
	fi

	for x in "${IP[@]}"; do
	    if [ "$x" == "$AddressB" ]; then
                printf ",\"${value[${x}_openDNS]}\",\"${value[${x}_cloudflareDNS]}\",\"${value[${x}_adguardDNS]}\",\"${value[${x}_whois]}\",\"${value[${x}_whoiscymru]}\",\"${value[${x}_sni]}\"\n"
		break
	    fi
	done

    done >> ${protocol}_conv.txt
}

done






