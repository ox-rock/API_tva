#!/bin/bash

START_TIME=$SECONDS

declare -A value=()
declare -a IP=()

addIP() {
    IP+=("$1")
    value["$1_openDNS"]="$2"
    value["$1_cloudflareDNS"]="$3"
    value["$1_adguardDNS"]="$4"
    value["$1_whois"]="$5"
    value["$1_whoiscymru"]="$6"	
}

pcap_file=$(find . -type f -name '*.pcap' -or -name '*.pcapng')

printf "Reading $pcap_file\n"

for protocol in udp tcp; do
    tshark -r $pcap_file -Y "ip and $protocol" -E separator=, -T fields -e $protocol.stream -e ip.src -e $protocol.srcport -e ip.dst -e $protocol.dstport -e frame.time_relative -e ssl.handshake.extensions_server_name > ${protocol}_sni 

    cnt=$(tshark -r $pcap_file -qz conv,$protocol,ip | head -n -1 | tail -n +6 | wc -l)

    tshark -r $pcap_file -qz conv,$protocol,ip | head -n -1 | tail -n +6 | {

    echo "\"ID\",\"Address A\",\"Port A\",\"Address B\",\"Port B\",\"Packets B → A\",\"Bytes B → A\",\"Packets A → B\",\"Bytes A → B\",\"Total Packets\",\"Total Bytes\",\"Start time\",\"Duration\",\"nslookup\",\"OpenDNS\",\"Cloudflare DNS\",\"AdGuard  DNS\",\"WhoIs\",\"WhoIs (Cymru)\",\"SNI\"" >> ${protocol}_conv.txt
    i=1
    while IFS=' ' read -r AddressA_PortA f2 AddressB_PortB B_A_Frames B_A_Bytes A_B_Frames A_B_Bytes Total_Frames Total_bytes start duration; do
	
	AddressB=$(echo $AddressB_PortB | cut -f1 -d:)
	PortA=$(echo $AddressA_PortA | cut -f2 -d:)

	id=$(cat ${protocol}_sni | grep ${AddressB} | grep ${start} | uniq | cut -f1 -d',')

	printf "\rProcessing [$i/$cnt] $protocol conversation" 1>&2
	i=$((i+1))
        printf "$id,${AddressA_PortA//':'/,},${AddressB_PortB//':'/,},$B_A_Frames,$B_A_Bytes,$A_B_Frames,$A_B_Bytes,$Total_Frames,$Total_bytes,$start,$duration"

	if [[ "$AddressB" == 192.168.* || "$AddressB" == "239.255.255.250" || "$AddressB" == 224.0.0.* || "$AddressB" == "255.255.255.255" ]]; then 
	    printf ",-,-,-,-,-,-,-\n"
	else
	    nslookup=$(cat nslookup.log | grep ${AddressB} | cut -f2 -d',')
            if [ -z "$nslookup" ]; then 
                nslookup="null"
	    fi
            printf ",$nslookup"

	    bool="false"
	    for x in "${IP[@]}"; do
	        if [ "$x" == "$AddressB" ]; then 
		    bool="true"
		    printf ",\"${value[${x}_openDNS]}\",\"${value[${x}_cloudflareDNS]}\",\"${value[${x}_adguardDNS]}\",\"${value[${x}_whois]}\",\"${value[${x}_whoiscymru]}\","
		    break 
		fi
	    done

	    if [ "$bool" == "false" ]; then 
		#Reverse DNS resolution by OpenDNS, CloudFlare and AdGuard DNS
		openDNS=$(dig +short @208.67.222.222 -x ${AddressB} | tr '\n' ' ')
		if [ -z "$openDNS" ]; then 
		    openDNS="null"
		fi
		cloudflareDNS=$(dig +short @1.1.1.1 -x ${AddressB} | tr '\n' ' ')
		if [ -z "$cloudflareDNS" ]; then 
		    cloudflareDNS="null"
		fi
		adguardDNS=$(dig +short @176.103.130.130 -x ${AddressB} | tr '\n' ' ')
		if [ -z "$adguardDNS" ]; then 
		    adguardDNS="null"
		fi

		#whois query
		whois=$(whois ${AddressB} | grep -i "org-name" | uniq | cut -f2 -d: | sed -e 's/^[ \t]*//')
		if [ -z "$whois" ]; then  
		    whois=$(whois ${AddressB} | grep -i "OrgName" | uniq | cut -f2 -d: | sed -e 's/^[ \t]*//')
	 	    if [ -z "$whois" ]; then
			whois=$(whois ${AddressB} | grep -i "descr" | uniq | head -n 1 | cut -f2 -d: | sed -e 's/^[ \t]*//')
			if [ -z "$whois" ]; then
			    whois="null"
			fi
		    fi
		fi

		#whois query by Team Cymru
		whoiscymru=$(whois -h whois.cymru.com ${AddressB} | tail -n 1 | cut -f3 -d'|')
			       
		addIP "$AddressB" "$openDNS" "$cloudflareDNS" "$adguardDNS" "$whois" "$whoiscymru"
		printf ",\"$openDNS\",\"$cloudflareDNS\",\"$adguardDNS\",\"$whois\",\"$whoiscymru\"," 
	    fi

	    #SNI extraction
	    if [ "$protocol" == "tcp" ]; then 	
		sni=$(cat ${protocol}_sni | grep ${id} | grep ${AddressB} | grep ${PortA} | cut -f7 -d',' | uniq | head -n 2 | tail -n 1 )
		if [ -z "$sni" ]; then
		    sni="null"
		fi
		printf "$sni\n"
	    else 
		sni="null"
		printf "$sni\n"
	    fi
        fi
	
        done >> ${protocol}_conv.txt
	printf "\n"
}
rm ${protocol}_sni
done

ELAPSED_TIME=$(($SECONDS - $START_TIME))
printf "\nElapsed time: $(($ELAPSED_TIME))s\n"
