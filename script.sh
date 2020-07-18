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

   tshark -r $pcap_file -E separator=, -T fields -e tcp.stream -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport -e frame.time_relative -e ssl.handshake.extensions_server_name -e http.host -Y "ip" > temp_tcp 

   tshark -r $pcap_file -E separator=, -T fields -e udp.stream -e ip.src -e udp.srcport -e ip.dst -e udp.dstport -e frame.time_relative -e http.host -Y "ip" > temp_udp 

   tshark -r $pcap_file -E separator=/s -T fields -e dns.a -e dns.qry.name -Y "(dns.flags.response == 1 )" > temp_dns

conv2csv() {
    cnt=$(tshark -r $pcap_file -qz conv,$protocol,ip | head -n -1 | tail -n +6 | wc -l)

    tshark -r $pcap_file -qz conv,$protocol,ip | head -n -1 | tail -n +6 | {

    echo "\"ID\",\"Address A\",\"Port A\",\"Address B\",\"Port B\",\"Packets B → A\",\"Bytes B → A\",\"Packets A → B\",\"Bytes A → B\",\"Total Packets\",\"Total Bytes\",\"Start time\",\"Duration\",\"Android DNS\",\"nslookup\",\"OpenDNS\",\"Cloudflare DNS\",\"AdGuard DNS\",\"WhoIs\",\"WhoIs (Cymru)\",\"SNI\",\"Host HTTP\"" >> ${protocol}_conv.txt
    i=1
    while IFS=' ' read -r AddressA_PortA f2 AddressB_PortB B_A_Frames B_A_Bytes A_B_Frames A_B_Bytes Total_Frames Total_bytes start duration; do

	AddressB=$(echo $AddressB_PortB | cut -f1 -d:)
	PortA=$(echo $AddressA_PortA | cut -f2 -d:)
	id=$(cat temp_${protocol} | grep ${AddressB} | grep ${start} | uniq | cut -f1 -d',')
	
	printf "\rProcessing [$i/$cnt] $protocol conversation" 1>&2

        printf "$id,${AddressA_PortA//':'/,},${AddressB_PortB//':'/,},$B_A_Frames,$B_A_Bytes,$A_B_Frames,$A_B_Bytes,$Total_Frames,$Total_bytes,$start,$duration"

	if [[ "$AddressB" == 192.168.* || "$AddressB" == "239.255.255.250" || "$AddressB" == 224.0.0.* || "$AddressB" == "255.255.255.255" ]]; then 
	    printf ",-,-,-,-,-,-,-,-,-\n"
	else
	    androidDNS=$(cat temp_dns | grep ${AddressB} | cut -f2 -d' ' | uniq | tr '\n' ' ')
            if [ -z "$androidDNS" ]; then 
                androidDNS="null"
	    fi
	    printf ",$androidDNS"

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

	    #SNI & Host HTTP extraction
	    if [ "$protocol" == "tcp" ]; then 	
		sni=$(cat temp_tcp | grep ${id} | grep ${AddressB} | grep ${PortA} | cut -f7 -d',' | uniq | head -n 2 | tail -n 1 )
		if [ -z "$sni" ]; then
		    sni="null"
		fi
	        host=$(cat temp_tcp | grep ${id} | grep ${AddressB} | grep ${PortA} | cut -f8 -d',' | uniq | head -n 2 | tail -n 1 )
	        if [ -z "$host" ]; then
		    host="null"
	        fi
	        printf "$sni,$host\n"
	    else 
	        host=$(cat temp_udp | grep ${id} | grep ${AddressB} | grep ${PortA} | cut -f7 -d',' | uniq | head -n 2 | tail -n 1 )
	        if [ -z "$host" ]; then
		    host="null"
	        fi
		printf -- "-,$host\n"
	    fi	
        fi
	i=$((i+1))
        done >> ${protocol}_conv.txt

	rm temp_${protocol}
    }
}

for protocol in udp tcp; do
    conv2csv &
done

wait

rm temp_dns

ELAPSED_TIME=$(($SECONDS - $START_TIME))
printf "\nElapsed time: $(($ELAPSED_TIME))s\n"
