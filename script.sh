#!/bin/bash
tshark -r 2020_07_07_180408.pcap -qz conv,tcp | head -n -1 | tail -n +6 | {

echo "\"Address A\",\"Port A\",\"Address B\",\"Port B\",\"Packets B → A\",\"Bytes B → A\",\"Packets A → B\",\"Bytes A → B\",\"Total Packets\",\"Total Bytes\",\"DNS\",\"WhoIs\"" >> tshark_conv_csv.txt
while IFS=' ' read -r Address_PortA f2 AddressB_PortB B_A_Frames B_A_Bytes A_B_Frames A_B_Bytes Total_Frames Total_bytes f10
do
AddressB=$(echo $AddressB_PortB | cut -f1 -d:)

#DNS RESOLUTION
dns=$(dig +short @9.9.9.9 -x ${AddressB})
if [ -z "$dns" ]
then
  dns="null"
fi

#WHOIS
whois=$(whois ${AddressB} | grep -i "orgname\|org-name")
if [ -z "$whois" ]
then
  whois="null"
fi

printf "${Address_PortA//':'/,},${AddressB_PortB//':'/,},$B_A_Frames,$B_A_Bytes,$A_B_Frames,$A_B_Bytes,$Total_Frames,$Total_bytes,\"$dns\",\"$whois\"\n"
done >> tshark_conv_csv.txt
}


