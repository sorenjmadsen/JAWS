import pyshark
filter = "ether host dc:a6:32:c9:e5:b9"
capture = pyshark.LiveCapture(interface="wlan0mon", bpf_filter=filter)
count = 0
for pkt in capture.sniff_continuously():
	if pkt.wlan.fc_retry != '1' and pkt.wlan.fc_type_subtype == '40':
		count += 1
		print(count)
		print("Retry: ", pkt.wlan.fc_retry)
		print("Type_Subtype: ", pkt.wlan.fc_type_subtype)
#		print(pkt)
