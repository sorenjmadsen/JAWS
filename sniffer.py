import pyshark
import threading
import time
from flask import Flask, render_template, request, redirect, url_for
import sys

global status, stat, alert, statAlert, clr, log

headings = (''' "Name" ''' "MAC", "Status")
data = [
	''' Typical Format
    ("Raspberry Pi", "6F:F7:4E:93:6B:D8", "Connected"),
    ("Client", "DC:27:2D:5B:BA:28", "Under Attack"),
    ("MacBook Pro", "14:46:01:0A:09:E0", "Connected"),
    ("IOT Device", "AC:87:3F:69:42:0F", "Connected"), '''
]

bad_status = ["Bad", "Active alert. System facing deauthentication.", "DarkOrange"]
good_status = ["Good", "No alerts active. System protected.", "green"]
status = "good"

logHead = ("Target MAC", "Start Time", "Duration", "End Time")
logData = [

	'''	Typical Format
    ("DC:27:2D:5B:BA:28", "06:59:33", "In Progress", "--:--:--"), # 00:31:27 07:31:00
    ("3F:28:93:89:60:48", "05:13:17", "00:01:22", "05:14:39"),
    ("C2:48:D2:72:3A:CD", "03:22:16", "00:12:24", "03:34:40"),
    ("83:44:65:B7:71:24", "01:09:42", "00:05:20", "01:15:02"),'''
]

app = Flask(__name__)
@app.route("/")
def home():
	use_labels = []
    if status in "good":
        #statAlert = "<span style=\"color:green;\">Good</span>"
        us = "green;\">Good"
		use_labels = good_status
    elif status in "bad":
        #statAlert = "<span style=\"color:DarkOrange;\">Alert</span>"
        us = "DarkOrange;\">Alert"
		use_labels = bad_status
    elif status in "ugly":
        us = "red;\">Warning"

    stat = "<div class=\"container\"><p>Status: <span style=\"color:" + us + "</span></p></div>"
    page = render_template("index1.html", headings = headings, data = data) + stat + render_template("index2.html", headings = headings, data = data, status=status, alert=alert, statAlert=statAlert, clr=clr, logHead=logHead, logData=logData)
    
	return page

@app.route("/cycle/", methods=['POST'])
def cycle():
    
    if status in "good":
        clr = "green"
        #statAlert = "<span style='color:green;'>Good</span>"
        statAlert = "Good"
        status = "bad"
        alert = "Active alert. System facing deauthentication."
    else:
        clr  = "DarkOrange"
        #statAlert = "<span style='color:DarkOrange;'>Alert</span>"
        statAlert = "Alert"
        status = "good"
        alert = "No alerts active. System protected."
    return redirect(url_for("home"))

@app.route("/status/<status>")
def user(floop):
    return "Status is {floop}"

# Hard coded for our system
ap = "0a:11:96:8c:11:29"

deauth_table = {"" : ""}
	# address: adddr
	# pkt_queue: packets
	# warning: true/false

connections = []

def parseMACaddrs(pkt):
	# Adds transmitting/receiving device to list of connections if not present
	addr = ""
	if pkt.wlan.sa != ap:
		addr = pkt.wlan.sa
	else:
		addr = pkt.wlan.da
	
	if addr not in connections:
		connections.append(addr)
		data.append((addr, "Connected"))
		print("New connection discovered: ", addr)
		cycle()
	return addr

def removeConnection(dev):
	print("Removing connection: ", dev)
	connections.remove(dev)
	data.remove((dev, "Connected"))
	data.append(dev, "Disconnected")

def monitorAttackProgress(dev):
	attack = True
	ts = deauth_table[dev]["first_timestamp"]
	while attack:
		last_ts = float(deauth_table[dev]["packet_queue"][-1].sniff_timestamp)
		if last_ts - ts < 3 and last_ts - ts > 0:
			print("Attack in progress on", dev)
		else:
			print("Attack ended on ", dev)
			start = deauth_table[dev]["first_timestamp"]
			end = last_ts
			logData.append((dev,start,end,end-start))
			attack = False
			break
		time.sleep(2)
		ts = last_ts
	deauth_table.pop(dev)

def checkDeAuth(dev, pkt):
	#print("Testing deauth")
	if dev not in deauth_table.keys():
		deauth_table[dev] = {"first_timestamp":float(pkt.sniff_timestamp), "packet_queue": [pkt], "warning": False}
	else:
		# Add to table
		deauth_table[dev]["packet_queue"].append(pkt)
		if (float(pkt.sniff_timestamp) - float(deauth_table[dev]["first_timestamp"]) > 5) and (deauth_table[dev]["warning"] != True):
			# Timeout if the next 
			deauth_table.pop(dev, None)
		if len(deauth_table[dev]["packet_queue"]) > 4 and deauth_table[dev]["warning"] == False:
			deauth_table[dev]["warning"] = True
			print("Deauthentication attack detected on: ", dev)
			mon = threading.Thread(target=monitorAttackProgress, args=(dev,))
			mon.start()


def startIDS():
	filter = "ether host 0a:11:96:8c:11:29"
	cap = pyshark.LiveCapture(interface="wlan0mon", bpf_filter=filter)
	dev = ""
	for pkt in cap.sniff_continuously():
		#print(pkt.wlan.fc[3:7])
		dev = parseMACaddrs(pkt)
		if pkt.wlan.fc[3:5] == '00':
			if pkt.wlan.fc[5:7] == '0a':
				# Disassociation is OK for now
				removeConnection(dev)
			if pkt.wlan.fc[5:7] == '0c':
				checkDeAuth(dev, pkt)

if __name__ == '__main__':
	if "--no-flask" in sys.argv:
		noFlask = True
	else:
		noFlask = False

	ids_thread = threading.Thread(target=startIDS)
	ids_thread.start()
	if not noFlask:
		app.run(host='127.0.0.1',port=5000,debug=True)
	ids_thread.join()
