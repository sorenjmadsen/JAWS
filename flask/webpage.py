from flask import Flask, render_template, request, redirect, url_for

app = Flask(__name__)

headings = ("Device Name", "MAC", "Status")
data = (
    ("Raspberry Pi", "6F:F7:4E:93:6B:D8", "Connected"),
    ("Client", "DC:27:2D:5B:BA:28", "Under Attack"),
    ("MacBook Pro", "14:46:01:0A:09:E0", "Connected"),
    ("IOT Device", "AC:87:3F:69:42:0F", "Connected"),
)

status = "bad"
alert = "Active alert. System facing deauthentication."
stat = ""
statAlert = ""
clr = ""

logHead = ("Target MAC", "Start Time", "Duration", "End Time")
logData = (
    ("DC:27:2D:5B:BA:28", "06:59:33", "In Progress", "--:--:--"), # 00:31:27 07:31:00
    ("3F:28:93:89:60:48", "05:13:17", "00:01:22", "05:14:39"),
    ("C2:48:D2:72:3A:CD", "03:22:16", "00:12:24", "03:34:40"),
    ("83:44:65:B7:71:24", "01:09:42", "00:05:20", "01:15:02"),
)

@app.route("/", methods=['GET', 'POST'])
def home():
    global status, stat, alert, statAlert, clr, log
    
    if status in "good":
        #statAlert = "<span style=\"color:green;\">Good</span>"
        us = "green;\">Good"
    elif status in "bad":
        #statAlert = "<span style=\"color:DarkOrange;\">Alert</span>"
        us = "DarkOrange;\">Alert"
    elif status in "ugly":
        us = "red;\">Warning"
    stat = "<div class=\"container\"><p>Status: <span style=\"color:" + us + "</span></p></div>"
    page = render_template("index1.html", headings = headings, data = data) + stat + render_template("index2.html", headings = headings, data = data, status=status, alert=alert, statAlert=statAlert, clr=clr, logHead=logHead, logData=logData)
    return page

@app.route("/cycle/", methods=['POST'])
def cycle():
    global status, stat, alert, statAlert, clr, log
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

if __name__ == "__main__":
    app.run(debug=True)