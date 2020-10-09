# session_capture

This repository is for the course Innovation group I in Southern University of Science and Technology (SUSTech, Shenzhen).

Our group members:

Shilong Li (Junior in SUSTech)

Xiangyu Xu (Junior in SUSTech)

Mulin Yi (Junior in SUSTech)

## Project Title

Cross-platform HTTPS traffic capture and analysis based on MitM-proxy

## Introduction

When performing various tasks of software engineering, especially for automated testing of major platforms (Window, Linux, mobile platforms, etc.), it is often necessary to capture the HTTP and HTTPS traffic generated during the test.  However, the currently widely used traffic monitoring tools on the market, such as WireShark, Fiddler, Charles, etc., often lack cross-platform support and lack ease of use in the development environment, causing users to waste a lot of traffic when doing traffic analysis.  Manpower and material resources.

In order to solve this difficulty, this project is based on the open source mitmproxy tool to develop a tool that is compatible with HTTPS traffic capture on major platforms.  The tool records and stores various information in the request and response in a detailed and structured manner, and further provides APIs for traffic analysis, such as classifying files in the traffic and security analysis.  This tool is easy to use and can be easily applied to various software development and testing tools, which provides convenience for the majority of developers.

## Tips for using our script

### Environment preparation

- python3.x

- mitmproxy
  - If not installed, please use the command `pip install mitmproxy` in the command line.

- mobile devices

- stable Internet connections

- shut down your firewalls (or give some permissions)
- install certificates from the website `mitm.it` in your mobile devices
  - if you have Apple devices, you not only install certificates from the website, but allow the root certificate to let your PC capture the https traffic (if not, your Apple devices cannot open the websites of https)

### Using the script

1. clone this repository
2. make your mobile devices and PC connect the same Wi-Fi.
3. open the terminal, and type the command `ipconfig /all` to see the PC's IPv4 address.
4. set the 'server' value to PC's IPv4 address in 3, and 'port' to the number you want, but it needs the same as the [portNumber] in 5
5. open the terminal, and type the command `mitmweb -p [portNumber] -s [the absolute path of capture.py] -q` or `mitmdump -p [portNumber] -s [the absolute path of capture.py] -q`to start the script. **Attention: **in Windows, you should use mitmweb/mitmdump instead of mitmproxy, but in MacOS/Linux, you can use mitmproxy.
6. open chrome/safari/edge in your mobile devices and go surfing
7. check the files stored in the PC.

### After executing the script

- The script stores every traffic in the PC, and classifies them according to its `device IPv4 address` and `content-type` of response.

- Every session is stored as multiple files:
  - [session_id]_request.json (including `headers`, `accept-language`,... but not containing `content`)
  - [session_id]_request_content.json (specially for storing content in request)
  - [session_id]_response.json (including `headers`, `content-type`,... but not containing `content`)
  - [session_id]_response_content.json (specially for strong content in response)
  - [session_id]_response_content.xxx (if the content of response is not null, then store it in the right suffix) **[optional]**
- 

## Credits

Most parts of the script credits to [jsondump.py](https://github.com/mitmproxy/mitmproxy/blob/master/examples/contrib/jsondump.py) in the official [mitmproxy repository](https://github.com/mitmproxy/mitmproxy/).