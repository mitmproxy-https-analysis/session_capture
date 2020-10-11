# for use of transfer strings to bytes, in function string2bytes_format()
DICTION = {'a': 7, 'b': 8, 'f': 12, 'n': 10, 'r': 13,
           't': 9, 'v': 11, "'": 39, '"': 34, '?': 63, '0': 0}
# for use of different ip id
ID_POOL = {}

# set the root directory of the project
HOME = "C:\\projects\\mitmproxy_group_I"

SUFFIX = {
    "application/octet-stream": [
        ""
    ],
    "image/tiff": [
        ".tif",
        ".tif",
        ".tiff"
    ],
    "application/x-001": [
        ".001"
    ],
    "application/x-301": [
        ".301"
    ],
    "text/h323": [
        ".323"
    ],
    "application/x-906": [
        ".906"
    ],
    "drawing/907": [
        ".907"
    ],
    "application/x-a11": [
        ".a11"
    ],
    "audio/x-mei-aac": [
        ".acp"
    ],
    "application/postscript": [
        ".ai",
        ".eps",
        ".ps"
    ],
    "audio/aiff": [
        ".aif",
        ".aifc",
        ".aiff"
    ],
    "application/x-anv": [
        ".anv"
    ],
    "text/asa": [
        ".asa"
    ],
    "video/x-ms-asf": [
        ".asf",
        ".asx"
    ],
    "text/asp": [
        ".asp"
    ],
    "audio/basic": [
        ".au",
        ".snd"
    ],
    "video/avi": [
        ".avi"
    ],
    "application/vnd.adobe.workflow": [
        ".awf"
    ],
    "text/xml": [
        ".biz",
        ".cml",
        ".dcd",
        ".dtd",
        ".ent",
        ".fo",
        ".math",
        ".mml",
        ".mtx",
        ".rdf",
        ".spp",
        ".svg",
        ".tld",
        ".tsd",
        ".vml",
        ".vxml",
        ".wsdl",
        ".xdr",
        ".xml",
        ".xq",
        ".xql",
        ".xquery",
        ".xsd",
        ".xsl",
        ".xslt"
    ],
    "application/x-bmp": [
        ".bmp"
    ],
    "application/x-bot": [
        ".bot"
    ],
    "application/x-c4t": [
        ".c4t"
    ],
    "application/x-c90": [
        ".c90"
    ],
    "application/x-cals": [
        ".cal"
    ],
    "application/vnd.ms-pki.seccat": [
        ".cat"
    ],
    "application/x-netcdf": [
        ".cdf"
    ],
    "application/x-cdr": [
        ".cdr"
    ],
    "application/x-cel": [
        ".cel"
    ],
    "application/x-x509-ca-cert": [
        ".cer",
        ".crt",
        ".der"
    ],
    "application/x-g4": [
        ".cg4",
        ".g4",
        ".ig4"
    ],
    "application/x-cgm": [
        ".cgm"
    ],
    "application/x-cit": [
        ".cit"
    ],
    "java/*": [
        ".class",
        ".java"
    ],
    "application/x-cmp": [
        ".cmp"
    ],
    "application/x-cmx": [
        ".cmx"
    ],
    "application/x-cot": [
        ".cot"
    ],
    "application/pkix-crl": [
        ".crl"
    ],
    "application/x-csi": [
        ".csi"
    ],
    "text/css": [
        ".css"
    ],
    "application/x-cut": [
        ".cut"
    ],
    "application/x-dbf": [
        ".dbf"
    ],
    "application/x-dbm": [
        ".dbm"
    ],
    "application/x-dbx": [
        ".dbx"
    ],
    "application/x-dcx": [
        ".dcx"
    ],
    "application/x-dgn": [
        ".dgn"
    ],
    "application/x-dib": [
        ".dib"
    ],
    "application/x-msdownload": [
        ".dll",
        ".exe"
    ],
    "application/msword": [
        ".doc",
        ".dot",
        ".rtf",
        ".wiz"
    ],
    "application/x-drw": [
        ".drw"
    ],
    "Model/vnd.dwf": [
        ".dwf"
    ],
    "application/x-dwf": [
        ".dwf"
    ],
    "application/x-dwg": [
        ".dwg"
    ],
    "application/x-dxb": [
        ".dxb"
    ],
    "application/x-dxf": [
        ".dxf"
    ],
    "application/vnd.adobe.edn": [
        ".edn"
    ],
    "application/x-emf": [
        ".emf"
    ],
    "message/rfc822": [
        ".eml",
        ".mht",
        ".mhtml",
        ".nws"
    ],
    "application/x-epi": [
        ".epi"
    ],
    "application/x-ps": [
        ".eps",
        ".ps"
    ],
    "application/x-ebx": [
        ".etd"
    ],
    "image/fax": [
        ".fax"
    ],
    "application/vnd.fdf": [
        ".fdf"
    ],
    "application/fractals": [
        ".fif"
    ],
    "application/x-frm": [
        ".frm"
    ],
    "application/x-gbr": [
        ".gbr"
    ],
    "application/x-": [
        "."
    ],
    "image/gif": [
        ".gif"
    ],
    "application/x-gl2": [
        ".gl2"
    ],
    "application/x-gp4": [
        ".gp4"
    ],
    "application/x-hgl": [
        ".hgl"
    ],
    "application/x-hmr": [
        ".hmr"
    ],
    "application/x-hpgl": [
        ".hpg"
    ],
    "application/x-hpl": [
        ".hpl"
    ],
    "application/mac-binhex40": [
        ".hqx"
    ],
    "application/x-hrf": [
        ".hrf"
    ],
    "application/hta": [
        ".hta"
    ],
    "text/x-component": [
        ".htc"
    ],
    "text/html": [
        ".htm",
        ".html",
        ".htx",
        ".jsp",
        ".plg",
        ".stm",
        ".xhtml"
    ],
    "text/webviewhtml": [
        ".htt"
    ],
    "application/x-icb": [
        ".icb"
    ],
    "image/x-icon": [
        ".ico"
    ],
    "application/x-ico": [
        ".ico"
    ],
    "application/x-iff": [
        ".iff"
    ],
    "application/x-igs": [
        ".igs"
    ],
    "application/x-iphone": [
        ".iii"
    ],
    "application/x-img": [
        ".img"
    ],
    "application/x-internet-signup": [
        ".ins",
        ".isp"
    ],
    "video/x-ivf": [
        ".IVF"
    ],
    "image/jpeg": [
        ".jfif",
        ".jpe",
        ".jpeg",
        ".jpg"
    ],
    "application/x-jpe": [
        ".jpe"
    ],
    "application/x-jpg": [
        ".jpg"
    ],
    "application/x-javascript": [
        ".js",
        ".ls",
        ".mocha"
    ],
    "audio/x-liquid-file": [
        ".la1"
    ],
    "application/x-laplayer-reg": [
        ".lar"
    ],
    "application/x-latex": [
        ".latex"
    ],
    "audio/x-liquid-secure": [
        ".lavs"
    ],
    "application/x-lbm": [
        ".lbm"
    ],
    "audio/x-la-lms": [
        ".lmsff"
    ],
    "application/x-ltr": [
        ".ltr"
    ],
    "video/x-mpeg": [
        ".m1v",
        ".m2v",
        ".mpe",
        ".mps"
    ],
    "audio/mpegurl": [
        ".m3u"
    ],
    "video/mpeg4": [
        ".m4e",
        ".mp4"
    ],
    "application/x-mac": [
        ".mac"
    ],
    "application/x-troff-man": [
        ".man"
    ],
    "application/msaccess": [
        ".mdb"
    ],
    "application/x-mdb": [
        ".mdb"
    ],
    "application/x-shockwave-flash": [
        ".mfp",
        ".swf"
    ],
    "application/x-mi": [
        ".mi"
    ],
    "audio/mid": [
        ".mid",
        ".midi",
        ".rmi"
    ],
    "application/x-mil": [
        ".mil"
    ],
    "audio/x-musicnet-download": [
        ".mnd"
    ],
    "audio/x-musicnet-stream": [
        ".mns"
    ],
    "video/x-sgi-movie": [
        ".movie"
    ],
    "audio/mp1": [
        ".mp1"
    ],
    "audio/mp2": [
        ".mp2"
    ],
    "video/mpeg": [
        ".mp2v",
        ".mpv2"
    ],
    "audio/mp3": [
        ".mp3"
    ],
    "video/x-mpg": [
        ".mpa"
    ],
    "application/vnd.ms-project": [
        ".mpd",
        ".mpp",
        ".mpt",
        ".mpw",
        ".mpx"
    ],
    "video/mpg": [
        ".mpeg",
        ".mpg",
        ".mpv"
    ],
    "audio/rn-mpeg": [
        ".mpga"
    ],
    "application/x-mmxp": [
        ".mxp"
    ],
    "image/pnetvue": [
        ".net"
    ],
    "application/x-nrf": [
        ".nrf"
    ],
    "text/x-ms-odc": [
        ".odc"
    ],
    "application/x-out": [
        ".out"
    ],
    "application/pkcs10": [
        ".p10"
    ],
    "application/x-pkcs12": [
        ".p12",
        ".pfx"
    ],
    "application/x-pkcs7-certificates": [
        ".p7b",
        ".spc"
    ],
    "application/pkcs7-mime": [
        ".p7c",
        ".p7m"
    ],
    "application/x-pkcs7-certreqresp": [
        ".p7r"
    ],
    "application/pkcs7-signature": [
        ".p7s"
    ],
    "application/x-pc5": [
        ".pc5"
    ],
    "application/x-pci": [
        ".pci"
    ],
    "application/x-pcl": [
        ".pcl"
    ],
    "application/x-pcx": [
        ".pcx"
    ],
    "application/pdf": [
        ".pdf",
        ".pdf"
    ],
    "application/vnd.adobe.pdx": [
        ".pdx"
    ],
    "application/x-pgl": [
        ".pgl"
    ],
    "application/x-pic": [
        ".pic"
    ],
    "application/vnd.ms-pki.pko": [
        ".pko"
    ],
    "application/x-perl": [
        ".pl"
    ],
    "audio/scpls": [
        ".pls",
        ".xpl"
    ],
    "application/x-plt": [
        ".plt"
    ],
    "image/png": [
        ".png"
    ],
    "application/x-png": [
        ".png"
    ],
    "application/vnd.ms-powerpoint": [
        ".pot",
        ".ppa",
        ".pps",
        ".ppt",
        ".pwz"
    ],
    "application/x-ppm": [
        ".ppm"
    ],
    "application/x-ppt": [
        ".ppt"
    ],
    "application/x-pr": [
        ".pr"
    ],
    "application/pics-rules": [
        ".prf"
    ],
    "application/x-prn": [
        ".prn"
    ],
    "application/x-prt": [
        ".prt"
    ],
    "application/x-ptn": [
        ".ptn"
    ],
    "text/vnd.rn-realtext3d": [
        ".r3t"
    ],
    "audio/vnd.rn-realaudio": [
        ".ra"
    ],
    "audio/x-pn-realaudio": [
        ".ram",
        ".rmm"
    ],
    "application/x-ras": [
        ".ras"
    ],
    "application/rat-file": [
        ".rat"
    ],
    "application/vnd.rn-recording": [
        ".rec"
    ],
    "application/x-red": [
        ".red"
    ],
    "application/x-rgb": [
        ".rgb"
    ],
    "application/vnd.rn-realsystem-rjs": [
        ".rjs"
    ],
    "application/vnd.rn-realsystem-rjt": [
        ".rjt"
    ],
    "application/x-rlc": [
        ".rlc"
    ],
    "application/x-rle": [
        ".rle"
    ],
    "application/vnd.rn-realmedia": [
        ".rm"
    ],
    "application/vnd.adobe.rmf": [
        ".rmf"
    ],
    "application/vnd.rn-realsystem-rmj": [
        ".rmj"
    ],
    "application/vnd.rn-rn_music_package": [
        ".rmp"
    ],
    "application/vnd.rn-realmedia-secure": [
        ".rms"
    ],
    "application/vnd.rn-realmedia-vbr": [
        ".rmvb"
    ],
    "application/vnd.rn-realsystem-rmx": [
        ".rmx"
    ],
    "application/vnd.rn-realplayer": [
        ".rnx"
    ],
    "image/vnd.rn-realpix": [
        ".rp"
    ],
    "audio/x-pn-realaudio-plugin": [
        ".rpm"
    ],
    "application/vnd.rn-rsml": [
        ".rsml"
    ],
    "text/vnd.rn-realtext": [
        ".rt"
    ],
    "application/x-rtf": [
        ".rtf"
    ],
    "video/vnd.rn-realvideo": [
        ".rv"
    ],
    "application/x-sam": [
        ".sam"
    ],
    "application/x-sat": [
        ".sat"
    ],
    "application/sdp": [
        ".sdp"
    ],
    "application/x-sdw": [
        ".sdw"
    ],
    "application/x-stuffit": [
        ".sit"
    ],
    "application/x-slb": [
        ".slb"
    ],
    "application/x-sld": [
        ".sld"
    ],
    "drawing/x-slk": [
        ".slk"
    ],
    "application/smil": [
        ".smi",
        ".smil"
    ],
    "application/x-smk": [
        ".smk"
    ],
    "text/plain": [
        ".sol",
        ".sor",
        ".txt"
    ],
    "application/futuresplash": [
        ".spl"
    ],
    "application/streamingmedia": [
        ".ssm"
    ],
    "application/vnd.ms-pki.certstore": [
        ".sst"
    ],
    "application/vnd.ms-pki.stl": [
        ".stl"
    ],
    "application/x-sty": [
        ".sty"
    ],
    "application/x-tdf": [
        ".tdf"
    ],
    "application/x-tg4": [
        ".tg4"
    ],
    "application/x-tga": [
        ".tga"
    ],
    "application/x-tif": [
        ".tif"
    ],
    "drawing/x-top": [
        ".top"
    ],
    "application/x-bittorrent": [
        ".torrent"
    ],
    "application/x-icq": [
        ".uin"
    ],
    "text/iuls": [
        ".uls"
    ],
    "text/x-vcard": [
        ".vcf"
    ],
    "application/x-vda": [
        ".vda"
    ],
    "application/vnd.visio": [
        ".vdx",
        ".vsd",
        ".vss",
        ".vst",
        ".vsw",
        ".vsx",
        ".vtx"
    ],
    "application/x-vpeg005": [
        ".vpg"
    ],
    "application/x-vsd": [
        ".vsd"
    ],
    "application/x-vst": [
        ".vst"
    ],
    "audio/wav": [
        ".wav"
    ],
    "audio/x-ms-wax": [
        ".wax"
    ],
    "application/x-wb1": [
        ".wb1"
    ],
    "application/x-wb2": [
        ".wb2"
    ],
    "application/x-wb3": [
        ".wb3"
    ],
    "image/vnd.wap.wbmp": [
        ".wbmp"
    ],
    "application/x-wk3": [
        ".wk3"
    ],
    "application/x-wk4": [
        ".wk4"
    ],
    "application/x-wkq": [
        ".wkq"
    ],
    "application/x-wks": [
        ".wks"
    ],
    "video/x-ms-wm": [
        ".wm"
    ],
    "audio/x-ms-wma": [
        ".wma"
    ],
    "application/x-ms-wmd": [
        ".wmd"
    ],
    "application/x-wmf": [
        ".wmf"
    ],
    "text/vnd.wap.wml": [
        ".wml"
    ],
    "video/x-ms-wmv": [
        ".wmv"
    ],
    "video/x-ms-wmx": [
        ".wmx"
    ],
    "application/x-ms-wmz": [
        ".wmz"
    ],
    "application/x-wp6": [
        ".wp6"
    ],
    "application/x-wpd": [
        ".wpd"
    ],
    "application/x-wpg": [
        ".wpg"
    ],
    "application/vnd.ms-wpl": [
        ".wpl"
    ],
    "application/x-wq1": [
        ".wq1"
    ],
    "application/x-wr1": [
        ".wr1"
    ],
    "application/x-wri": [
        ".wri"
    ],
    "application/x-wrk": [
        ".wrk"
    ],
    "application/x-ws": [
        ".ws",
        ".ws2"
    ],
    "text/scriptlet": [
        ".wsc"
    ],
    "video/x-ms-wvx": [
        ".wvx"
    ],
    "application/vnd.adobe.xdp": [
        ".xdp"
    ],
    "application/vnd.adobe.xfd": [
        ".xfd"
    ],
    "application/vnd.adobe.xfdf": [
        ".xfdf"
    ],
    "application/vnd.ms-excel": [
        ".xls"
    ],
    "application/x-xls": [
        ".xls"
    ],
    "application/x-xlw": [
        ".xlw"
    ],
    "application/x-xwd": [
        ".xwd"
    ],
    "application/x-x_b": [
        ".x_b"
    ],
    "application/vnd.symbian.install": [
        ".sis",
        ".sisx"
    ],
    "application/x-x_t": [
        ".x_t"
    ],
    "application/vnd.iphone": [
        ".ipa"
    ],
    "application/vnd.android.package-archive": [
        ".apk"
    ],
    "application/x-silverlight-app": [
        ".xap"
    ]
}
"""
    Retrieved from https://www.runoob.com/http/http-content-type.html
"""
# import json
# suffix = [{"application/octet-stream": ""}, {"image/tiff": ".tif"}, {"application/x-001": ".001"},
#           {"application/x-301": ".301"}, {"text/h323": ".323"}, {
#               "application/x-906": ".906"}, {"drawing/907": ".907"},
#           {"application/x-a11": ".a11"}, {"audio/x-mei-aac": ".acp"}, {"application/postscript": ".ai"},
#           {"audio/aiff": ".aif"}, {"audio/aiff": ".aifc"}, {
#               "audio/aiff": ".aiff"}, {"application/x-anv": ".anv"},
#           {"text/asa": ".asa"}, {"video/x-ms-asf": ".asf"}, {
#               "text/asp": ".asp"}, {"video/x-ms-asf": ".asx"},
#           {"audio/basic": ".au"}, {"video/avi": ".avi"}, {"application/vnd.adobe.workflow": ".awf"},
#           {"text/xml": ".biz"}, {"application/x-bmp": ".bmp"}, {"application/x-bot": ".bot"},
#           {"application/x-c4t": ".c4t"}, {"application/x-c90": ".c90"}, {"application/x-cals": ".cal"},
#           {"application/vnd.ms-pki.seccat": ".cat"}, {
#               "application/x-netcdf": ".cdf"}, {"application/x-cdr": ".cdr"},
#           {"application/x-cel": ".cel"}, {"application/x-x509-ca-cert": ".cer"}, {"application/x-g4": ".cg4"},
#           {"application/x-cgm": ".cgm"}, {"application/x-cit": ".cit"}, {
#               "java/*": ".class"}, {"text/xml": ".cml"},
#           {"application/x-cmp": ".cmp"}, {"application/x-cmx": ".cmx"}, {"application/x-cot": ".cot"},
#           {"application/pkix-crl": ".crl"}, {
#               "application/x-x509-ca-cert": ".crt"}, {"application/x-csi": ".csi"},
#           {"text/css": ".css"}, {"application/x-cut": ".cut"}, {"application/x-dbf": ".dbf"},
#           {"application/x-dbm": ".dbm"}, {"application/x-dbx": ".dbx"}, {"text/xml": ".dcd"},
#           {"application/x-dcx": ".dcx"}, {"application/x-x509-ca-cert": ".der"}, {"application/x-dgn": ".dgn"},
#           {"application/x-dib": ".dib"}, {"application/x-msdownload": ".dll"}, {"application/msword": ".doc"},
#           {"application/msword": ".dot"}, {"application/x-drw": ".drw"}, {"text/xml": ".dtd"},
#           {"Model/vnd.dwf": ".dwf"}, {"application/x-dwf": ".dwf"}, {"application/x-dwg": ".dwg"},
#           {"application/x-dxb": ".dxb"}, {"application/x-dxf": ".dxf"}, {
#               "application/vnd.adobe.edn": ".edn"},
#           {"application/x-emf": ".emf"}, {"message/rfc822": ".eml"}, {"text/xml": ".ent"},
#           {"application/x-epi": ".epi"}, {"application/x-ps": ".eps"}, {"application/postscript": ".eps"},
#           {"application/x-ebx": ".etd"}, {"application/x-msdownload": ".exe"}, {"image/fax": ".fax"},
#           {"application/vnd.fdf": ".fdf"}, {"application/fractals": ".fif"}, {"text/xml": ".fo"},
#           {"application/x-frm": ".frm"}, {"application/x-g4": ".g4"}, {"application/x-gbr": ".gbr"},
#           {"application/x-": "."}, {"image/gif": ".gif"}, {
#               "application/x-gl2": ".gl2"}, {"application/x-gp4": ".gp4"},
#           {"application/x-hgl": ".hgl"}, {"application/x-hmr": ".hmr"}, {"application/x-hpgl": ".hpg"},
#           {"application/x-hpl": ".hpl"}, {"application/mac-binhex40": ".hqx"}, {"application/x-hrf": ".hrf"},
#           {"application/hta": ".hta"}, {"text/x-component": ".htc"}, {
#               "text/html": ".htm"}, {"text/html": ".html"},
#           {"text/webviewhtml": ".htt"}, {"text/html": ".htx"}, {
#               "application/x-icb": ".icb"}, {"image/x-icon": ".ico"},
#           {"application/x-ico": ".ico"}, {"application/x-iff": ".iff"}, {"application/x-g4": ".ig4"},
#           {"application/x-igs": ".igs"}, {"application/x-iphone": ".iii"}, {"application/x-img": ".img"},
#           {"application/x-internet-signup": ".ins"}, {
#               "application/x-internet-signup": ".isp"}, {"video/x-ivf": ".IVF"},
#           {"java/*": ".java"}, {"image/jpeg": ".jfif"}, {
#               "image/jpeg": ".jpe"}, {"application/x-jpe": ".jpe"},
#           {"image/jpeg": ".jpeg"}, {"image/jpeg": ".jpg"}, {"application/x-jpg": ".jpg"},
#           {"application/x-javascript": ".js"}, {"text/html": ".jsp"}, {"audio/x-liquid-file": ".la1"},
#           {"application/x-laplayer-reg": ".lar"}, {
#               "application/x-latex": ".latex"}, {"audio/x-liquid-secure": ".lavs"},
#           {"application/x-lbm": ".lbm"}, {"audio/x-la-lms": ".lmsff"}, {"application/x-javascript": ".ls"},
#           {"application/x-ltr": ".ltr"}, {"video/x-mpeg": ".m1v"}, {
#               "video/x-mpeg": ".m2v"}, {"audio/mpegurl": ".m3u"},
#           {"video/mpeg4": ".m4e"}, {"application/x-mac": ".mac"}, {"application/x-troff-man": ".man"},
#           {"text/xml": ".math"}, {"application/msaccess": ".mdb"}, {"application/x-mdb": ".mdb"},
#           {"application/x-shockwave-flash": ".mfp"}, {
#               "message/rfc822": ".mht"}, {"message/rfc822": ".mhtml"},
#           {"application/x-mi": ".mi"}, {"audio/mid": ".mid"}, {
#               "audio/mid": ".midi"}, {"application/x-mil": ".mil"},
#           {"text/xml": ".mml"}, {"audio/x-musicnet-download": ".mnd"}, {"audio/x-musicnet-stream": ".mns"},
#           {"application/x-javascript": ".mocha"}, {"video/x-sgi-movie": ".movie"}, {"audio/mp1": ".mp1"},
#           {"audio/mp2": ".mp2"}, {"video/mpeg": ".mp2v"}, {
#               "audio/mp3": ".mp3"}, {"video/mpeg4": ".mp4"},
#           {"video/x-mpg": ".mpa"}, {"application/vnd.ms-project": ".mpd"}, {"video/x-mpeg": ".mpe"},
#           {"video/mpg": ".mpeg"}, {"video/mpg": ".mpg"}, {"audio/rn-mpeg": ".mpga"},
#           {"application/vnd.ms-project": ".mpp"}, {"video/x-mpeg": ".mps"}, {
#               "application/vnd.ms-project": ".mpt"},
#           {"video/mpg": ".mpv"}, {"video/mpeg": ".mpv2"}, {"application/vnd.ms-project": ".mpw"},
#           {"application/vnd.ms-project": ".mpx"}, {"text/xml": ".mtx"}, {"application/x-mmxp": ".mxp"},
#           {"image/pnetvue": ".net"}, {"application/x-nrf": ".nrf"}, {"message/rfc822": ".nws"},
#           {"text/x-ms-odc": ".odc"}, {"application/x-out": ".out"}, {"application/pkcs10": ".p10"},
#           {"application/x-pkcs12": ".p12"}, {"application/x-pkcs7-certificates": ".p7b"},
#           {"application/pkcs7-mime": ".p7c"}, {"application/pkcs7-mime": ".p7m"},
#           {"application/x-pkcs7-certreqresp": ".p7r"}, {"application/pkcs7-signature": ".p7s"},
#           {"application/x-pc5": ".pc5"}, {"application/x-pci": ".pci"}, {"application/x-pcl": ".pcl"},
#           {"application/x-pcx": ".pcx"}, {"application/pdf": ".pdf"}, {"application/pdf": ".pdf"},
#           {"application/vnd.adobe.pdx": ".pdx"}, {
#               "application/x-pkcs12": ".pfx"}, {"application/x-pgl": ".pgl"},
#           {"application/x-pic": ".pic"}, {"application/vnd.ms-pki.pko": ".pko"}, {"application/x-perl": ".pl"},
#           {"text/html": ".plg"}, {"audio/scpls": ".pls"}, {
#               "application/x-plt": ".plt"}, {"image/png": ".png"},
#           {"application/x-png": ".png"}, {"application/vnd.ms-powerpoint": ".pot"},
#           {"application/vnd.ms-powerpoint": ".ppa"}, {"application/x-ppm": ".ppm"},
#           {"application/vnd.ms-powerpoint": ".pps"}, {"application/vnd.ms-powerpoint": ".ppt"},
#           {"application/x-ppt": ".ppt"}, {"application/x-pr": ".pr"}, {"application/pics-rules": ".prf"},
#           {"application/x-prn": ".prn"}, {"application/x-prt": ".prt"}, {"application/x-ps": ".ps"},
#           {"application/postscript": ".ps"}, {"application/x-ptn": ".ptn"}, {
#               "application/vnd.ms-powerpoint": ".pwz"},
#           {"text/vnd.rn-realtext3d": ".r3t"}, {
#               "audio/vnd.rn-realaudio": ".ra"}, {"audio/x-pn-realaudio": ".ram"},
#           {"application/x-ras": ".ras"}, {"application/rat-file": ".rat"}, {"text/xml": ".rdf"},
#           {"application/vnd.rn-recording": ".rec"}, {
#               "application/x-red": ".red"}, {"application/x-rgb": ".rgb"},
#           {"application/vnd.rn-realsystem-rjs": ".rjs"}, {"application/vnd.rn-realsystem-rjt": ".rjt"},
#           {"application/x-rlc": ".rlc"}, {"application/x-rle": ".rle"}, {
#               "application/vnd.rn-realmedia": ".rm"},
#           {"application/vnd.adobe.rmf": ".rmf"}, {"audio/mid": ".rmi"}, {
#               "application/vnd.rn-realsystem-rmj": ".rmj"},
#           {"audio/x-pn-realaudio": ".rmm"}, {"application/vnd.rn-rn_music_package": ".rmp"},
#           {"application/vnd.rn-realmedia-secure": ".rms"}, {
#               "application/vnd.rn-realmedia-vbr": ".rmvb"},
#           {"application/vnd.rn-realsystem-rmx": ".rmx"}, {"application/vnd.rn-realplayer": ".rnx"},
#           {"image/vnd.rn-realpix": ".rp"}, {"audio/x-pn-realaudio-plugin": ".rpm"},
#           {"application/vnd.rn-rsml": ".rsml"}, {
#               "text/vnd.rn-realtext": ".rt"}, {"application/msword": ".rtf"},
#           {"application/x-rtf": ".rtf"}, {"video/vnd.rn-realvideo": ".rv"}, {"application/x-sam": ".sam"},
#           {"application/x-sat": ".sat"}, {"application/sdp": ".sdp"}, {"application/x-sdw": ".sdw"},
#           {"application/x-stuffit": ".sit"}, {"application/x-slb": ".slb"}, {"application/x-sld": ".sld"},
#           {"drawing/x-slk": ".slk"}, {"application/smil": ".smi"}, {"application/smil": ".smil"},
#           {"application/x-smk": ".smk"}, {"audio/basic": ".snd"}, {
#               "text/plain": ".sol"}, {"text/plain": ".sor"},
#           {"application/x-pkcs7-certificates": ".spc"}, {
#               "application/futuresplash": ".spl"}, {"text/xml": ".spp"},
#           {"application/streamingmedia": ".ssm"}, {"application/vnd.ms-pki.certstore": ".sst"},
#           {"application/vnd.ms-pki.stl": ".stl"}, {"text/html": ".stm"}, {"application/x-sty": ".sty"},
#           {"text/xml": ".svg"}, {"application/x-shockwave-flash": ".swf"}, {"application/x-tdf": ".tdf"},
#           {"application/x-tg4": ".tg4"}, {"application/x-tga": ".tga"}, {"image/tiff": ".tif"},
#           {"application/x-tif": ".tif"}, {"image/tiff": ".tiff"}, {
#               "text/xml": ".tld"}, {"drawing/x-top": ".top"},
#           {"application/x-bittorrent": ".torrent"}, {"text/xml": ".tsd"}, {"text/plain": ".txt"},
#           {"application/x-icq": ".uin"}, {"text/iuls": ".uls"}, {
#               "text/x-vcard": ".vcf"}, {"application/x-vda": ".vda"},
#           {"application/vnd.visio": ".vdx"}, {"text/xml": ".vml"}, {"application/x-vpeg005": ".vpg"},
#           {"application/vnd.visio": ".vsd"}, {"application/x-vsd": ".vsd"}, {"application/vnd.visio": ".vss"},
#           {"application/vnd.visio": ".vst"}, {"application/x-vst": ".vst"}, {"application/vnd.visio": ".vsw"},
#           {"application/vnd.visio": ".vsx"}, {"application/vnd.visio": ".vtx"}, {"text/xml": ".vxml"},
#           {"audio/wav": ".wav"}, {"audio/x-ms-wax": ".wax"}, {"application/x-wb1": ".wb1"},
#           {"application/x-wb2": ".wb2"}, {"application/x-wb3": ".wb3"}, {"image/vnd.wap.wbmp": ".wbmp"},
#           {"application/msword": ".wiz"}, {"application/x-wk3": ".wk3"}, {"application/x-wk4": ".wk4"},
#           {"application/x-wkq": ".wkq"}, {"application/x-wks": ".wks"}, {"video/x-ms-wm": ".wm"},
#           {"audio/x-ms-wma": ".wma"}, {"application/x-ms-wmd": ".wmd"}, {"application/x-wmf": ".wmf"},
#           {"text/vnd.wap.wml": ".wml"}, {"video/x-ms-wmv": ".wmv"}, {"video/x-ms-wmx": ".wmx"},
#           {"application/x-ms-wmz": ".wmz"}, {"application/x-wp6": ".wp6"}, {"application/x-wpd": ".wpd"},
#           {"application/x-wpg": ".wpg"}, {"application/vnd.ms-wpl": ".wpl"}, {"application/x-wq1": ".wq1"},
#           {"application/x-wr1": ".wr1"}, {"application/x-wri": ".wri"}, {"application/x-wrk": ".wrk"},
#           {"application/x-ws": ".ws"}, {"application/x-ws": ".ws2"}, {
#               "text/scriptlet": ".wsc"}, {"text/xml": ".wsdl"},
#           {"video/x-ms-wvx": ".wvx"}, {"application/vnd.adobe.xdp": ".xdp"}, {"text/xml": ".xdr"},
#           {"application/vnd.adobe.xfd": ".xfd"}, {
#               "application/vnd.adobe.xfdf": ".xfdf"}, {"text/html": ".xhtml"},
#           {"application/vnd.ms-excel": ".xls"}, {"application/x-xls": ".xls"}, {"application/x-xlw": ".xlw"},
#           {"text/xml": ".xml"}, {"audio/scpls": ".xpl"}, {"text/xml": ".xq"}, {"text/xml": ".xql"},
#           {"text/xml": ".xquery"}, {"text/xml": ".xsd"}, {"text/xml": ".xsl"}, {"text/xml": ".xslt"},
#           {"application/x-xwd": ".xwd"}, {"application/x-x_b": ".x_b"}, {
#               "application/vnd.symbian.install": ".sis"},
#           {"application/vnd.symbian.install": ".sisx"}, {"application/x-x_t": ".x_t"},
#           {"application/vnd.iphone": ".ipa"}, {"application/vnd.android.package-archive": ".apk"},
#           {"application/x-silverlight-app": ".xap"}]
# SUFFIX = {}
# for i in suffix:
#     for k in i.keys():
#         if not SUFFIX.__contains__(k):
#             SUFFIX[k] = []
#         SUFFIX[k].append(i[k])
# outfile = open('suffix.json', 'a')
# outfile.write(json.dumps(SUFFIX)+'\n')
