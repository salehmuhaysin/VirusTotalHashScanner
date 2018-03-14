# VirusTotalHashScanner
Tool to check a list of MD5 hashes against VirusTotal to get the result ( number of AV found the file of the given hash malicious )

NOTE: inside the python script change the API key with your own key, you get it from your VirusTotal account

To learn more about VirusTotal API please go [here](https://github.com/Gawen/virustotal)

### Requirements:

Install the virustotal api

>	**pip install virustotal**


### Usage:

*\<input-file\>*: a file contain a list of hashes each one in new line  
The result will be stored in another file ( *\<input-file\>.scanned* )

To start scanning:

> **python vtchk.py *\<filename\>***



### Watching results:

If you want to watch only the results that has 2 hits or more, use the following command:

> **watch -d "cat res.csv.scanned | grep -v 0/ | grep -v 'NO DATA' | grep -v 'Couldn' | grep -v 1/"**

