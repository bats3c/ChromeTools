# ChromeTools

https://www.mdsec.co.uk/2021/01/breaking-the-browser-a-tale-of-ipc-credentials-and-backdoors/

Tools to abuse chrome

- ChromeTap

  Log all data sent by chrome to disk, allowing you to extract cookies and credentials with the `hunt.py` tool or manual review.

- ChromeBackdoor

  Turn chrome into a backdoor forcing it to execute any code between `<shellcode></shellcode>` tags. Using this along side a persistence method will allow you to retain access to a machine without having a beacon. All the user has to do is click a link, open an email or view an 'image' containing these tags and your shellcode.
  
- SSLSteal

  Steal data from chrome's SSL encryption routine.
