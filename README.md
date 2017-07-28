# VolatilityNotpetyakeys
This Volatility plugin is used to search for AES key withing a memory snapshot of an infected host **on which NotPetya is running**.

### Input
The only input required is the 32-bit `rsaenh.dll` file from the filesystem of the infected host.
You will find it:
* On 32-bit hosts, at `C:\WINDOWS\System32\rsaenh.dll`
* On 64-bit hosts, at `C:\WINDOWS\SysWOW64\rsaenh.dll`

### Usage
```
vol.py -f mem --profile=<profile> notpetyakeys -r rsaenh.dll
```


### Output
Output is every AES key used by NotPetya (on per fixed drive).


### Next steps
Python decryption tool to come.
