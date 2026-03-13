# Kerlab
A Rust implementation of Kerberos for FUn and Detection

Kerlab was developed just to drill down *kerberos* protocol and better understand it.
The main purpose is to write more targeted detection rules. 

:warning: Kerlab needs the nightly version of rust because we massively use static parameters for template :warning:

## klist2kirbi Convert Klist command output into kirbi format

`klist2kirbi` will parse the output of the command like:

```
ServiceName        : krbtgt
TargetName (SPN)   : krbtgt
ClientName         : SA-MONITORING
DomainName         : ATTACKRANGE.LOCAL
TargetDomainName   : ATTACKRANGE.LOCAL
AltTargetDomainName: ATTACKRANGE.LOCAL
Ticket Flags       : 0x40e10000 -> forwardable renewable initial pre_authent name_canonicalize
Session Key        : KeyType 0x12 - AES-256-CTS-HMAC-SHA1-96
                   : KeyLength 32 - 17 a7 b0 95 e8 e8 d2 9d c9 58 a8 c6 1b b8 5b 3f fe 22 84 9e 27 64 cc 77 26 a2 56 0f df 98 fe 17
StartTime          : 3/13/2026 10:15:43 (local)
EndTime            : 3/13/2026 20:15:43 (local)
RenewUntil         : 3/20/2026 10:15:43 (local)
TimeSkew           :  + 0:00 minute(s)
EncodedTicket      : (size: 1279)
0000  61 82 04 fb 30 82 04 f7:a0 03 02 01 05 a1 13 1b  a...0...........
0010  11 41 54 54 41 43 4b 52:41 4e 47 45 2e 4c 4f 43  .ATTACKRANGE.LOC
0020  41 4c a2 26 30 24 a0 03:02 01 02 a1 1d 30 1b 1b  AL.&0$.......0..
0030  06 6b 72 62 74 67 74 1b:11 41 54 54 41 43 4b 52  .krbtgt..ATTACKR
0040  41 4e 47 45 2e 4c 4f 43:41 4c a3 82 04 b1 30 82  ANGE.LOCAL....0.
...
```

To produce a valid ticket in *kirbi* format:

```
.\klist2kirbi --klist example.klist --outfile example.kirbi
[APPLICATION 22] KrbCredBody
        pvno         [0] : 5
        msg_ticket   [1] : 22
        tickets      [2] : SEQUENCE OF
                [APPLICATION 1] TicketBody
                        tkt_vno  [0] : 5
                        realm    [1] : "ATTACKRANGE.LOCAL"
                        sname    [2] : PrincipalName
                                name_type    [0] : 2 (NtSrvInst)
                                name_string  [1] : SEQUENCE OF
                                        "krbtgt"
                                        "ATTACKRANGE.LOCAL"
                        enc_part [3] : EncryptedData
                                etype  [0] : 18 (AES-256-CTS-HMAC-SHA-196)
                                kvno   [1] : 2
                                cipher [2] : QekDm3LT7ngk0mBqoiJhhhOJQEU8gjZsB9+6AMyYEz3ehaEwIV71InGGhcH596LyjRic6FaFKJsXcZqsPKKLxMlBNY6IFmnWmlUTposlTVbjvIO4i6tbaZczweMFCg7W5C8gwgScSM4geJyDrriti8b325T9TVzd5TxCWn4MFu4Im0IOo8jA1IGnD8pR7lADPIRhg3cc8NWEY+peeCA/DQ9EJfHYs4GqDDUkUsL9auwdL2Pe9S+JNwD8W7Hxh1cMU361J372cytCkOi/RcCQiXFO+tP09GmlokBSFARCHaXl1glZqRPSqse+s8zgYsoh0EQipguPxckdzYNz5dgYyIGRmYNKPYy7ZZUyqXbb5DBTp/REsJ5CdgKlmyyQ52bV4K0EMjUO3IvPDCDx9SVuH4t/n00ov8+gQECGbxXobvK+jSNUaeg7C8mV01ie2bywtUZEsSg/XQi8zFNgLTMV6QN66mX0scOX7Vd/K8w+i5v44yIJV+fLUZEuFIqZbS9ZHKB7KvL3+o0E1OJ0qjOmQRGiWaBEc1SV20IFt4b0mEVIPKI9H5wOf/OQny9z5BQZfjlRk64VFGnQD22eVGrQZqq+NfcRCk3AG+H5w+TReoN9gKw3RxrwP4QH/DAS2g+rdXEG0Vj5oYPVdMZAsOxPIWq2wRNwKXxi1nv19kfp6AmWMuhDR9q0mnVYnNBfMizDwTjxNB3DY1Yiis7YPMmQtehRs11gxOxVNLd6e14GK6GuVhnTQm0PiM3hDA+jzhSXmGGOLDHtw4dmjaHaZX7ob2qFTgqB9eliDHdwTqeE98TDBj2jNSGIDj+FRUSKGheWPdscnuHt+Lw6laoY/Bv0oRK3qcZBh56rUxK5z5rrBhPHuUKo/rPU31Wzlnqssg54U32MNfhsAcXcXp4Rj42XKmpr8pKCjT+rsKtDS2OvItolnqtJugB1BO4Ui8OeTvVUoGFJQV98TktjDdhcraG9aB8TKHds8gCxHyRe/A8cuA6Fuig0QMf0gNgmYeA7TsuLhYlBYRPIvptjWfpdWySCCXzCaoXDewJmy0cYmKF9noet2yuUeizoHz4vfVQcAYkBX348D3c4OJgbafL4HSTnfES2VBfszoHqZvaPm37jQJk4pKVX1c02cKqMENEXI+u1bpsaozwpYF8+L3TMY/Iqrooa7uy/7HNOrTrqLZPSWImrFXbUKHhbvS8UqDrAxsvw9v0Gc/8k5Nar4tXsXTVweTGg0XApYik9wO8xJGmUnb9PMutT5B6QMt4UwQjoeJ/AMtkntDO2tijBfLjNLXR/2ArSMuskp2gkEV8dLEtJ6Pv+GIV5qSp9qYgbGTITpKU8Wx/JAbcwE9/oCyUSRwrkl8ZqlGEjpAkAo+FNnVF1qvAi2lWN3zulFg32wEVUEttUDClM8NZNZ02PSDgq+1PFT/WnwN58cfCao6s/W7nh+dr1dtSKxd3H6xAnN9H7mNiRB+IE2zZgouV8tLPS6FbMZVyafVMVwYO8xtmKV1rFl/psYR3V78Yox5v5+8o8Wj4RYE1p9IkAJdOF8TMZq0SBVCGnTd+anm3lq4nP

        enc_part     [3] : EncryptedData
                etype  [0] : 0 (UNKNOWN)
                kvno   None
                cipher [2] : fYH8MIH5oIH2MIHzMIHwoCswKaADAgESoSIEIBensJXo6NKdyVioxhu4Wz/+IoSeJ2TMdyaiVg/fmP4XoRMbEUFUVEFDS1JBTkdFLkxPQ0FMohowGKADAgEBoREwDxsNU0EtTU9OSVRPUklOR6MHAwUAQOEAAKQRGA8yMDI2MDMxMzEyMzExOVqlERgPMjAyNjAzMTMxMjMxMTlaphEYDzIwMjYwMzEzMTIzMTE5WqcRGA8yMDI2MDMxMzEyMzExOVqoExsRQVRUQUNLUkFOR0UuTE9DQUypJjAkoAMCAQKhHTAbGwZrcmJ0Z3QbEUFUVEFDS1JBTkdFLkxPQ0FM
**************************************************
Saving KRB-CRED in c:\work\tmp\example.kirbi
```

## kerasktgt Kerberos Ask Ticket Granting Ticket

Use to ask the first Ticket in kerberos protocol. If the username is not set, the TGT request is made without pre authentication.
It will write the ticket into KRB_CRED format, compatible with rubeus or mimikatz.
We can choose between the cleartext password, or the ntlm hash version.

## kerasktgs Kerberos Ask Ticket Granting Servive

Use to ask a TGS ticket using a saved TGT. `kerasktgs` support S4U protocol extension, through `s4u` options.

## kerforce Kerberos Brute Force

Use to perform an online brute force attack. The file attribute is just a file with a password at each line.

## kerspray Kerberos Password Spraying

Use to perform a Kerberos Password spraying attack using a list of username.

## kerticket Kerberos Ticket Viewer

Print informations of ticket saved on disk. Use to convert a ticket into hashcat compatible format.
We can decrytp the `EncTicketPartBody` using the hash or the password of the service (including krbtgt).

