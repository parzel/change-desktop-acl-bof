# Change WINSTA/Desktop ACLs BOF

This BOF/EXE changes the ACLs of the current window station and desktop to allow the access to the everyone group. It can for example be used in combination with
CreateProcessWithTokenW to run a process with another user's token (from a different session), in the current session. 

## Compile
```
make 
make test
```

## Credits:
* https://github.com/trustedsec/CS-Situational-Awareness-BOF
* ChatGPT
