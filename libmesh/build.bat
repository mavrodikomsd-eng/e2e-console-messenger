@echo off
set PATH=C:\msys64\ucrt64\bin;%PATH%
cd /d %~dp0
gcc -shared -O2 -Wall -o libmesh.dll libmesh.c libmesh.def -L/ucrt64/lib -Wl,-Bstatic -lsodium -Wl,-Bdynamic

