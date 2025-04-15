```
gcc -Xlinker -rpath=$HOME/glibc-2.38/compiled-2.38/lib/ -Xlinker -I$HOME/glibc-2.38/compiled-2.38/lib/ld-linux-x86-64.so.2 tmp.c -o tmp
```

fwrite, fread, stdout, 2 rce, stdin = greeting from bksec