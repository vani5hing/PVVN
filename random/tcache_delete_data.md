note cua JHT sai? tcache chi xoa key chu k xoa full data?
Debug this:

```
#include <stdio.h>
#include <stdlib.h>

void main() {
   long *chunk;
   chunk = malloc(0x20);
   chunk[0] = 0x4141414141414141;
   chunk[1] = 0x4141414141414141;
   chunk[2] = 0x4141414141414141;
   chunk[3] = 0x4141414141414141;
   free(chunk);
   chunk = malloc(0x20);
   printf(chunk);
}
```
