# Code Path Overview

So this part is legit just going through the code path for both malloc and free. In addition to that, I made a brief diagram showing what I think are the major parts of both code paths, for what we care about. By doing this, we gain a much deeper understanding of the glibc heap, and know where we need to look for things like how certain checks work. This is the best order I think, for going through these:

> <mark>Mình suggest xem heap_demos trước khi deep dive vào cái này (mình đã làm ngược lại)</mark>.

- [free_diagram](free_diagram.md)
- [free](free.md) (70% done, this is dope, I dont understand the last part, I suggest look at diagram only) (This can be useful whenever meet error).  
- [malloc_diagram](malloc_diagram.md)
- [malloc](malloc.md) (70% done, this also dope, I dont understand the last part (except top chunk allocate), I suggest look at diagram only) (This can be useful whenever meet error).
