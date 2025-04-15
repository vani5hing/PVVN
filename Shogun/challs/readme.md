# Challs

These are some mock CTF Challenges. Here, we will actually see various heap bugs, and how we can use them in order to get code execution. The goal of these challenges is to either call a function that says something like `"You Win"`, or get a shell.

Here are the solutions for the various challs:
- [00](00/solution.md) (basic UAF, sau khi solve chall này mình nhận ra CTFNote của JHT trol, tcache không delete toàn bộ data, mà chỉ delete key).
- [01](01/solution.md) (basic heap overflow, nhưng guyintuxedo abuse để make overlap chunk, cái này sẽ hiệu quả hơn nhiều).
- [02](02/solution.md) (guyintuxedo dùng bug out of bound để attack `tcache_per_thread struct`, cái này sẽ hiệu quả hơn nhiều).
- [03](03/solution.md) (basic DBF, bài này mình debug some bins behaviour).
- [04](04/solution.md) (create a fake chunk, nhưng mình làm cách đặc biệt hơn xíu (abuse các chunk có sẵn)).
- [05](05/solution.md)
