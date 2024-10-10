# Format string vulnerability - Part 2

In the [previous part](format_string.md), we saw the basics of writing with the `%n` format. In this part, I'll explain how to use these simple basics to exploit this vulnerability.

### The Basic principle

The main idea to exploit format string vulnerability is to write into memory e.g. EIP or RIP backup on the stack, a variable ...etc.

To do so, we need to know :\
1- The address or the addresses we want write to\
2- How reach the these addresses with `%n`\
3- Values we want to write on these address



## Writing into memory

Often times, we need to push into the stack the addresses we want write to, since it's not granted that they are already on the stack.\
So depending on the functions the code implements, for example, we can write into memory with `scanf`, `sprintf` or `snprintf`.\

TO DO... Endianess + gdb

## Reaching the addresses

TO DO... %x$n ... and the stack

## The values to write
