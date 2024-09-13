# Format string vulnerability explained

In this article, i'll try to explain as clearly as possible the format string vulnerability, especially writing with ```%n/```.\
I've read many articles on this topic, and almost all of them can be very confusing; that's why\
i've decided to write this article in order to clarify this for good.


### First things first

Just like the for the formats ```%x```, ```%s```, ```%p```, ```%d``` ...etc which are used to print a variable\
for example :\

```printf("%x", some_variable);``` which prints the value of ```some_variable``` in hexadecimal, if we do :\
```printf("%n", &some_variable);``` - and here's most important thing to understand in this article - the value of ```some_variable```\
will contain the number of characters before ```%n``` in the first argument of ```printf```; \

in this case, there's 0 characters before ```%n```\
so ```some_variable``` has the value 0.\
To put it simply, the format ```%n``` is used to count the number of characters printed prior to ```%n```.



**Here are other examples:**


```printf("Hello%nAA", &some_variable);```: in this case, the first argument to ```printf``` is "Hello%nAA", thus\
```some_variable``` has the value 4, because "Hello" is before ```%n``` and has length 4. ("AA" is after ```%n``` in the string, so it does not count).\


```printf("HelloAA%n", &some_variable);```. In this case, the first argument to ```printf``` is "HelloAA%n", thus\
```some_variable``` has the value 6, because "HelloAA" is before ```%n``` and has length 6.\

And here's another interesting one slightly different:

```printf("Hello%nAA%n", &some_variable1, &some_variable2);```.
Just by following the definition, the first argument to ```printf``` is "Hello%nAA%n", thus
the first ```%n``` will contain 4(the length of "Hello"), and the second ```%n``` will contain all\
which is before it, namely "HelloAA", thus 6.\
So ```some_variable1``` has the value 4 and ```some_variable2``` has the value 6.


With all this in mind, the rest of the exploitation is fairly simple.

### Variants of `%n` in C

In C, the format specifiers `%n` and its variants are used with the `printf` family of functions to store the number of characters printed so far into the provided argument. Below is a list of commonly used variants:

1. **`%n`**:  
   Stores the number of characters printed so far as an `int` into the argument.

2. **`%hn`**:  
   Stores the number of characters printed so far as a `short int` (typically a 16-bit integer) into the argument.

3. **`%hhn`**:  
   Stores the number of characters printed so far as a `signed char` (typically an 8-bit integer) into the argument.

4. **`%ln`**:  
   Stores the number of characters printed so far as a `long int` (typically a 32-bit or 64-bit integer, depending on the platform) into the argument.

5. **`%lln`**:  
   Stores the number of characters printed so far as a `long long int` (typically a 64-bit integer) into the argument.

6. **`%zn`**:  
   Stores the number of characters printed so far as a `size_t`, which is an unsigned integer type used to represent sizes. The actual size of `size_t` depends on the platform (usually 32-bit or 64-bit).

7. **`%tn`**:  
   Stores the number of characters printed so far as a `ptrdiff_t`, which is an integer type capable of holding the difference between two pointers.
