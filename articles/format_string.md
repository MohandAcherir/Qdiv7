# Format string vulnerability explained

In this article, i'll try to explain as clearly as possible the format string vulnerability, especially writing with ```%n/```.\
I've read many articles on this topic, and almost all of them can be very confusing; that's why
i've decided to write this article in order to clarify this for good.


### First things first

Just like the for the formats ```%x```, ```%s```, ```%p```, ```%d``` ...etc which are used to print a variable, for example :\
```printf("%x", some_variable);``` which prints the value of ```some_variable``` in hexadecimal, if we do :\
```printf("%n", &some_variable);``` - and here's most important thing to understand in this article - the value of ```some_variable```\
will contain the number of characters before ```%n``` in the first argument of ```printf```; in this case, there's 0 characters before ```%n```\
so ```some_variable``` has the value 0.\
So, to put it simply, the format ```%n``` is used to count the number of characters printed prior to ```%n```.

**Here are other examples:**


```printf("Hello%nAA", &some_variable);```. In this case, the first argument to ```printf``` is "Hello%nAA", thus\
```some_variable``` has the value 4, because "Hello" is before ```%n``` and has length 4. ("AA" is after ```%n``` in the string, so it does not count).


```printf("HelloAA%n", &some_variable);```. In this case, the first argument to ```printf``` is "HelloAA%n", thus\
```some_variable``` has the value 6, because "HelloAA" is before ```%n``` and has length 4.

And here's another interesting one slightly different:

```printf("Hello%nAA%n", &some_variable1, &some_variable2);```. Just by following the definition, the first argument to ```printf``` is "Hello%nAA%n", thus\
the first ```%n``` will contain 4(the length of "Hello"), and the second ```%n``` will contain all which is before it, namely "HelloAA", thus 6.\
So ```some_variable1``` has the value 4 and ```some_variable2``` has the value 6.


With all this in mind, the rest of the exploitation is fairly simple.

