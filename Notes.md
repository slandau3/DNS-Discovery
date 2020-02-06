### Strange Behavior

```
dig +short test.openresolver.com A @103.39.215.238
``` 
does not return a response (no open resolver detected). However, when we try 
```
dig +short txt @103.39.215.238 google.com
``` 
we do get a response. If I'm interpreting this correctly it means that there is a resolver at `103.39.215.238` but that resolver is unable to resolve `test.openresolver.com` for some reason.


After further digging. I discovered that this resolver does not return when given 'bing.com' or several other domains. Upon investigation I discovered that this IP originates from China. Thus, it will not resolved banned sites thanks to the great firewall of China. Nevertheless, there is definitely a resolver at this domain. It would appear the ip range 103.39.215.255 is owned by _China Telecom (Group)_

