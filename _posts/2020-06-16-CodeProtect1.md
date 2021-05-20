---
layout: post
title:  "Secure a code part 1"
date:   2020-06-16 00:00:00 +0000
categories: SecDev
---

Programs (especially commercial) have some sort techniques of protection against unauthorized modification or reversing engineering. We have two categories: data-based obfuscation and control-based obfuscation. In real life the two combine in complex ways are used. We can simply change something like:

{% highlight c %}
JMP some_address
    ...

some_address:
    ...
{% endhighlight %}

in somethimg like that:

{% highlight c %}
help address:
    ADD [ESP], 9
    RET

start:
    CALL help_address
    ...
some_address:
    ...
{% endhighlight %}

We have obfuscation techniques like:
* pattern-based obfuscation,
* constant unfolding,
* junk code insertion,
* stack-based obfuscation,
* uncommon instructions,
* operating system-based control indirection.

For languages like JavaScript we have a source code transformation. With which we can use tools like [obfuscator.io](https://obfuscator.io/). For example, before:

{% highlight javascript %}
function multiply(a, b) {
    var aNumRows = a.length, aNumCols = a[0].length,
        bNumRows = b.length, bNumCols = b[0].length,
        m = new Array(aNumRows);  // initialize array of rows
    for (var r = 0; r < aNumRows; ++r) {
        m[r] = new Array(bNumCols); // initialize the current row
        for (var c = 0; c < bNumCols; ++c) {
        m[r][c] = 0;             // initialize the current cell
        for (var i = 0; i < aNumCols; ++i) {
            m[r][c] += a[r][i] * b[i][c];
        }
        }
    }
    return m;
    }
    
    function display(m) {
    for (var r = 0; r < m.length; ++r) {
        document.write('&nbsp;&nbsp;'+m[r].join(' ')+'&lt;br />');
    }
    }
    
    var a = [[8, 3], [2, 4], [3, 6]],
        b = [[1, 2, 3], [4, 6, 8]];
    document.write('matrix a:&lt;br />');
    display(a);
    document.write('matrix b:&lt;br />');
    display(b);
    document.write('a * b =&lt;br />');
    display(multiply(a, b));
{% endhighlight %}

after:

{% highlight javascript %}
var _0x5c3f=['matrix\x20a:<br\x20/>','length','a\x20*\x20b\x20=<br\x20/>','&nbsp;&nbsp;','<br\x20/>','join','write','matrix\x20b:<br\x20/>'];(function(_0x1f8ad1,_0x5c3fdb)
{var _0xf3ae59=function(_0x26238c){while(--_0x26238c){_0x1f8ad1['push'](_0x1f8ad1['shift']());}};_0xf3ae59(++_0x5c3fdb);}(_0x5c3f,0xe8));var _0xf3ae=function(_0x1f8ad1,_0x5c3fdb)
{_0x1f8ad1=_0x1f8ad1-0x0;var _0xf3ae59=_0x5c3f[_0x1f8ad1];return _0xf3ae59;};
function multiply(_0xa9ce96,_0x5918d6){var _0x2fdaa3=_0xa9ce96[_0xf3ae('0x1')],_0x129418=_0xa9ce96[0x0]['length'],_0x39c95f=_0x5918d6[_0xf3ae('0x1')],_0x1aa717=_0x5918d6[0x0]
[_0xf3ae('0x1')],_0x362cff=new Array(_0x2fdaa3);for(var _0x376dd3=0x0;_0x376dd3<_0x2fdaa3;++_0x376dd3){_0x362cff[_0x376dd3]=new Array(_0x1aa717);for(var _0x2d1d1d=0x0;
_0x2d1d1d<_0x1aa717;++_0x2d1d1d){_0x362cff[_0x376dd3][_0x2d1d1d]=0x0;for(var _0x4480d4=0x0;_0x4480d4<_0x129418;++_0x4480d4){_0x362cff[_0x376dd3][_0x2d1d1d]+=_0xa9ce96[_0x376dd3]
[_0x4480d4]*_0x5918d6[_0x4480d4][_0x2d1d1d];}}}return _0x362cff;}function display(_0x4e881d){for(var _0x5979ac=0x0;_0x5979ac<_0x4e881d[_0xf3ae('0x1')];++_0x5979ac){document['write']
(_0xf3ae('0x3')+_0x4e881d[_0x5979ac][_0xf3ae('0x5')]('\x20')+_0xf3ae('0x4'));}}var a=[[0x8,0x3],[0x2,0x4],[0x3,0x6]],b=[[0x1,0x2,0x3],[0x4,0x6,0x8]];
document['write'](_0xf3ae('0x0'));display(a);document[_0xf3ae('0x6')](_0xf3ae('0x7'));display(b);document[_0xf3ae('0x6')](_0xf3ae('0x2'));display(multiply(a,b));
{% endhighlight %}

We also have a code obfuscation based on virtual machines. A virtual machine simulates a CPU along with a few other hardware components, allowing it to perform arithmetic, read and write to memory and interact with I/O devices. It can understand a machine language which you can use to program it. Virtual machines used in code obfuscation are completely different than common virtual machnines. They are very specific to the task of executing a few set of instructions. Each instruction is given a custom opcode (often generated randomly). For example, of a protection project [VMPROTECT](https://github.com/eaglx/VMPROTECT). A VM protection is complex transformation.

o protect servers like verification servers, we can use something called Domain Generation Algorithm. Algorithms for generating domains are used in botnets to hide connections to Command and Control servers, as well as to prevent the takeover of the infrastructure of a given botnet. Their main goal is to create a large number of domain names, which usually look like pseudo-random strings, e.g. pkjdgjwzcr.com. Only some of the generated domains are registered by the botmaster, but infected machines send DNS queries for all of them. Example DGA in python ([source](https://en.wikipedia.org/wiki/Domain_generation_algorithm)):


{% highlight python %}
def generate_domain(year: int, month: int, day: int) -> str:
"""Generate a domain name for the given date."""
domain = ""

for i in range(16):
    year = ((year ^ 8 * year) >> 11) ^ ((year & 0xFFFFFFF0) << 17)
    month = ((month ^ 4 * month) >> 25) ^ 16 * (month & 0xFFFFFFF8)
    day = ((day ^ (day << 13)) >> 19) ^ ((day & 0xFFFFFFFE) << 12)
    domain += chr(((year ^ month ^ day) % 25) + 97)

return domain + ".com"
{% endhighlight %}