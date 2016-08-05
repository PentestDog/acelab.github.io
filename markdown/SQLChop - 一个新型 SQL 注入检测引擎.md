

## 引言

在 8 月 5 日的 Blackhat 大会上，我们在 Arsenal 分会场做了 SQLChop 的展示，同步上线的还有 SQLChop 的网站 http://sqlchop.chaitin.com/ ，以及在 Github 放出了 SQLChop 二进制模块的下载试用 https://github.com/chaitin/sqlchop ，API 使用文档在 http://sqlchop.chaitin.com/doc.html 。

## SQLChop 是什么?

SQLChop 是一个基于**词法分析和语法分析**的 SQL 注入检测引擎，它工作在 HTTP 应用层，在对后台应用一无所知的情况下，单纯从用户输入中进行**递归解码**，检测可能存在的 SQL 注入。

使用词法和语法分析去处理 SQL 注入的好处是显而易见的，其最大好处是无规则，再也不用写千变万化的规则（每次都还有写错扣奖金的风险），也天生就获得一定的 SQL 注入 0day 防御能力。

在我们通过正规途径收集到的互联网真实流量中整理出的数据集上，SQLChop 准确率和召回率都可以轻松达到 99% 以上，也就是小于 1% 误报率和漏报率。这相比现有的工作在相同情况下基于规则的 WAF，modsecurity 等，防护效果提升了一个台阶（仅仅对比其中 SQL 注入检测的部分，其他攻击类型不考虑。对于其他不同类型，如根据网络流量自学习的，需要了解后台应用数据的检测工具由于基本假设不同，不能直接对比）。

这里强调几个大家比较关注的问题：

 - SQLChop 是一个通用 SQL 注入检测引擎，不需要对后台应用有所了解，因此无法与一些了解后台信息的专用防护过滤产品直接比较检测能力。工作在数据库前端和编程语言框架层的防护产品，可以获取完整的 SQL 语句，从而有能力获得比通用防护产品更高的准确率和召回率。但是，专用防护产品需要介入到开发或具体部署环节中，在易用性方面不如通用防护产品。
 - 任何一个 SQL 防护产品，只有同时考虑准确率和召回率才是有意义的，单方面做到 99.9999999% 都不难，难的是两个方面同时做到一个比较高的水平。这样的结果才是有意义的。实际上 SQLChop 最终输出结果是一个由打分模型评估出来的分值，用户可以自行调节最终阈值参数，调高就会让准确率变高、召回率下降，调低就反之使得准确率下降召回率上升，二者本身就有一定矛盾对立，需要根据场景进行不同的参数设定。
 - 非常感谢大家对 SQLChop 的关注与支持，也有朋友提出了很多有价值的建议。我们将在原有基础上不断地改进，进一步提升 SQLChop 的检测能力。而对于SQLChop在漏报误报情况方面的疑问，我们认为 SQLChop 在 SQL 注入方面的检测防护效果已经达到了一个比较好的水平。这个信心源自于两个方面：
   1. 我们有来自于真实数据的测试集和横向对比，测试结果明显优于传统基于规则的 WAF。我们并没有说 SQLChop 的准确率已经达到了 100%，只是强调新方法达到了远好于传统方法的水平。
   1. SQLChop 部署了多次的真实防护测试，获取了大量实战注入数据。在某厂商众测活动中，只有部署了 SQLChop 的分站（这个分站之前满是SQL注入漏洞）没有被成功注入。

 我们已经放出了 SQLChop 的二进制模块，欢迎大家下载测试。

## SQLChop 如何工作？

这里将尝试用偏技术化的词汇描述一下 SQLChop 的工作原理。SQLChop 可以分为四大模块，分别是：

 1. 递归解码模块
 1. 词法分析模块
 1. 语法分析模块
 1. 综合打分模块

### 递归解码模块

递归解码是一个原理简单但是实现繁杂的模块。所处理的输入是用户的 HTTP 流量。所谓递归解码，是将输入的各种可能编码，例如 urlencode, json, phpserialize, base64 等，全部解码，一直解码到最终应用程序所接受的输入为止，我们称之为 payload。当然一个输入可能会解出来很多 payload，这些 payload 都需要进入后面的模块进行处理。

### 词法分析模块

词法分析所接受的输入是 payload。对于一个 payload，它既有可能是一个正常的用户名、密码、数字等，也有可能是一个 SQL 注入，词法分析模块的作用就是，假设它是一个 SQL 注入，按照 SQL 的词法规则对这个 payload 进行词法分析。

举一个具体的例子来说明词法分析的作用。

```sql
select 1 from users where password = 'admin'
```

对它进行词法分析的结果就是:

```
<keyword select> <type number> <keyword from> <type bareword> <keyword where> <type bareword> <operator => <type string>
```

再比如，以下的注入片断

```
xxxx' or '1'='1
```

正确的词法分析应当是 

```
<type string> <keyword or> <type string> <operator => <type string>
```

但是显而易见，最开始的 `<type string>` 是不完整的，缺少前面一个单引号。如果按照普通的处理顺序从第一个字母开始处理，那么就会处理成如下错误的结果：

```
<type bareword> <type string> <type number> <type string> <type number>
```

因此，这里一个挑战就是如何消除歧义。这个算法并不难，大家可以自己思考。

词法分析的部分有一些开源代码可供参考，[libinjection](https://github.com/client9/libinjection/) 就是一个不错的例子。

### 语法分析模块

语法分析模块是 SQLChop 的核心。它的作用是在词法分析的基础上，分析 payload 的语法是否符合 SQL 语法规则。

语法分析听起来简单，但是做起来其实有不小的难度。这里就不考虑 SQL 语法有 MYSQL, MS SQL Server, Oracle SQL, Sybase, DB2, PostgreSQL, SQLite, Informix 这么多变种的事实，也不考虑各家的实现天差地别，各有各的扩展、变化、甚至还存在有 http://bugs.mysql.com/bug.php?id=55477 这种让人欲哭无泪的 bug 了。

首先第一个问题，由于不知道后台应用的情况，得到的 payload 只是 SQL 的一个片断，如何分析一个片断是否符合 SQL 语法规则？

在网上的分析看到有人说可以假设 payload 的前面是 `Select * from table where id = `，然后与 payload 进行拼接处理，这显然是不可接受的，与实际相比相差太远。

由于我们的目标是能够判断一个 payload 是否是一条合法 SQL 语句的片断，显然我们也不可能去使用 MySQL 等开源代码的语法分析，那么究竟是否存在这样的算法呢？

让我们先把问题简化。我们知道在 [Chomsky 文法体系](https://en.wikipedia.org/wiki/Chomsky_hierarchy) 里面，SQL 属于 [Context Free Grammer](https://en.wikipedia.org/wiki/Context-free_grammar)，我们可以使用一个简化的 CFG 层面的问题来代替处理。

我们规定一个如下规则的四则运算的子集：

 1. 数字只能是 0-9，仅允许个位数
 1. 只包含 + 和 * 两种运算
 1. 括号只包含左右小括号: ()
 1. 优先级是 () 最大，* 次之，+ 最低

显而易见，这个四则运算集合的语言也是属于 CFG 层的（其实应该称之为二则运算了），正则表达式与对应的[正则语言](https://en.wikipedia.org/wiki/Regular_language)无法表达括号匹配。

那么问题简化为，在这个简化的四则运算子集中，判断一个字符串是否是合法四则运算的子串。

显而易见，以下几个是合法的： `1+1` `3*5+2)` `1+5*1)+(`

下面几个是非法的: `3*5+)2` `3++2` `3+2*(*`

我们先将复杂度等考虑都置之度外，先想办法实现一个最简单的非多项式算法。这其实不难，懂一点编译器原理的同学都可以很快写出，只需要遍历规则尝试 reduce 即可。如果有兴趣做类似研究的同学可以尝试自己实现一个。我们这里直接给出一个参考递归实现：https://gist.github.com/zTrix/3d3266673d3ff84a302d (作者是 [fqj1994](https://fqj.me/))

```bash
 $ python2 validate_arithmetic.py '3*5+2)'                │  $ python2 validate_arithmetic.py '1+5*1)+('
3*5+2) is valid, it can be reduced to E                   │  1+5*1)+( is valid, it can be reduced to E
        3*5+2)  (0, 0) N => 3                             │         1+5*1)+(        (0, 0) N => 1
        N*5+2)  (0, 0) P => N                             │         N+5*1)+(        (0, 0) P => N
        P*5+2)  (0, 0) M => M*P                           │         P+5*1)+(        (0, 0) M => M*P
        M*5+2)  (2, 2) N => 5                             │         M+5*1)+(        (0, 0) A => A+M
        M*N+2)  (2, 2) P => N                             │         A+5*1)+(        (2, 2) N => 5
        M*P+2)  (0, 2) M => M*P                           │         A+N*1)+(        (2, 2) P => N
        M+2)    (0, 0) A => A+M                           │         A+P*1)+(        (2, 2) M => P
        A+2)    (2, 2) N => 2                             │         A+M*1)+(        (4, 4) N => 1
        A+N)    (2, 2) P => N                             │         A+M*N)+(        (4, 4) P => N
        A+P)    (2, 2) M => P                             │         A+M*P)+(        (2, 4) M => M*P
        A+M)    (0, 2) A => A+M                           │         A+M)+(  (0, 2) A => A+M
        A)      (0, 0) E => A                             │         A)+(    (0, 0) E => A
        E)      (0, 1) P => (E)                           │         E)+(    (0, 1) P => (E)
        P       (0, 0) M => M*P                           │         P+(     (0, 0) M => M*P
        M       (0, 0) A => A+M                           │         M+(     (0, 0) A => A+M
        A       (0, 0) E => A                             │         A+(     (2, 2) P => (E)
        E                                                 │         A+P     (2, 2) M => P
                                                          │         A+M     (0, 2) A => A+M
                                                          │         A       (0, 0) E => A
                                                          │         E
                                                          │ 
```

```bash
$ python2 validate_arithmetic.py '3+2*(*'
3+2*(* is invalid, and cannot be reduced to E
```

```bash
$ python2 validate_arithmetic.py '3++2'
3++2 is invalid, and cannot be reduced to E
```

有了这个算法之后，剩下的事情就是两个方面了

 - 一是需要将整套算法在 SQL 层面实现一遍，上面的四则运算简化规则太过于简单，如果要在 SQL 上实现一遍的话，请记住以下几个血泪数字：1992 SQL 规范有 625 页文本, 2003 SQL Spec 是 128 页的 [BNF](https://en.wikipedia.org/wiki/Backus%E2%80%93Naur_Form)
 - 二是需要优化算法复杂度，要想尽一切办法把这个算法复杂度优化到 $O(N)$ 才能够实际使用，有人可能会说怎么可能呢，CFG 的 [LL parser](https://en.wikipedia.org/wiki/LL_parser) 和 [LR parser](https://en.wikipedia.org/wiki/LR_parser) 都是至少 $O(N^2)$ 复杂度了，上面给出的算法更是非多项式的。但是我们的确做到了，使用了一些比较猥琐的思路达到了很不错的效果，这需要比较多的编译原理知识才能阐述明白，此处不再赘述。

### 综合打分模块

经过前面三个模块之后，我们已经可以知道一个 payload 是否是 SQL 合法语句的一个片断。但是这还不能完全确定它是不是一个 SQL 注入。

这个道理很简单，数字 1 就是 SQL 语句的合法片断，任何 bareword 比如 username 都是 SQL 的合法片断，但是不能简单粗暴判定它们就是 SQL 注入。因此我们还需要最后的打分系统，给一个 payload 综合打分。

这里的方法和实现就太多了，仁者见仁，智者见智，这里不再多说。

## 总结

本文讨论了使用词法分析和语法分析来进行 SQL 注入检测的诸多实现细节和挑战。

我们在测试数据集和公开测试中都验证了这种方法远好于传统基于规则的方法。

SQLChop 目前来说还只是一个研究型技术引擎，算不上任何产品。商业产品需要更好的包装、简洁优雅的界面和普及大众的宣传，而技术研究则带来这些商业产品内部技术的核心。SQLChop 的目标是将 SQL 注入检测技术核心向前推动一步，也许仅仅是一小步，也达到了它的价值。我们希望未来将 SQLChop 整合进商业产品中，发挥它的作用。

## 相关网站和报道

 - http://sqlchop.chaitin.com/
 - http://sqlchop.chaitin.com/demo
 - http://netsecurity.51cto.com/art/201508/487706.htm
 - http://www.people.com.cn/n/2015/0814/c347407-27464986.html?from=timeline&isappinstalled=0

## 一点花絮

基于新思路的 XSS 检测工具 XSSChop 我们也在做，大家敬请期待！
