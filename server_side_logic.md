## Tars服务器端逻辑

作为一个多线程网络应用，一般会抽象出网络线程类，监听器类，客户端连接类，客户端连接列表类。<br/>

对于网络监听，存在accept新客户端连接和监听客户端读写事件，有的实现会把这两个操作拆成两种<br/>
线程，即一种线程负责accept新客户端连接，另外一种负责监听客户端读写时间。但无论是那一种实<br/>
现，都要考虑，当accept到一个新客户端连接套接字后，都需要将此套接字封装到一个客户端连接类，<br/>
该客户端连接封装类至少要记录套接字sockfd和归属于那个监听器。然后保存到客户端连接列表中。<br/>
当accept一个新的客户端连接后，接下来的读写事件，逻辑处理都是在网络线程驱动，比如也会涉及<br/>
对客户端连接列表的操作，这导致了，客户端连接列表变成了临界区资源，处理不好也增加线程锁以<br/>
保证线程安全。不过，可以不在accept线程构建新客户端连接实例，而是通过事件通知网络线程，由<br/>
网络线程来构建新客户端连接。这样，新客户端连接的构建和操作都是在网络线程完成。但这样依旧<br/>
还存在客户端连接列表在多个网络线程的共享的问题，当然，也可以每个线程各自维护独立的客户端<br/>
连接列表，这样就可以保证，客户端连接和客户端连接列表只在一个网络线程进行操作，这样也就<br/>
避免多线程互斥带来的额外开销，也能达到线程安全的目的。<br/>

对于客户端连接列表，需要考虑采用何种数据结构进行存储客户端连接，用以对客户端连接列表读写<br/>
达到较优的性能，链表，哈希表，树，数组，还是别的数据结构。我们知道，对一个客户端连接的连接来说，<br/>
写操作主要存在accept和close新连接时存在，其他大多数是读操作居多。链表在插入会比较快，但查找<br/>
极端情况需要遍历整个链表，显然很不理想。而哈希表，虽然可以进一步降低遍历的深度，但哈希可能存在<br/>
分布极端不均匀的情况，退变成链表。而树则需要解决树的平衡，以降低树的深度。无论何种，仍旧存在极端<br/>
情况，一旦退变，其性能急剧下降。而我们知道，对数组的访问，直接通过下标索引即可访问得到，性能无疑<br/>
是最优的，缺点就是需要一次性开辟连续内存，如果考虑动态数组，会存在扩容时数据的大量拷贝。数组性能虽<br/>
但仍需解决一个问题，新客户端连接如何插入，遍历吗？如果是这样，性能又会急剧下降。其实，可以额外使用<br/>
一个列表来保存可用的数组索引下标，当新连接来临时，从新连接列表中pop出一个数组索引下标，通过索引下标，<br/>
即可直接寻址。

对于客户端连接，上面提到至少要记录套接字sockfd和归属于那个监听器，在讨论客户端连接列表后，还需额外记录<br/>
数组索引下标，最好还记录下是哪个网络线程。

当一个客户端请求过来后，网络线程负责接收数据后，由谁继续处理该请求。一种是同步方案，直接在网络线程解析数据，<br/>
调用业务接口处理请求，业务接口返回响应数据，然后在网络线程响应客户端。另外一种是异步方案，网络接收完数据后，<br/>
网络线程不直接处理，然后放到异步请求消息对列中，然后通知异步处理线程。异步处理线程则从队列中取出请求消息，<br/>
分发，调用业务接口处理，业务接口返回响应数据，然后放到异步响应消息队列中。直接发送，或者由于网络线程写事件<br/>
触发后处理。

网络线程接收到数据后，其实至少要做的事情，是根据通信协议校验是否满足一个数据包的长度要求，数据包格式要求和<br/>
其他协议要求。在实现上，网络线程负责接收网络数据，通过调用应用侧设置的协议回调函数，校验是否法满足协议要求，<br/>
和返回过滤后的数据。而在业务接口返回的响应数据则是已经满足协议要求的数据，不需要进一步序列化。

对于异步请求消息队列，需要考虑采用多少个队列。一种是只有一个异步请求队列，这就涉及到多个网络线程和多个异步处理<br/>
线程并发访问的问题，因此需要进行线程互斥，会带来一点性能损失。另外一个是网络线程数量和异步处理线程数量保持一致<br/>
这样，每个网络线程对应一个唯一的异步处理线程，每个线程对采用一个异步请求消息队列，这样能降低并发访问带来的损耗。<br/>这种方案相对第一种而言，业务接口发生长耗时的情况时，消息队列更容易发生堆积。当然，还可以采用1对多的实现，<br/>即一个网络线程对应多个异步处理线程，不过要注意控制线程数量。

对于异步响应队列，需要考虑采用多少个队列。一种只有一个异步响应队列，即对应的客户端连接维护一个队列。另外一种，<br/>
维护多个队列，每个网络对应一个异步响应队列，根据对应的客户端连接找到对应的网络线程的队列。

要做到从请求消息中找到对应的客户端连接，因此还需要抽象一个请求消息类，至少包括请求消息数据和对应的客户端连接。

上面讨论那种多，只是抛出了能考虑到的多种实现方案，用以引导思考，毕竟带着这些问题去研究，<br/>
印象才会更加深刻。接下来，一一研究，看看Tars服务端代码内部是如何实现的。

对于一些服务端的数据结构是在和时初始化的，可以**参考：[Tars应用启动流程](application_startup.md)**，<br/>

对于内部的一些其他数据结构的初始化，下面也会一一研究。<br/>




