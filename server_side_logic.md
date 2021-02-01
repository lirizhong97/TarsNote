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

<br/>


EpollServer主要负责网络线程的管理，服务监听器BindAdapter的管理

先看下EpollServer声明的一些接口和成员变量

```
class TC_EpollServer
{
    //初始化EpollServer实例，创建必要的数据结构，如网络线程，但这会不启动线程
    TC_EpollServer(unsigned int iNetThreadNum = 1)；

    //空连接检测开关，主要用于防止空连接攻击。可通过配置文件设置两个参数，
    //Tars框架内部在应用启动时，会调用这两个函数设置
    void enAntiEmptyConnAttack(bool bEnable);
    //设置判断空连接的超时时间
    void setEmptyConnTimeout(int timeout);

    //设置本地循环日志，Tars框架内部在应用启动时，会创建日志实例，并设置进EpollServer
    void setLocalLogger(RollWrapperInterface *pLocalLogger)；

    //路由到网络线程，根据套接字路由
    NetThread* getNetThreadOfFd(int fd) 

    //设置是否合并网络线程和异步处理业务线程
    void setMergeHandleNetThread(bool merge)

    //创将监听器BindAdapter套接字，绑定端口和监听。Tars框架内部在应用启动时，会根据配置文件配置的Adapter
    //信息，创建对应BindAdapter监听器实例，然后主动调用该函数完成监听器的初始化工作。
    int bind(BindAdapterPtr &lsPtr);

    //启动服务，开始对外提供服务。这里会启动网络线程，异步处理业务线程，并阻塞在该线程，
    //主要执行调时属性上报，异步手动监听和等待终止通知等。
    void waitForShutdown();

    //停止服务，包括停止网络线程，异步处理业务线程和主线程(即调用waitForShutdown的线程)
    void terminate();

    //根据Adapter监听器名称获取对应的服务监听器
    BindAdapterPtr getBindAdapter(const string &sName);

    //accept新的客户端连接后，将客户端连接保存到网络线程
    void addConnection(Connection * cPtr, int fd, CONN_TYPE iType);

    //关闭连接。RecvContext包括了当前客户端连接的信息，通过该信息，
    //EpollServer可路由到对应的网络线程，将关闭连接操作转线程到网络线程处理
    void close(const shared_ptr<TC_EpollServer::RecvContext> &data);

    //发送数据，主要用于异步响应数据。SendContext包括了当前客户端连接的信息，通过该信息，
    //EpollServer可路由到对应的网络线程，将数据的发送操作转线程到网络线程处理
    void send(const shared_ptr<SendContext> &data);

    //获取指定服务监听器的所有客户端连接状态信息列表
    vector<ConnStatus> getConnStatus(int lfd);

    //获取所有的服务监听器列表
    unordered_map<int, BindAdapterPtr> getListenSocketInfo();
    vector<BindAdapterPtr> getBindAdapters();

    //获取当前所有的客户端连接数量，网络线程会维护一个本线程accept的客户端连接列表
    size_t getConnectionCount();

    //停止异步处理业务线程，业务线程保存在BindAdapter服务器监听器中
    //因此EpollServer维护了所有的服务监听器，即_bindAdapters
    void stopThread()；

    //设置accept新客户端连接回调函数，应用侧可通过Application类提供的接口注册
    void setOnAccept(const accept_callback_functor& f)；

    //设置应用回调函数，Tars框架在应用启动时注册该回调函数，主要用于属性上报
    void setCallbackFunctor(const application_callback_functor &hf)；

    //设置服务心跳回调函数，Tars框架在应用启动时注册该回调函数，主要给tarsnode上报存活心跳
    void setHeartBeatFunctor(const heartbeat_callback_functor& heartFunc)；

private:
    //网络线程组
    std::vector<NetThread*> _netThreads;

    //网络线程数量
    int _netThreadNum;

    //epoll操作封装类
	TC_Epoller _epoller;

    //用于发送通知，主要用于通知主线程，即调用waitForShutdown的线程
	TC_Epoller::NotifyInfo _notify;

    //用来标识应用终止，用以通知网络线程和异步处理业务线程退出
    bool _bTerminate;

    //用来标识异步处理业务线程是否已经启动，会在waitForShutdown接口中启动异步处理业务线程
    bool _handleStarted;

	//是否合并网络线程和请求异步处理业务线程，如果合并，则异步处理线程类不会run，仅仅当作一个普通逻辑处理类来调用
	bool _mergeHandleNetThread = false;

    //本地循环日志，Tars框架内部会在Application类中应用启动时实例化一个日志实例，并设置到EpollServer
    RollWrapperInterface *_pLocalLogger;

    //服务监听器，即创建socket，bind绑定端口和listen监听，其内部还会维护必要的数据结构，
    //如客户端连接列表，异步线程组和异步处理请求的消息队列等。
	vector<BindAdapterPtr> _bindAdapters;
	unordered_map<int, BindAdapterPtr> _listeners;

	//应用回调函数，Tars框架内部会在Application类中应用启动时注册该回调函数，用于业务属性上报
	application_callback_functor _hf;

    //心跳回调函数，Tars框架内部会在Application类中应用启动时注册该回调函数
    heartbeat_callback_functor _heartFunc;

    //accept新客户端连接后的回调函数，当accept新的客户端连接后，框架会回调该函数。
    //应用如果需要保存新连接信息，应用侧可通过Application提供的接口设置该回调函数
    accept_callback_functor _acceptFunc;
};
```

Tars框架在应用启动时，会实例化一个EpollServer，这会做了那些初始化工作。

```
TC_EpollServer::TC_EpollServer(unsigned int iNetThreadNum)
: _netThreadNum(iNetThreadNum)
, _bTerminate(false)
, _handleStarted(false)
, _pLocalLogger(NULL)
, _acceptFunc(NULL)
{
    if(_netThreadNum < 1)
    {
        _netThreadNum = 1;
    }

    //网络线程的配置数目不能15个
    if(_netThreadNum > 15)
    {
        _netThreadNum = 15;
    }

    //该epoll封装类实例，主要用于在主线程(调用waitForShutdown的线程)accept新的客户端连接和定时回调应用回调
    _epoller.create(10240);

    //主要用于通知主线程消息
    _notify.init(&_epoller);
    _notify.add(_notify.notifyFd());

    //创将网络线程，但不启动。后续研究网络线程时，我们只要知道网络线程是在EpollServer构造实例时创建的
    for (size_t i = 0; i < _netThreadNum; ++i)
    {
        TC_EpollServer::NetThread* netThreads = new TC_EpollServer::NetThread(this, i);
        _netThreads.push_back(netThreads);
    }
}
```

上面提到了主线程，即调用waitForShutdown的线程，Tars框架在应用启动时会在Application类内调用。<br/>
此时的调用线程就是主线程。所以我们先看下waitForShutdown的逻辑。

```
void TC_EpollServer::waitForShutdown()
{
    //启动异步处理业务线程。之前提到，Tars框架在应用启动时会根据配置文件的Adapter监听器的配置，
    //实例化相应的BindAdapter监听器实例。也有提到了，每个BindAdapter监听器对应着一组的异步
    //处理业务线程组，在实例化监听器时就会创将多个异步处理业务线程，但不会启动线程。在此时才会启动。
    //知道这些背景后，暂时不会理会这些细节，后续会专门研究监听器。此处，只要知道会启动业务线程就够了。
    if(!isMergeHandleNetThread())
        startHandle();

    //之前提到，在EpollServer构造时，创将了一个epoll封装类实例，用于主线程accept新客户端连接
    //和超时定时处理。但还没有将每个BindAdapter监听器的套接字add到epoll实例。而每个网络线程也
    //需要有一个epoll实例，用以监听每个客户端连接的读写事件。所以，此处会做三件事情。
    //一是每个BindAdapter监听器的套接字add到主线程epoll实例
    //二是如果服务走的是udp协议，还会是实例化一个udp连接
    //三是初始化网络线程管理的客户端连接链表
    createEpoll();

    //启动网络线程，会进入线程routine run函数。这里只需要知道网络线程此时已经开始工作了。
    //即在主线程开始accept前启动网络线程。
    for (size_t i = 0; i < _netThreadNum; ++i)
    {
        _netThreads[i]->start();
    }

    //主线程的逻辑
    int64_t iLastCheckTime = TNOWMS;
    while (!_bTerminate)
    {
        //等待客户端新连接
        int iEvNum = _epoller.wait(300);
        if (_bTerminate)
            break;

        //定时回调应用回调，进行属性上报
        if(TNOWMS - iLastCheckTime > 1000) 
        {
            try { _hf(this); } catch(...) {}
            iLastCheckTime = TNOWMS;
        }

        for (int i = 0; i < iEvNum; ++i)
        {
            try
            {
                const epoll_event &ev = _epoller.get(i);
                uint32_t fd = TC_Epoller::getU32(ev, false);
                auto it = _listeners.find(fd);
                if (it != _listeners.end())
                {
                    //Tars提供了延迟监听的机制
                    if (TC_Epoller::writeEvent(ev))
                    {
                        TC_Socket s;
                        s.init(fd, false);
                        s.listen(1024);
                    }

                    //接收新客户端连接
                    if (TC_Epoller::readEvent(ev))
                    {
                        bool ret;
                        do {
                            ret = accept(fd, it->second->_ep.isIPv6() ? AF_INET6 : AF_INET);
                        } while (ret);
                    }
                }
            }
            catch (exception &ex)
            {
                error("run exception:" + string(ex.what()));
            }
            catch (...)
            {
                error("TC_EpollServer::waitForShutdown unknown error");
            }
        }
    }

    for (size_t i = 0; i < _netThreads.size(); ++i)
    {
        if (_netThreads[i]->isAlive())
        {
            _netThreads[i]->terminate();
            _netThreads[i]->getThreadControl().join();
        }
    }
    
}
```

- ***[Tars连接管理逻辑](server_manage_connection.md)***<br/>


启动异步处理业务线程

```
void TC_EpollServer::startHandle()
{
    if(!this->isMergeHandleNetThread())
    {
        if (!_handleStarted)
        {
            _handleStarted = true;
            for (auto & bindAdapter : _bindAdapters)
            {
                const vector<TC_EpollServer::HandlePtr> & hds = bindAdapter->getHandles();
                for (uint32_t i = 0; i < hds.size(); ++i) 
                {
                    if (!hds[i]->isAlive()) 
                    {
                        hds[i]->start();
                    }
                }
            }
        }
    }
}
```

***创建epoll实例***

```
void TC_EpollServer::createEpoll()
{
    uint32_t maxAllConn = 0;
    auto it = _listeners.begin();
    while (it != _listeners.end())
    {
        if (it->second->getEndpoint().isTcp())
        {
            //获取最大连接数
            maxAllConn += it->second->getMaxConns();
            _epoller.add(it->first, it->first, EPOLLIN);
        }
        else
        {
            maxAllConn++;
        }

        ++it;
    }

    if (maxAllConn >= (1 << 22))
    {
        maxAllConn = (1 << 22) - 1;
    }

    for (size_t i = 0; i < _netThreads.size(); ++i)
    {
        _netThreads[i]->createEpoll(maxAllConn);
    }

    //必须先等所有网络线程调用createEpoll()，初始化list后，才能调用initUdp()
    for (size_t i = 0; i < _netThreads.size(); ++i)
    {
        _netThreads[i]->initUdp(_listeners);
    }
}
````

探讨了主线程的逻辑，接下来要探讨网络线程，然后再探讨异步处理业务线程。毕竟线程都有一个入口函数，从入口函数来跟进逻辑处理是个不错的方法。


***网络线程的初始化***

```
TC_EpollServer::TC_EpollServer(unsigned int iNetThreadNum)
: _netThreadNum(iNetThreadNum)
{
    if(_netThreadNum < 1)
    {
        _netThreadNum = 1;
    }

    //网络线程的配置数目不能15个
    if(_netThreadNum > 15)
    {
        _netThreadNum = 15;
    }

    for (size_t i = 0; i < _netThreadNum; ++i)
    {
        //传入EpollServer和线程索引标识
        TC_EpollServer::NetThread* netThreads = new TC_EpollServer::NetThread(this, i);
        _netThreads.push_back(netThreads);
    }
}
```

网络线程是在构造EpollServer核心服务时创建的，但此时并没有启动线程。

```
class TC_EpollServer::NetThread
{
public:
    TC_EpollServer::NetThread::NetThread(TC_EpollServer *epollServer, int threadIndex)
    : _epollServer(epollServer)
    , _threadIndex(threadIndex)
    , _list(this)
    {
        _epoller.create(10240);
        _notify.init(&_epoller);
        _notify.add(_notify.notifyFd());
    }

private:
    //线程索引标识，范围0～网络线程数量-1
    int _threadIndex;

    //客户端连接链表
    ConnectionList _list;

    //网络引擎核心服务
    TC_EpollServer *_epollServer;
};

```

每个网络线程都分配了一个线程索引标识，标识从0开始，最大为网络线程数量-1。还构造了一个客户端连接链表。<br/>
此处



在EpollServer构造时就初始化网络线程。这里有个问题，为什么网络线程的配置数量强制不能超过15个？<br/>
这里一方面是基于性能考虑，另外也与客户端连接唯一标识的生成规则相关。

```
//
void TC_EpollServer::NetThread::createEpoll(uint32_t maxAllConn)
{
    //_threadIndex线程索引标识，范围0~网络线程数量-1
    list.init((uint32_t)maxAllConn, _threadIndex + 1);
}

_iConnectionMagic = ((((uint32_t)_lastTimeoutTime) << 26) & (0xFFFFFFFF << 26)) + ((iIndex << 22) & (0xFFFFFFFF << 22));

uint32_t TC_EpollServer::ConnectionList::getUniqId()
{
    TC_LockT<TC_ThreadMutex> lock(_mutex);
    uint32_t uid = _free.front();
    assert(uid > 0 && uid <= _total);
    _free.pop_front();
    --_free_size;
    return _iConnectionMagic | uid;
}
```


