
***客户端连接管理的事件主要有如下几方面：***

1. 接收客户端连接
2. 关闭客户端连接
3. 读写客户端连接
4. 空连接超时处理

***在连接管理方面，Tars做了如下几点操作：***

1. 抽象了客户连接Connection类和客户端连接链表ConnectionList类
2. 在主线程接收和初始化新的客户端连接，并保存到网络线程管理的客户端连接链表
3. 在网络线程监听客户端连接的读写事件，并分发和处理
4. 在网络线程处理客户端连接的关闭事件，包括网络数据收发过程中的连接端开事件和应用主动关闭连接的事件
5. 字网络线程定时检测空连接，针对空连接，服务器端主动在网络线程关闭连接，避免空连接攻击

***首先先看下客户连接Connection类和客户端连接链表onnectionList类的定义：***

- Connection
```
class Connection
{
public:
    //连接类型
    enum EnumConnectionType
    {
        EM_TCP = 0,
        EM_UDP = 1,
    };

    //TCP连接
    Connection(BindAdapter *pBindAdapter, int lfd, int timeout, int fd, const string& ip, uint16_t port);

    //UDP连接
    Connection(BindAdapter *pBindAdapter, int fd);

    virtual ~Connection();

    //分配连接唯一标识和初始化
    void init(unsigned int uid)；

    //获取连接唯一标识
    uint32_t getId() const；

    //获取连接超时时间
    int getTimeout() const；

    //连接所属的服务监听器
    BindAdapterPtr& getBindAdapter()；

    //获取归属的服务监听器的套接字
    int getListenfd() const；

    //获取当前客户端连接的套接字
    int getfd() const；

    //当前客户端连接的套接字是否有效
    bool isValid() const

    //当前客户端连接的远程IP
    string getIp() const；

    //当前客户端连接的远程端口
    uint16_t getPort() const；

    //Tars支持针对新连接过滤首包数据，设置首个数据包包头需要过滤的字节数
    void setHeaderFilterLen(int iHeaderLen)；

    //设置需关闭状态，发送完当前数据就关闭连接
    bool setClose();

    //获取连接类型
    EnumConnectionType getType() const；

    //是否是空连接
    bool isEmptyConn() const;

    //初始化监权状态
    void tryInitAuthState(int initState);

    //获取接收数据buffer
    TC_NetWorkBuffer &getRecvBuffer()；

    //获取发送数据buffer
    TC_NetWorkBuffer &getSendBuffer() { return _sendBuffer; }

    //发送buffer中的数据
    int sendBuffer();

    //关闭连接
    void close();

protected:

    //添加发送buffer
    //return -1:发送出错, 0:无数据, 1:发送完毕, 2:还有数据
    int send(const shared_ptr<SendContext> &data);

    //读取数据
    //return int, -1:接收出错, 0:接收不全, 1:接收到一个完整包
    int recv();

    //接收TCP
    int recvTcp();

    //接收Udp
    int recvUdp();

    //解析协议，包括校验是否满包和协议格式
    int parseProtocol(TC_NetWorkBuffer &rbuf);

    //增加数据到队列中。每接收到一个满包的请求消息，则保存到请求消息异步处理队列
    void insertRecvQueue(const shared_ptr<RecvContext> &recv);

    //对于udp方式的连接，分配指定大小的接收缓冲区
    bool setRecvBuffer(size_t nSize=DEFAULT_RECV_BUFFERSIZE);

    //是否是tcp连接
    bool isTcp() const；

    //最后刷新时间(L连接心跳时间)，用于连接超时检测。新连接建立时更新一次，一旦有数据收发也更新
    time_t _iLastRefreshTime;

protected:

    //服务监听器
    BindAdapterPtr _pBindAdapter;

    //当前连接套接字
    TC_Socket _sock;

    //当前连接的唯一标识，4字节，高10bit为幻数，低22bit为连接索引
    volatile uint32_t _uid;

    //服务监听器套接字
    int _lfd;

    //超时时间，用于检测连接是否超时处理
    int _timeout;

    //当前连接远程IP
    string _ip;
    
    //当前连接远程IP
    uint16_t _port;

    //接收数据buffer
    TC_NetWorkBuffer _recvBuffer;

    //发送数据buffer
    TC_NetWorkBuffer    _sendBuffer;

    //用于过载保护，防止发送数据积压
    //送数据大小
    size_t _sendBufferSize = 0;
    //发送的检查<已经发送数据, 剩余buffer大小>
    vector<pair<size_t, size_t>> _checkSend;
    //最后一次数据积压检查时间
    time_t _lastCheckTime = 0;

    //需要过滤的头部字节数
    int _iHeaderLen;

    //发送完当前数据就关闭连接
    bool _bClose;

    //连接类型
    EnumConnectionType  _enType;

    //是否空连接转台
    bool _bEmptyConn;

    //接收数据的临时buffer,加这个目的是对udp接收数据包大小进行设置
    char *_pRecvBuffer = NULL;
    size_t _nRecvBufferSize;

public:
    //当前连接的鉴权状态
    int _authState;
    
    //该连接的鉴权状态是否初始化了
    bool _authInit;

    //openssl
    std::shared_ptr<TC_OpenSSL> _openssl;
};
```

***归纳***

1. Tars支持TCP和UDP协议，通过配置即可指定协议。
2. 一个TCP客户端连接至少包括BindAdapter服务监听器，监听的套接子lfd，空连接超时事件timeout，客户端连接的套接字fd，客户端的IP和端口。
3. Tars会为每个新客户端连接分配一个唯一标识，在关闭连接时回收已分配的唯一标识，后续新连接可以复用。
4. Tars支持空连接检测，应用侧可配置空连接开关，空连接检测超时时间。一旦新连接接收过一个完整的数据包，则视为非空连接。
5. Tars支持连接超时检测。一旦超过时间无数据收发，服务器端则会在网络线程断开当前连接。
6. Tars支持针对新连接过滤首包数据。默认情况，Tars协议不过滤新连接首包数据。应用侧如有需要，可调用对应协议接口设置。
7. Tars提供了鉴权机制。
8. Tars支持防碎片化网络数据的缓存。依赖此机制，可支持缓冲多包未发送数据和网络数据碎片化接收。
9. 在网络线程接收客户端请求数据后，都会调用协议解析回调函数校验是否瞒包和是否格式正确。一旦满足则保存到客户端请求消息队列，或者直接在网络线程处理(合并线程模式)。
10. Tars提供了发送数据防积压检测机制。当连接待发送数据大小大于配置数据积压阈值，则触发防积压检测机制。连续3个5秒发送过慢，或者连续12个5秒持续积压，则丢弃数据并关闭当前连接。只有发送数据时才会触发。
11. Tars对连接的操作，包括连接初始化，连接的数据收发，连接的关闭，提供了转线程到网络线程，连接的操作都在连接绑定的线程中完成，因此对连接的操作没有锁操作。

- ConnectionList
```
class ConnectionList
{
public:

    ConnectionList(NetThread *pNetThread);

    ~ConnectionList()
    {
        if(_vConn)
        {
            //服务停止时, 主动关闭一下连接, 这样客户端会检测到, 不需要等下一个发送包时, 发送失败才知道连接被关闭
            for (auto it = _tl.begin(); it != _tl.end(); ++it) 
            {
                if (_vConn[it->second].first != NULL) 
                {
                    _vConn[it->second].first->close();
                }
            }

            delete[] _vConn;
        }
    }

    //初始化连接链表大小
    void init(uint32_t size, uint32_t iIndex = 0);

    //请求分配一个新连接标识
    uint32_t getUniqId();

    //添加连接到连接链表
    void add(Connection *cPtr, time_t iTimeOutStamp);

    //刷新时间链
    void refresh(uint32_t uid, time_t iTimeOutStamp);

    //连接超时检测处理
    void checkTimeout(time_t iCurTime);

    //获取某个监听端口的连接
    vector<ConnStatus> getConnStatus(int lfd);

    //根据连接唯一标识获取连接
    Connection* get(uint32_t uid);

    //根据连接唯一标识删除连接
    void del(uint32_t uid);

    //连接链表当前连接数
    size_t size();

protected:
    typedef pair<Connection*, multimap<time_t, uint32_t>::iterator> list_data;

    //内部删除, 不加锁
    void _del(uint32_t uid);

protected:

    //锁，用以保护访问链表的线程安全
    TC_ThreadMutex _mutex;

    //网络线程
    NetThread *_pNetThread;

    //最大连接数
    volatile uint32_t _total;

    //空闲链表，用以保存可用的连接索引
    list<uint32_t> _free;

    //空闲链表元素个数
    volatile size_t _free_size;

    //连接动态数组，每个连接通过连接索引访问
    list_data *_vConn;

    //超时链表，用以超时检测
    multimap<time_t, uint32_t> _tl;

    //上次超时检测时间
    time_t _lastTimeoutTime;

    //连接标识的魔数部分
    uint32_t _iConnectionMagic;
};

```

***归纳***

1. Tars网络线程管理的连接链表通过数组保存所有的连接信息，能够高效的访问。另外，每个连接携带一个连接心跳时间，用于超时检测。
   每当新接收一个客户端连接，则为其分配一个唯一标识。
   每当需要访问连接，包括通过连接进行数据收发，关闭连接，更新连接状态等，通过连接唯一标识直接寻址即可。
2. 连接唯一标识包括两部分：魔数和数组索引，4字节的整数，高10bit为魔数，低22bit为连接索引。魔数高6bit为时间戳，低4bit为网络线程索引。
3. 连接链表的访问通过锁互斥访问。因为接收新客户端连接是在主线程操作，连接数据读写和关闭是在网络线程操作，而获取所有连接状态和连接列表信息是在业务线程操作。
4. 网络线程定时检测连接链表中的超时连接，如果超时，则关闭连接。
5. 网络线程进行连接数据读写后操作，都会更新连接心跳时间。

通过上面背景知识的了解，进一不查看代码。

***接收新连接***

***背景知识***
1. 主线程，即调用TC_EpollServer::waitForShutdown的线程，Tars应用在启动时会在Application类内调用。
2. Tars应用在启动时，先创建一个EpollServer实例，在EpollServer构造函数中创建一组网络线程和一个epoll实例，在网络线程NetThread构造函数中创建epoll实例。
3. Tars应用在启动时，会根据应用配置文件的Adapter监听器配置，创建对应的BindAdapter监听器实例，在BindAdapter监听器构造函数中创建异步处理业务线程Handle。
4. 每个BindAdapter监听器对应着一组的异步处理业务线程组。
5. 主线程主要职责是初始化必要数据结构，如服务核心，网络线程，异步处理业务线程，启动线程，监听接收新客户端连接和超时定时处理。

```
void TC_EpollServer::waitForShutdown()
{
    //启动异步处理业务线程。
    if(!isMergeHandleNetThread())
        startHandle();

    //一是将每个BindAdapter监听器的套接字add到主线程epoll实例
    //二是初始化每个网络线程管理的客户端连接链表
    //三是如果服务走的是udp协议，还会是实例化一个udp连接
    createEpoll();

    //启动网络线程，会进入线程routine函数，即在主线程开始accept前启动网络线程。
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

```
bool TC_EpollServer::accept(int fd, int domain)
{
    struct sockaddr_in stSockAddr4;
    struct ::sockaddr_in6 stSockAddr6;

    socklen_t iSockAddrSize = (AF_INET6 == domain) ? sizeof(::sockaddr_in6) : sizeof(sockaddr_in);
    struct sockaddr* stSockAddr = (AF_INET6 == domain) ? (struct sockaddr*) & stSockAddr6 : (struct sockaddr*) & stSockAddr4;
    TC_Socket cs;
    cs.setOwner(false);

    //接收连接
    TC_Socket s;
    s.init(fd, false, domain);
    int iRetCode = s.accept(cs, (struct sockaddr *)stSockAddr, iSockAddrSize);
    if (iRetCode > 0)
    {
        string ip;
        uint16_t port;
        char sAddr[INET6_ADDRSTRLEN] = "\0";
        inet_ntop(domain, (AF_INET6 == domain) ? ( void *)&stSockAddr6.sin6_addr : ( void *)&stSockAddr4.sin_addr, sAddr, sizeof(sAddr));
        port = (AF_INET6 == domain) ? ntohs(stSockAddr6.sin6_port) : ntohs(stSockAddr4.sin_port);
        ip = sAddr;

        //Tars提供了白名单IP和黑名单IP过滤的机制，应用侧只需要在配置文件配置过滤规则和IP即可。
        if (!_listeners[fd]->isIpAllow(ip))
        {
            //被拦截了
            cs.close();
            return true;
        }

        //Tars也提供了最大连接数的过载保护机制，超过了连接数后，后续新的连接请求直接拒绝掉
        if (_listeners[fd]->isLimitMaxConnection())
        {
            cs.close();
            return true;
        }

        //非阻塞IO,支持TCP心跳，nagle，默认的closewait操作
        cs.setblock(false);
        cs.setKeepAlive();
        cs.setTcpNoDelay();
        cs.setCloseWaitDefault();

        int timeout = _listeners[fd]->getEndpoint().getTimeout() / 1000;

        //新客户端连接请求过来，实例化一个连接实例，记录了归属的BindAdapter监听器和套接字
        Connection *cPtr = new Connection(_listeners[fd].get(), fd, (timeout < 2 ? 2 : timeout), cs.getfd(), ip, port);

        //Tars提供了过滤新客户端连接首个数据包过滤一定长度的能力
        cPtr->setHeaderFilterLen((int)_listeners[fd]->getHeaderFilterLen());

        //保存到网络线程的客户端连接链表表
        addConnection(cPtr, cs.getfd(), TCP_CONNECTION);

        return true;
    }
    else
    {
        //直到发生EAGAIN才不继续accept
        if (TC_Socket::isPending())
        {
            return false;
        }
    }

    return true;
}
```

***归纳***
1. Tars提供了白名单IP和黑名单IP过滤的机制，在接收TCP连接，UDP接收数据时校验。没通过过滤规则，直接拒绝新连接。
2. Tars提供了最大连接数的过载保护机制，超过了连接数后，接拒绝新的连接请求。
3. Tars采用非阻塞IO模型，支持TCP心跳，nagle和默认的closewait操作。
4. Tars提供了过滤客户端连接首个数据包过滤一定长度的机制。

***新连接的创建和初始化***

```
TC_EpollServer::Connection::Connection(TC_EpollServer::BindAdapter *pBindAdapter, int lfd, int timeout, int fd, const string& ip, uint16_t port)
: _pBindAdapter(pBindAdapter)
, _uid(0)
, _lfd(lfd)
, _timeout(timeout)
, _ip(ip)
, _port(port)
, _recvBuffer(this)
, _sendBuffer(this)
, _iHeaderLen(0)
, _bClose(false)
, _enType(EM_TCP)
, _bEmptyConn(true)
, _pRecvBuffer(NULL)
, _nRecvBufferSize(DEFAULT_RECV_BUFFERSIZE)
, _authInit(false)
{
    _iLastRefreshTime = TNOW;
    _sock.init(fd, true, pBindAdapter->_ep.isIPv6() ? AF_INET6 : AF_INET);
}
```

***网络线程管理的连接链表的创建和初始化***

```
TC_EpollServer::NetThread::NetThread(TC_EpollServer *epollServer, int threadIndex)
: _epollServer(epollServer)
, _threadIndex(threadIndex)
, _bTerminate(false)
, _list(this)
, _bEmptyConnAttackCheck(false)
, _iEmptyCheckTimeout(MIN_EMPTY_CONN_TIMEOUT)
, _nUdpRecvBufferSize(DEFAULT_RECV_BUFFERSIZE)
{
    _epoller.create(10240);
    _notify.init(&_epoller);
    _notify.add(_notify.notifyFd());
}

TC_EpollServer::ConnectionList::ConnectionList(TC_EpollServer::NetThread *pEpollServer)
: _pEpollServer(pEpollServer)
, _total(0)
, _free_size(0)
, _vConn(NULL)
, _lastTimeoutTime(0)
, _iConnectionMagic(0)
{
}
```

***归纳***
1. 每个网络线程都各自管理一个客户端连接链表。
2. 创建网络线程时会初创建客户端连接链表。

```
void TC_EpollServer::NetThread::createEpoll(uint32_t maxAllConn)
{
    _list.init((uint32_t)maxAllConn, _threadIndex + 1);
}

void TC_EpollServer::ConnectionList::init(uint32_t size, uint32_t iIndex)
{
    _lastTimeoutTime = TNOW;
    
    //最大连接数
    _total = size;

    _free_size = 0;
    if (_vConn) delete[] _vConn;

    //分配total+1个空间(多分配一个空间, 第一个空间其实无效)
    _vConn = new list_data[_total+1];
    _iConnectionMagic = ((((uint32_t)_lastTimeoutTime) << 26) & (0xFFFFFFFF << 26)) + ((iIndex << 22) & (0xFFFFFFFF << 22));//((uint32_t)_lastTimeoutTime) << 20;

    //free从1开始分配, 这个值为uid, 0保留为管道用, epollwait根据0判断是否是管道消息
    for(uint32_t i = 1; i <= _total; i++)
    {
        _vConn[i].first = NULL;
        _free.push_back(i);
        ++_free_size;
    }
}

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

***归纳***
1. Tars采用线性数据结构数组存在连接列表和维护一个可用索引列表。通过索引，后续连接操作可以直接寻址快速查找到对用连接信息。
2. Tars连接唯一标识包括魔数和索引。通过魔数增强连接的辨识度。唯一标识使用4字节整数，其中高6bit是时间戳，接着4bit是网络索引+1，即从1开始，最大15，因为网络线程数量最大为15。


```
void TC_EpollServer::addConnection(TC_EpollServer::Connection *cPtr, int fd, TC_EpollServer::CONN_TYPE iType)
{
    //直接通过fd路由到网络线程
    TC_EpollServer::NetThread* netThread = getNetThreadOfFd(fd);

    if(iType == TCP_CONNECTION)
    {
        netThread->addTcpConnection(cPtr);
    }
    else
    {
        netThread->addUdpConnection(cPtr);
    }
    
    //Tars提供了接收新连接后，回调应用注册回调函数的能力
    if (_acceptFunc != NULL)
    {
        _acceptFunc(cPtr);
    }
}
```

***归纳***
1. 每一个客户端连接都会绑定一个网络线程，Tars通过fd求余绑定一个网络线程。Tars通过fd求余绑定网络线程的算法过于简单，可能出现网络线程间的连接数不均匀的情况。好处是简单处理，性能高。
2. Tars提供了接收新连接后，回调应用注册回调函数的机制，应用侧可通过Application类的接口注册。

***添加到网络线程管理连接链表***

```
void TC_EpollServer::NetThread::addTcpConnection(TC_EpollServer::Connection *cPtr)
{
    uint32_t uid = _list.getUniqId();

    //新连接Connection在加入网络线程的客户端连接列表时才分配唯一标识
    cPtr->init(uid);

    _list.add(cPtr, cPtr->getTimeout() + TNOW);

    //同一个BindAdapter监听器的新客户端连接会分散到不同的网络线程处理，但连接数得归到同一个监听器
    cPtr->getBindAdapter()->increaseNowConnection();

#if TARS_SSL
    if (cPtr->getBindAdapter()->getEndpoint().isSSL())
    {
        // 分配ssl对象, ctxName 放在obj proxy里
        // cPtr->getBindAdapter()->_ctx在应用启动时，Tars框架会初始化
        cPtr->_openssl = TC_OpenSSL::newSSL(cPtr->getBindAdapter()->_ctx);
        if (!cPtr->_openssl)
        {
	        cPtr->close();
            return;
        }

        cPtr->_openssl->init(true);
        cPtr->_openssl->setReadBufferSize(1024 * 8);
        cPtr->_openssl->setWriteBufferSize(1024 * 8);
        
        //握手
        int ret = cPtr->_openssl->doHandshake(cPtr->_sendBuffer);
        if (ret != 0)
        {
	        cPtr->close();
            return;
        }

        // send the encrypt data from write buffer
        if (!cPtr->_sendBuffer.empty())
        {
            cPtr->sendBuffer();
        }
    }
#endif

    //加入网络线程的epoll监听客户端连接的读写事件
    //注意epoll add必须放在最后, 否则可能导致执行完, 才调用上面语句
    _epoller.add(cPtr->getfd(), cPtr->getId(), EPOLLIN | EPOLLOUT);
}

void TC_EpollServer::NetThread::addUdpConnection(TC_EpollServer::Connection *cPtr)
{
    //udp没有连接的概念，Tars只是将tcp和udp统一处理，将走udp协议的监听器的套接字封装成连接
    uint32_t uid = _list.getUniqId();
    cPtr->init(uid);
    _list.add(cPtr, cPtr->getTimeout() + TNOW);
    _epoller.add(cPtr->getfd(), cPtr->getId(), EPOLLIN | EPOLLOUT);
}
```

***归纳***

1. Tars支持SSL，默认编译不打开，需cmake .. -DTARS_SSL=1打开编译选项，应用侧还需配置证书和密钥。


***背景知识***

关闭操作类型包括：

1. 关闭操作包括客户端主动关闭
2. 业务侧服务器端主动关闭，服务异常服务器端主动关闭
3. 连接超时服务器端主动关闭


***关闭连接套接字***

```
void TC_EpollServer::Connection::close()
{
#if TARS_SSL
    if (_openssl)
    {
        _openssl->release();
        _openssl.reset();
    }
#endif

    if (isTcp() && _sock.isValid())
    {
        _pBindAdapter->decreaseSendBufferSize(_sendBuffer.size());
        _sock.close();
    }
}
```

***关闭连接***

```
oid TC_EpollServer::NetThread::delConnection(TC_EpollServer::Connection *cPtr, bool bEraseList, EM_CLOSE_T closeType)
{
    //如果是TCP的连接才真正的关闭连接
    if (cPtr->getListenfd() != -1)
    {
        uint32_t uid = cPtr->getId();

        //构造一个tagRecvData，通知业务该连接的关闭事件
        shared_ptr<RecvContext> recv = std::make_shared<RecvContext>(uid, cPtr->getIp(), cPtr->getPort(), cPtr->getfd(), cPtr->getBindAdapter(), true, (int)closeType);

        //如果是merge模式，则close直接交给网络线程处理
        if (_epollServer->isMergeHandleNetThread())
        {
            cPtr->insertRecvQueue(recv);
        }
        else
        {
            cPtr->getBindAdapter()->insertRecvQueue(recv);
        }

        cPtr->getBindAdapter()->decreaseNowConnection();

        //从epoller删除句柄放在close之前, 否则重用socket时会有问题
        _epoller.del(cPtr->getfd(), uid, 0);

        cPtr->close();

        //对于超时检查, 由于锁的原因, 在这里不从链表中删除
        if(bEraseList)
        {
            _list.del(uid);
        }
    }
}
```

***归纳***

关闭连接需要如下步骤：

1. 通知异步处理业务线程当前连接已经关闭
2. 从epoll移除监听的套接字
3. 关闭连接套接字
4. 从连接链表删除

***转线程***

1. 当客户端发送请求，服务器端网络线程监听到读事件，在网络线程读取请求数据，校验数据是否满包和格式要求。
2. 如果启用合并网络线程和异步处理业务线程，则直接在网络线程分发请求，调用业务提供接口处理，不涉及转线程。业务处理完毕后，也是直接在网络线程响应客户端。
3. 如果不启用合并网络线程和异步处理业务线程，将请求消息添加到异步处理消息队列，并通知异步处理业务线程，由异步处理业务线程分发请求，调用业务提供接口处理，此时涉及转线程。
   业务处理完毕后，将响应消息添加到异步响应消息队列，并通知网络线程，此时涉及转线程。
4. 如果应用侧直接从应用线程给客户端推送消息，消息也是加到异步响应消息队列，并通知网络线程，此时涉及转线程。
5. 如果在网络线程进行数据收发，出现客户端已主动关闭连接，服务器端处理出现异常，则会关闭连接。关闭操作直接在网络线程处理，不涉及转线程。
6. 如果应用侧直接从应用线程主动关闭连接或者在异步处理线程关闭连接，则将关闭连接消息转添加到异步响应消息队列，并通知网络线程，此时涉及转线程。

总的来说，Tars对网络连接的IO操作以网络线程为主，操作都是在网络线程中完成。如果操作不在网络线程，则将操作请求转发到网络线程。

```
void TC_EpollServer::NetThread::run()
{
    _threadId = std::this_thread::get_id();

    if(_epollServer->isMergeHandleNetThread()) 
    {
        //合并网络线程和异步处理业务线程的情况下，需要设置网络线程到业务处理类，通过网络线程直接响应
        vector<TC_EpollServer::BindAdapterPtr> adapters = _epollServer->getBindAdapters();
        for (auto adapter : adapters)
        {
            adapter->getHandle(_threadIndex)->setNetThread(this);
            adapter->getHandle(_threadIndex)->initialize();
        }
    }

    //循环监听网路连接请求
    while(!_bTerminate)
    {
        // 空连接检测和连接超时检测
        _list.checkTimeout(TNOW);

        int iEvNum = _epoller.wait(1000);
        //没有网络事件
        if (iEvNum == 0)
        {
            if (_epollServer->isMergeHandleNetThread()) 
            {
                //合并网络线程和异步处理业务线程，心跳逻辑直接在网络线程执行
                vector<TC_EpollServer::BindAdapterPtr> adapters = _epollServer->getBindAdapters();
                for (auto adapter : adapters)
                {
                    adapter->getHandle(_threadIndex)->heartbeat();
                }
            }
        }

        if (_bTerminate)
            break;

        for (int i = 0; i < iEvNum; ++i)
        {
            try
            {
                const epoll_event &ev = _epoller.get(i);
                uint32_t fd = TC_Epoller::getU32(ev, false);
                if (fd == (uint32_t)_notify.notifyFd())
                {
                    //通知消息
                    processPipe();
                }
                else
                {
                    //网络读写事件
                    processNet(ev);
                }
            }
            catch (exception &ex)
            {
                error("run exception:" + string(ex.what()));
            }
        }
    }
}
```

