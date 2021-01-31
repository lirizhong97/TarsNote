本篇描述依赖于如下文档，通过如下文档可以了解一些背景知识，更方便理解。

- [Tars应用启动流程](application_startup.md)
- [Tars服务器端逻辑](server_side_logic.md)

主线程，即调用waitForShutdown的线程，Tars框架在应用启动时会在Application类内调用。<br/>
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
    //二是为每个网络线程创建epoll实例
    //三是如果服务走的是udp协议，还会是实例化一个udp连接
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

***接收新客户端连接的逻辑***

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

        //走的是非阻塞IO,支持TCP心跳，nagle，默认的closewait操作
        cs.setblock(false);
        cs.setKeepAlive();
        cs.setTcpNoDelay();
        cs.setCloseWaitDefault();

        int timeout = _listeners[fd]->getEndpoint().getTimeout() / 1000;

        //新客户端连接请求过来，实例化一个连接实例，记录了归属的BindAdapter监听器和套接字
        Connection *cPtr = new Connection(_listeners[fd].get(), fd, (timeout < 2 ? 2 : timeout), cs.getfd(), ip, port);

        //Tars提供了过滤新客户端连接首个数据包过滤一定长度的能力，这种需求可能走的是非Tars协议，
        //即走的是自定义协议时，可能会用到，需求较少。但Tars提供了这种能力
        cPtr->setHeaderFilterLen((int)_listeners[fd]->getHeaderFilterLen());

        //保存到网络线程的客户端连接列表
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

看以下，创建一个新的客户端连接Connection实例时内部都做了哪些初始化

```
TC_EpollServer::Connection::Connection(TC_EpollServer::BindAdapter *pBindAdapter, int lfd, int timeout, int fd, const string& ip, uint16_t port)
//记录归属于哪个监听器
: _pBindAdapter(pBindAdapter)
//唯一标识，此时还每分配，等网络线程将此连接加入连接列表时会分配一个唯一标识
, _uid(0)
//监听器的套接字
, _lfd(lfd)
, _timeout(timeout)
, _ip(ip)
, _port(port)
//收发数据缓存，暂时可以理解为一个队列
, _recvBuffer(this)
, _sendBuffer(this)
//首包过滤头部数据长度
, _iHeaderLen(0)
//是否关闭标识
, _bClose(false)
//连接类型是TCP
, _enType(EM_TCP)
//新连接是空连接，等有数据收发时才变换状态
, _bEmptyConn(true)
, _pRecvBuffer(NULL)
, _nRecvBufferSize(DEFAULT_RECV_BUFFERSIZE)
//鉴权初始化标识
, _authInit(false)
{
    _iLastRefreshTime = TNOW;
    _sock.init(fd, true, pBindAdapter->_ep.isIPv6() ? AF_INET6 : AF_INET);
}
```

***添加到网络线程的新连接列表***

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

```
void TC_EpollServer::NetThread::addTcpConnection(TC_EpollServer::Connection *cPtr)
{
    //从可用的连接唯一标识队列中pop一个出来使用。网络线程在EpollServer实例化时创建，创建网络线程时
    //每个线程都会创建一个客户端连接列表，创建客户端连接列表时会创建一个可用连接唯一标识队列。
    //接收新连接消耗掉一个连接唯一标识，关闭连接归还已分配的连接唯一标识
    uint32_t uid = _list.getUniqId();

    //新连接Connection在加入网络线程的客户端连接列表时才分配唯一标识
    cPtr->init(uid);

    //加入网络线程的客户端连接列表。由于客户端连接列表肯定存在主线程和网络线程的并发操作，因此其内部必然存在互斥操作来保证线程安全
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
````

