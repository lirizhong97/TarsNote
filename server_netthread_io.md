
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
class NetThread : public TC_Thread, public TC_HandleBase
{
public:
    //关联核心服务EpollServer和为每个线程分配一个索引
    NetThread(TC_EpollServer *epollServer, int index);

    virtual ~NetThread();

    //获取网路线程索引，0~线程数量-1。
    int getIndex() const；

    //线程的执行函数
    virtual void run();

    //停止网络线程，唤醒网络线程并停止
    void terminate();

    //初始化网络线程管理的客户端连接链表
    void createEpoll(uint32_t maxAllConn);

    //初始化udp监听器服务
    void initUdp(const unordered_map<int, BindAdapterPtr> &listeners);

    //是否网络线程已停止
    bool isTerminate() const；

    //获取网络线程管理的epoll实例
    TC_Epoller* getEpoller()；

    //通知，用于唤醒网络线程
    void notify();

    //关闭连接。非网络线程需要关闭连接时，通过该接口，可将关闭请求转线程到网络线程处理
    void close(const shared_ptr<RecvContext> &data);

    //发送数据。网络线程本身也可调用该接口，而非网络线程需要发送数据时，通过该接口，可将发送请求转线程到网络线程处理
    void send(const shared_ptr<SendContext> &data);

    //获取某一监听器的连接列表信息
    vector<TC_EpollServer::ConnStatus> getConnStatus(int lfd);

    //获取网络线程管理的连接数
    size_t getConnectionCount()；

    //记录DEBUG日志
    void debug(const string &s) const;

    //记录INFO日志
    void info(const string &s) const;

    //记录TARS日志
    void tars(const string &s) const;

    //记录错误日志
    void error(const string &s) const;

    //是否启用防止空链接攻击的机制
    void enAntiEmptyConnAttack(bool bEnable);

    //设置空连接超时时间
    void setEmptyConnTimeout(int timeout);

    //设置udp的接收缓存区大小，单位是B,最小值为8192，最大值为DEFAULT_RECV_BUFFERSIZE
    void setUdpRecvBufferSize(size_t nSize=DEFAULT_RECV_BUFFERSIZE);

protected:

    //根据连接唯一标识获取对应连接
    Connection *getConnectionPtr(uint32_t uid);

    //添加tcp连接，在主线程会接收和添加新的连接
    void addTcpConnection(Connection *cPtr);

    //添加udp连接，应用在启动时会将UDP的服务器端套接字添加进来
    void addUdpConnection(Connection *cPtr);

    //删除链接
    //bEraseList 是否是超时连接的删除。超时连接的删除在接口外部完成加锁操作
    //closeType  关闭类型,0:表示客户端主动关闭；1:服务端主动关闭;2:连接超时服务端主动关闭
    void delConnection(Connection *cPtr, bool bEraseList = true, EM_CLOSE_T closeType=EM_CLIENT_CLOSE);

    //处理通知消息
    void processPipe();

    //处理网络请求
    void processNet(const epoll_event &ev);

    //空连接超时时间
    int getEmptyConnTimeout() const;

    //是否开启空连接检测
    bool isEmptyConnCheck() const;

private:

    //核心服务
    TC_EpollServer *_epollServer;

    //线程id
    std::thread::id _threadId;

    //线程索引
    int _threadIndex;

    //epoll封装类实例
    TC_Epoller _epoller;

    //服务是否已停止
    bool _bTerminate;

    //通知，用于通知网络处理通知消息，达到别的线程请求转发到网络线程处理
    TC_Epoller::NotifyInfo _notify;

    //管理的连接链表
    ConnectionList _list;

    //异步响应消息队列，用于异步发送响应消息和关闭连接
    send_queue _sbuffer;

    //空连接检测机制开关
    bool _bEmptyConnAttackCheck;

    //空连接超时时间,单位是毫秒,默认值2s, 该时间必须小于等于adapter自身的超时时间
    int _iEmptyCheckTimeout;

    //udp连接时接收包缓存大小,针对所有udp接收缓存有效
    size_t _nUdpRecvBufferSize;

    //通知信号
    bool _notifySignal = false;
};
```

网络线程主要职责：
1. 接收客户端请求消息，处理，分发
2. 同步响应，异步响应，主动推送客户端消息。
3. 管理客户端连接和连接链表



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
