
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
