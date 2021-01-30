## 应用启动流程
---------------

要定位应用的启动流程，就需要找到应用的入口函数或者入口类。

Tars的入口类是Application，启动流程核心函数声明如下：

- Application.h
```
class Application
{
public:
    void main(int argc, char *argv[]);
    void waitForShutdown();
};
```

其中，main是入口函数，负责处理命令行参数，解析配置文件，初始化必要的数据结构，<br/><br/>而waitForShutdown则负责启动线程，开始接受外部请求。

**备注：<br/><br/>1. 应用开发需要继承Application实现自己的Tars应用服务类，并在应用main函数中调用这两个函数启动应用**

- 解析命令行参数

```
TC_Option op;
op.decode(argc, argv);
```

**参考：[Tars解析命令行参数](argument_parser.md)**

- 获取配置文件名

  通过刚才TC_Option获取，即命令行参数: --config=/path/to/config/file

```
ServerConfig::ConfigFile = option.getValue("config");
```

- 解析配置文件

    - 配置相关声明函数代码

```
class Application
{
public:
    TC_Config &getConfig();
	const TC_Config &getConfig() const;

protected:
    virtual void onParseConfig(TC_Config &conf){};
    void parseConfig(const string &config);

private:
    TC_Config _conf;
};
```

***备注：<br/><br/>1. 应用侧如有需要可通过getConfig函数应用配置信息，而不仅仅框架内部使用***
  
  先读取文件内容，然后解析

```
string config = TC_File::load2str(ServerConfig::ConfigFile);
parseConfig(config);
```

parseConfig函数代码:

```
_conf.parseString(config);
onParseConfig(_conf);
```

**参考：[Tars解析配置文件](configure_file_parser.md)**

***备注：<br/><br/>1. 应用侧如有需要可通过getConfig函数应用配置信息，而不仅仅框架内部使用<br/><br/>  2. Tars提供了应用侧修改配置的能力，即Tars在解析完配置文件后，会回调onParseConfig函数，应用开发<br/><br/>可在Application继承子类中重载该回调函数，在该函数可对配置进行读取和修改，但一般情况下不需要重载***

获取到配置文件的配置参数后，接下来会初始化必要的数据结构，包括初始化服务器端和客户端的相关数据结构。

- 客户端初始化

    - 客户端相关声明函数代码

```
//初始化通信器
_communicator = CommunicatorFactory::getInstance()->getCommunicator(_conf);

class Application
{
public:
    static CommunicatorPtr& getCommunicator();

protected:
    void initializeClient();

private:
    static CommunicatorPtr _communicator;
};
```

***备注：<br/><br/>1. 通信器Communicator类是一个核心类，内部封装了客户端必要的数据结构，<br/><br/>网络线程，异步响应线程，消息队列，网络数据收发等核心逻辑<br/><br/>2. Tars应用只需通过调用Application::getCommunicator即可获取到通信器类，对于非Tars应用的纯客户端应用，可自己new创建一个通信器<br/><br/>3. 为了避免整个流程过于复杂，这里不继续展开通信器的初始化代码，会专门研究通信器的实，此处主要针对服务器端初始化展开<br/><br/>4. 通信器一旦创建和初始化后，即可使用，即可通过ServantProxy调用别的服务，所以这里看到客户端的初始比较简单，但内部其实做了很多工作***

**参考：[Tars通信器Communicator的初始化](communicator_initialize.md)**


- 服务器端初始化

在了解服务器端初始化流程之前，需要了解服务端配置的数据结构和一些基本概念。

```
struct ServerConfig
{
    static std::string TarsPath;            //Tars服务安装目录，一般是/usr/local/app/tars
    static std::string Application;         //应用名称，即业务标识，一个业务由多个服务组成，如TestApp
    static std::string ServerName;          //服务名称, 即应用程序名称，对应一个进程，如HelloServer
    static std::string BasePath;            //应用程序路径，用于拉取远程配置文件存放的本地目录，如/usr/local/app/TestApp/HelloServer
    static std::string DataPath;            //应用程序数据路径，用于保存普通数据文件
    static std::string LocalIp;             //本机IP，不能是本机回环IP127.0.0.1
    static std::string LogPath;             //log路径
    static int         LogSize;             //log大小(字节)
    static int         LogNum;              //log个数()
    static std::string LogLevel;            //log日志级别
    static std::string Local;               //本地套接字，主要提供给tarsnode管理应用
    static std::string Node;                //本机node地址
    static std::string Log;                 //日志中心地址
    static std::string Config;              //配置中心地址
    static std::string Notify;              //信息通知中心
    static std::string ConfigFile;          //框架配置文件路径，通过命令行参数--conf=/path/to/config/file传入
    static bool        CloseCout;           //输出控制台开关，主要用于调试，可通过web控制台下发命令开启和关闭
    static int         ReportFlow;          //是否服务端上报所有接口stat流量 0不上报 1上报(用于非Tars协议服务流量统计)，默认情况下由客户端上报接口调用流量，但对于TUP请求，单向请求，非Tars协议请求由服务器端上报，而对于非Tars协议的接口调用流量，由该开关控制
    static int         IsCheckSet;          //是否对按照set规则调用进行合法性检查(针对Tars协议服务) 0,不检查，1检查
    static bool        OpenCoroutine;       //是否启用协程处理方式
    static size_t      CoroutineMemSize;    //协程占用内存空间的最大大小
    static uint32_t    CoroutineStackSize;  //每个协程的栈大小(默认128k)
	static int         NetThread;           //服务网络线程数量
	static bool        ManualListen;        //是否启用手工端口监听，用于延迟accept新连接。默认情况下，服务在初始化bind绑定IP和端口后，会马上listen监听套接字，但该开关开启后，在服务启动后，应用侧可调用接口开始listen监听套接界
	static bool        MergeNetImp;         //是否合并网络线程和逻辑处理线程，默认不合并，客户端请求push进逻辑处理线程的消息队列，并由逻辑处理线程异步处理；合并后，直接push进网络线程的消息队列，直接有网络线程处理
	static int         BackPacketLimit;     //回包积压检查（针对单个客户连接，避免队列过大，过载保护）
	static int         BackPacketMin;       //回包速度检查（针对单个客户连接，避免队列过大，过载保护）
	static std::string CA;                  //CA证书(SSL)
	static std::string Cert;                //客户端证书(SSL)
	static std::string Key;                 //服务端密钥(SSL)
	static bool VerifyClient;               //是否校验客户端证书(SSL)       
	static std::string Ciphers;             //密码(SSL)  
	static map<string, string> Context;     //框架内部用, 传递节点名称(以域名形式部署时)
};
```

由于配置比较多，这里不作展开研究，后续涉及到时会展开研究。

**参考：[Tars服务端配置](server_side_configuration.md)**

从已解析的TC_Config配置中获取对应配置填充ServerConfig每一个配置项。

***备注：其中，服务名在无配置的情况下，降级使用可执行文件名，极端情况下，还会降级使用本机IP***

代码如下：

```
string exe = "";
try
{
    exe = TC_File::extractFileName(TC_File::getExePath());
}
catch(TC_File_Exception & ex)
{
    exe = _conf.get("/tars/application/server<localip>");
}

ServerConfig::ServerName = toDefault(_conf.get("/tars/application/server<server>"), exe);
```

***备注：其中，Tars服务安装路径选择了日志路径的上一层目录<br/><br/>默认情况下，Tars服务安装路径为/usr/local/app/tars/，<br/><br/>日志路径为/use/local/app/tars/app_log/，建议采用默认路径***

```
ServerConfig::TarsPath = TC_File::simplifyDirectory(ServerConfig::LogPath + FILE_SEP + ".." + FILE_SEP) + FILE_SEP;
```


***备注：其中，如果没有配置本机IP，则读取本机IP列表，并优先使用第一个非回环IP***

```
if (ServerConfig::LocalIp.empty())
{
    vector<string> v = TC_Socket::getLocalHosts();
    ServerConfig::LocalIp = "127.0.0.1";
    for(size_t i = 0; i < v.size(); i++)
    {
        if(v[i] != "127.0.0.1")
        {
            ServerConfig::LocalIp = v[i];
            break;
        }
    }
}
```

对于其他配置项，也是通过如下代码获取配置值，考虑0配置或者异常配置情况，

每个配置项都会提供默认值，由于配置项比较多，不一一贴代码。

```
_conf.get("/tars/application/server<keyname>")
```

填充完ServerConfig所有的配置项参数后，Tars还提供了一个回调函数给应用侧修改ServerConfig的机会。

```
class Application
{
public:
    TC_Config &getConfig();
	const TC_Config &getConfig() const;

protected:
    virtual void onParseConfig(TC_Config &conf){};
    void parseConfig(const string &config);
    virtual void onServerConfig(){};

private:
    TC_Config _conf;
};
```

***备注：应用侧可在Application继承子类中重载onServerConfig回调来进一步修改ServerConfig，正常情况下不需要修改***

<br/>接下来，Tars会进一步初始化其他数据结构。<br/><br/>


- SSL数据结构及初始化

```
struct CTX
{
    CTX(SSL_CTX* x) : ctx(x) {}
    SSL_CTX* ctx;
};

class Application
{
protected:
    shared_ptr<TC_OpenSSL::CTX> _ctx = nullptr;
};

#if TARS_SSL
if(!ServerConfig::Cert.empty()) 
{
    _ctx = TC_OpenSSL::newCtx(ServerConfig::CA, ServerConfig::Cert, ServerConfig::Key, ServerConfig::VerifyClient, ServerConfig::Ciphers);
    if (!_ctx) 
    {
        exit(-1);
    }
}
#endif
```

***备注：Tars默认不编译SSL，需要编译时打开，可执行命令：$cmake .. -DTARS_SSL，这里不展开研究Tars SSL***

***参考：[Tars SSL](tars_ssl.md)***

<br/>
- EpollServer数据结构及初始化
<br/>

```
class TC_EpollServer
{
private:
	TC_Epoller _epoller;                //对linux/unix多路复用epoll接口的一个封装类
	TC_Epoller::NotifyInfo _notify;     //用于通知，对应一个套接字，其他线程通过发送消息和epoll操作读写唤醒网络线程，达到转网络线程的目的
    std::vector<NetThread*> _netThreads;//一组网络线程
};
```

```
_epollServer = new TC_EpollServer(ServerConfig::NetThread);
```

```
TC_EpollServer::TC_EpollServer(unsigned int iNetThreadNum)
{
    _epoller.create(10240);
    _notify.init(&_epoller);
    _notify.add(_notify.notifyFd());
    for (size_t i = 0; i < _netThreadNum; ++i)
    {
        TC_EpollServer::NetThread* netThreads = new TC_EpollServer::NetThread(this, i);
        _netThreads.push_back(netThreads);
    }
}
```

到目前为止，创建了一个EpollServer核心类实例， 内部只是创建了用于异步通知的结构，网络线程的结构，还没有启动网络线程。

```
class Application
{
public:
    TC_EpollServerPtr &getEpollServer() { return _epollServer; }
    const TC_EpollServerPtr &getEpollServer() const { return _epollServer; }
    void terminate();
    
protected:
    TC_EpollServerPtr _epollServer;
};
```

***备注： 在Application类中，对外提供了获取了EpollServer实例的接口， 应用侧可使用***

其中，终止应用接口terminate，内部也是通过EpollServer来终止。

```
void Application::terminate()
{
    if (_epollServer && !_epollServer->isTerminate())
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(100)); //稍微休息一下, 让当前处理包能够回复
        _epollServer->terminate();
    }
}
```

设置接收新客户端连接时的回调
```
_epollServer->setOnAccept(std::bind(&Application::onAccept, this, std::placeholders::_1));

// 接收新的客户端链接时的回调
typedef std::function<void (TC_EpollServer::Connection*)> accept_callback_functor;

class TC_EpollServer
{
public:
    void setOnAccept(const accept_callback_functor& f) { _acceptFunc = f; }

private:
    accept_callback_functor _acceptFunc;
};
```

```
class Application
{
public:
    void addAcceptCallback(const TC_EpollServer::accept_callback_functor& cb);

protected:
    void onAccept(TC_EpollServer::Connection* cPtr);
};

void Application::addAcceptCallback(const TC_EpollServer::accept_callback_functor& cb)
{
    _acceptFuncs.push_back(cb);
}

void Application::onAccept(TC_EpollServer::Connection* cPtr)
{
    for (size_t i = 0; i < _acceptFuncs.size(); ++i)
    {
        _acceptFuncs[i](cPtr);
    }
}
```

***备注： 在Application类中，对外提供了设置新客户端新连接addAcceptCallback的回调接口， 应用侧可使用***

```
    //是否对空链接进行超时检查
    _epollServer->enAntiEmptyConnAttack(bEnable);
    _epollServer->setEmptyConnTimeout(TC_Common::strto<int>(toDefault(_conf.get("/tars/application/server<emptyconntimeout>"), "3")));
    //合并线程
	_epollServer->setMergeHandleNetThread(ServerConfig::MergeNetImp);
```

***备注： 该配置对应用挺有用，只需简单配置即可***

- 创建务端口监听管理服实例

```
//设置了一个Obj对应的接口提供者AdminServant，当有一个AdminObj对应的请求过来了，则使用提供者AdminServant的接口提供服务。
_servantHelper->addServant<AdminServant>("AdminObj", this);

//一个Adapter对应一个Obj, 这里进行设置映射关系。
_servantHelper->setAdapterServant("AdminAdapter", "AdminObj");

//创建一个端口监听管理核心类实例
TC_EpollServer::BindAdapterPtr lsPtr = new TC_EpollServer::BindAdapter(_epollServer.get());

//设置Adapter名称，一旦该监听套接子接受的客户端连接请求过来了，通过Adapter名称查找到Obj名称，通过Obj名称则可查找到接口提供者Servant
setAdapter(lsPtr, "AdminAdapter");
```

- 设置解析协议

```
lsPtr->setProtocolName("tars");
lsPtr->setProtocol(AppProtocol::parse);
```

***备注：<br/>1. 管理服务通信采用的是Tars协议<br/>2. Tars协议服务默认使用AppProtocol::parse回调函数解析请求数据。在接收到客户端连接请求数据后，使用协议解析回调函数AppProtocol::parse进行解析<br/>3. 协议：4字节长度数据+body数据***

```
class AppProtocol
{
public:
    static TC_NetWorkBuffer::PACKET_TYPE parse(TC_NetWorkBuffer &in, vector<char> &out)
    {
        return TC_NetWorkBuffer::parseBinary4<TARS_NET_MIN_PACKAGE_SIZE, TARS_NET_MAX_PACKAGE_SIZE>(in, out);
    }
};
template<uint32_t iMinLength, uint32_t iMaxLength>
static TC_NetWorkBuffer::PACKET_TYPE parseBinary4(TC_NetWorkBuffer&in, vector<char> &out)
{
    return in.parseBufferOf4(out, iMinLength, iMaxLength);
}
TC_NetWorkBuffer::PACKET_TYPE TC_NetWorkBuffer::parseBufferOf4(vector<char> &buffer, uint32_t minLength, uint32_t maxLength)
{
    return parseBuffer<uint32_t>(buffer, minLength, maxLength);
}
template<typename T>
TC_NetWorkBuffer::PACKET_TYPE parseBuffer(vector<char> &buffer, T minLength, T maxLength)
{
    if(getBufferLength() < sizeof(T))
    {
        return PACKET_LESS;
    }

    if(minLength < sizeof(T))
        minLength = sizeof(T);

    T length = getValue<T>();

    if(length < minLength || length > maxLength)
    {
        return PACKET_ERR;
    }

    if(getBufferLength() < length)
    {
        return PACKET_LESS;
    }

    //往后移动
    //move backward
    moveHeader(sizeof(T));

    //读取length长度的buffer
    //Read buffer of length length
    if(!getHeader(length - sizeof(T), buffer))
    {
        return PACKET_LESS;
    }

    moveHeader(length - sizeof(T));
    return PACKET_FULL;
}
```

***备注： 如果想修改默认的数据包限制大小，可以在应用侧重新设置解析协议***

```
lsPtr->setProtocol(TC_NetWorkBuffer::parseBinary4<128, 81920000>);
```

- 设置endpoint，主要包括协议类型，监听的IP和端口及超时

```
lsPtr->setEndpoint(ServerConfig::Local);

class TC_BindAdapter
{
public:
    void setEndpoint(const string &str)
    {
        std::lock_guard<std::mutex> lock (_mutex);
        _ep.parse(str)
    }

private:
    C_Endpoint _ep;
};

void TC_Endpoint::parse(const string &str)
{
    _grid = 0;
    _qos = 0;
    _weight = -1;
    _weighttype = 0;
    _authType = 0;

    const string delim = " \t\n\r";

    string::size_type beg;
    string::size_type end = 0;

    beg = str.find_first_not_of(delim, end);
    if(beg == string::npos)
    {
        throw TC_EndpointParse_Exception("TC_Endpoint::parse error : " + str);
    }

    end = str.find_first_of(delim, beg);
    if(end == string::npos)
    {
        end = str.length();
    }

    string desc = str.substr(beg, end - beg);
    if(desc == "tcp")
    {
        _type = TCP;
    }
    else if (desc == "ssl")
    {
        _type = SSL;
    }
    else if(desc == "udp")
    {
        _type = UDP;
    }
    else
    {
        throw TC_EndpointParse_Exception("TC_Endpoint::parse tcp or udp or ssl error : " + str);
    }

    desc = str.substr(end);
	end  = 0;
    while(true)
    {
    	beg = desc.find_first_not_of(delim, end);
    	if(beg == string::npos)
    	{
    	    break;
    	}

    	end = desc.find_first_of(delim, beg);
    	if(end == string::npos)
    	{
    	    end = desc.length();
    	}

    	string option = desc.substr(beg, end - beg);
    	if(option.length() != 2 || option[0] != '-')
    	{
    	    throw TC_EndpointParse_Exception("TC_Endpoint::parse error : " + str);
    	}

    	string argument;
    	string::size_type argumentBeg = desc.find_first_not_of(delim, end);
    	if(argumentBeg != string::npos && desc[argumentBeg] != '-')
    	{
    	    beg = argumentBeg;
    	    end = desc.find_first_of(delim, beg);
    	    if(end == string::npos)
    	    {
                end = desc.length();
    	    }
    	    argument = desc.substr(beg, end - beg);
    	}

    	switch(option[1])
    	{
    	    case 'h':
    	    {
        		if(argument.empty())
        		{
                    throw TC_EndpointParse_Exception("TC_Endpoint::parse -h error : " + str);
        		}
        		const_cast<string&>(_host) = argument;
        		break;
    	    }
    	    case 'p':
    	    {
        		istringstream p(argument);
        		if(!(p >> const_cast<int&>(_port)) || !p.eof() || _port < 0 || _port > 65535)
        		{
                    throw TC_EndpointParse_Exception("TC_Endpoint::parse -p error : " + str);
        		}
        		break;
    	    }
    	    case 't':
    	    {
        		istringstream t(argument);
        		if(!(t >> const_cast<int&>(_timeout)) || !t.eof())
        		{
                    throw TC_EndpointParse_Exception("TC_Endpoint::parse -t error : " + str);
                }
                break;
            }
            case 'g':
            {
                istringstream t(argument);
                if(!(t >> const_cast<int&>(_grid)) || !t.eof())
                {
                    throw TC_EndpointParse_Exception("TC_Endpoint::parse -g error : " + str);
                }
                break;
            }
            case 'q':
            {
                istringstream t(argument);
                if(!(t >> const_cast<int&>(_qos)) || !t.eof())
                {
                    throw TC_EndpointParse_Exception("TC_Endpoint::parse -q error : " + str);
                }
                break;
            }
            case 'w':
            {
                istringstream t(argument);
                if(!(t >> const_cast<int&>(_weight)) || !t.eof())
                {
                    throw TC_EndpointParse_Exception("TC_Endpoint::parse -w error : " + str);
                }
                break;
            }
            case 'v':
            {
                istringstream t(argument);
                if(!(t >> const_cast<unsigned int&>(_weighttype)) || !t.eof())
                {
                    throw TC_EndpointParse_Exception("TC_Endpoint::parse -v error : " + str);
                }
                break;
            }
            // auth type
            case 'e':
            {
                istringstream p(argument);
                if (!(p >> const_cast<int&>(_authType)) || !p.eof() || _authType < 0 || _authType > 1)
                {
                    throw TC_EndpointParse_Exception("TC_Endpoint::parse -e error : " + str);
                }
                break;
            }
            default:
    	    {
                ///throw TC_EndpointParse_Exception("TC_Endpoint::parse error : " + str);
    	    }
    	}
    }

    if(_weighttype != 0)
    {
        if(_weight == -1)
        {
            _weight = 100;
        }

        _weight = (_weight > 100 ? 100 : _weight);
    }

    if(_host.empty())
    {
        throw TC_EndpointParse_Exception("TC_Endpoint::parse error : host must not be empty: " + str);
    }
    else if(_host == "*")
    {
        const_cast<string&>(_host) = "0.0.0.0";
    }
    _isIPv6 = TC_Socket::addressIsIPv6(_host);

    if (_authType < 0)
        _authType = 0;
    else if (_authType > 0)
        _authType = 1;
}
```

endpoint配置格式：<br/>
协议类型 -h IP地址 -p 端口 [-其他配置项 配置直]...<br/>
例如：tcp 192.168.70.131 -p 8889 -t 3000<br/>
协议类型包括ssl，tcp和udp<br/>
-h ip 支持*，即0.0.0.0，支持IPv6地址<br/>
-p 端口<br/>
-t 超时<br/>
-g 路由状态<br/>
-q 网络QoS的dscp值<br/>
-w 节点的静态权重值<br/>
-v 节点的权重使用方式<br/>
-e 鉴权类型<br/>

***参考：[EndPoint配置](endpoint_configuration.md)***

<br/>
- 创建异步处理(线程)ServantHandle(继承Handle)实例，当合并网络网络线程时，并不会跑线程的routine函数run，这种情况下，仅仅作为异步处理类
<br/>

```
lsPtr->setHandle<ServantHandle>(1, this);

class TC_BindAdapter
{
public:
    template<typename T, typename ...Args>
    void setHandle(size_t n, Args&&... args)
    {
        if(!_handles.empty())
        {
            getEpollServer()->error("[BindAdapter::setHandle] handle is not empty!");
            return;
        }

        _iHandleNum = n;

        _threadDataQueue.resize(_iHandleNum + 1);
        _threadDataQueue[0] = std::make_shared<BindAdapter::DataQueue>();

        if(_pEpollServer->isMergeHandleNetThread())
        {
            _iHandleNum = _pEpollServer->_netThreadNum;
        }

        for (int32_t i = 0; i < _iHandleNum ; ++i)
        {
            HandlePtr handle = new T(args...);
            handle->setHandleIndex(i);
            handle->setEpollServer(this->getEpollServer());
            handle->setBindAdapter(this);
            _handles.push_back(handle);
        }
    }

private:
    vector<HandlePtr> _handles;
};
```

***备注：<br/>1. 一个BindAdapter对应一个异步处理（线程）组<br/>2. 在合并网络线程和异步处理线程的情况下，每个异步处理线程对应一个客户端请求消息队列，网络线程根据套接字文件描述符路由(push)到对应的消息队列<br/>3.在不合并的情况下，仅有使用第一个消息队列，多个异步处理线程抢占式处理消息队列中的请求***

<br/>
- 创建服务器端建监听的套接字，绑定端口，默认情况下还会马上进行监听
<br/>

```
_epollServer->bind(lsPtr);

class TC_EpollServer
{
public:
    int bind(BindAdapterPtr &lsPtr)
    {
        auto it = _listeners.begin();
        while (it != _listeners.end())
        {
            if (it->second->getName() == lsPtr->getName())
            {
                throw TC_Exception("bind name '" + lsPtr->getName() + "' conflicts.");
            }
            ++it;
        }

        const TC_Endpoint &ep = lsPtr->getEndpoint();
        TC_Socket &s = lsPtr->getSocket();
        bind(ep, s, lsPtr->isManualListen());
        _listeners[s.getfd()] = lsPtr;
        _bindAdapters.push_back(lsPtr);
        return s.getfd();
    }

private:
    unordered_map<int, BindAdapterPtr> _listeners;
    vector<BindAdapterPtr> _bindAdapters;
};
```

当有新的客户端连接请求过来了，通过_listeners可以查找到对应的BindAdapter

当需要对所有BindAdapter进行类似操作时，可通过遍历_bindAdapters实现

到目前为止， 仍然是在创建相应的数据结构实例，还没有启动相关的线程，但可能是已经服务已经处理监听状态，但也只是监听管理端口而已，真正对外提供服务的IP和端口还没有创建，接下来就会看到这块。

<br/>
- 服务监听
<br/>

```
void Application::bindAdapter(vector<TC_EpollServer::BindAdapterPtr>& adapters)
{
    application/server<BackPacketBuffLimit>", "0"), "0"));
    string sPrefix = ServerConfig::Application + "." + ServerConfig::ServerName + ".";
    vector<string> adapterName;
    map<string, ServantHandle*> servantHandles;
    if (_conf.getDomainVector("/tars/application/server", adapterName))
    {
        for (size_t i = 0; i < adapterName.size(); i++)
        {
            string servant = _conf.get("/tars/application/server/" + adapterName[i] + "<servant>");
            //Adapter Domain节点不符合前缀要求
            checkServantNameValid(servant, sPrefix);

            //Adapter名称和Obj名称作映射
            _servantHelper->setAdapterServant(adapterName[i], servant);
            TC_EpollServer::BindAdapterPtr bindAdapter = new TC_EpollServer::BindAdapter(_epollServer.get());
	        setAdapter(bindAdapter, adapterName[i]);

            string sLastPath = "/tars/application/server/" + adapterName[i];
            TC_Endpoint ep;
            ep.parse(_conf[sLastPath + "<endpoint>"]);
            if (ep.getHost() == "localip")
            {
                ep.setHost(ServerConfig::LocalIp);
            }

            bindAdapter->setName(adapterName[i]);
            bindAdapter->setEndpoint(_conf[sLastPath + "<endpoint>"]);

            //设置最大连接数
            bindAdapter->setMaxConns(TC_Common::strto<int>(_conf.get(sLastPath + "<maxconns>", "128")));
            
            //设置黑名单和白名单IP
            bindAdapter->setOrder(parseOrder(_conf.get(sLastPath + "<order>", "allow,deny")));
            bindAdapter->setAllow(TC_Common::sepstr<string>(_conf[sLastPath + "<allow>"], ";,", false));
            bindAdapter->setDeny(TC_Common::sepstr<string>(_conf.get(sLastPath + "<deny>", ""), ";,", false));

            //设置队列大小，用于过载保护
            bindAdapter->setQueueCapacity(TC_Common::strto<int>(_conf.get(sLastPath + "<queuecap>", "1024")));
            bindAdapter->setQueueTimeout(TC_Common::strto<int>(_conf.get(sLastPath + "<queuetimeout>", "10000")));

            //默认是tars协议，如果是非tars协议，可以在配置中配置protocol=no-tars
            bindAdapter->setProtocolName(_conf.get(sLastPath + "<protocol>", "tars"));

	        bindAdapter->setBackPacketBuffLimit(ServerConfig::BackPacketLimit);
	        bindAdapter->setBackPacketBuffMin(ServerConfig::BackPacketMin);
	        
            if (bindAdapter->isTarsProtocol())
            {
                //Tars协议服务默认请求数据解析回调函数
                bindAdapter->setProtocol(AppProtocol::parse);
            }

            //校验ssl正常初始化
#if TARS_SSL
            if (bindAdapter->getEndpoint().isSSL() && (!(bindAdapter->getSSLCtx())))
            {
                cout << "load server ssl error, no cert config!" << bindAdapter->getEndpoint().toString() << endl;
                exit(-1);
            }
#endif
            //创建异步线程组
            bindAdapter->setHandle<ServantHandle>(TC_Common::strto<int>(_conf.get(sLastPath + "<threads>", "1")), this);
            if(ServerConfig::ManualListen) 
            {
                bindAdapter->enableManualListen();
            }

            //监听
            _epollServer->bind(bindAdapter);
            adapters.push_back(bindAdapter);

            //属性上报实例
            if(!_communicator->getProperty("property").empty())
            {
                PropertyReportPtr p;
                p = _communicator->getStatReport()->createPropertyReport(bindAdapter->getName() + ".queue", PropertyReport::avg());
                bindAdapter->_pReportQueue = p.get();

                p = _communicator->getStatReport()->createPropertyReport(bindAdapter->getName() + ".connectRate", PropertyReport::avg());
                bindAdapter->_pReportConRate = p.get();

                p = _communicator->getStatReport()->createPropertyReport(bindAdapter->getName() + ".timeoutNum", PropertyReport::sum());
                bindAdapter->_pReportTimeoutNum = p.get();
            }
        }
    }
}
```
***备注：配置文件采用开始节点和结束节点代表一个Domain，每个节点，包括key-value形式的文本节点独占一行，为了美化，可以适当的缩进。<br>
但一个Server下不能有其他Domain节点，且servant需遵循带有前缀ApplicationName.ServerName，节点的顺序不强制要求***

<tars>
    <appliation>
        <server>
            key0 = value0
            <ApplicationName.ServerName.XXXXAdapter>
                endpoint = tcp 192.168.70.132 -p 8889 -t 3000
                key1 = value1
                servant = pplicationName.ServerName.XXXXObj
            </ApplicationName.ServerName.XXXXAdapter>
            <ApplicationName.ServerName.XXXX2Adapter>
                endpoint = tcp 192.168.70.132 -p 8899 -t 3000
                key2 = value2
                servant = pplicationName.ServerName.XXXX2Obj
            </ApplicationName.ServerName.XXXX2Adapter>
            key3 = value3
        </server>
    </appliation>
</tars>

以上流程跟管理服务的初始化类似，只是管理服务一般使用本机回环IP127.0.0.1，外部无法访问，安全性得以保证，<br/>但对外服务调用量大很多，因此额外设置了一些属性，但不设置也会由默认值。比如对外服务特意设置了对外连接数限制，队列大小限制，另外还额外需监控对外服务的健康度等。


这会基本完成必要的数据结构的初始化，此时Tars会回调initialize接口

应用开发可以Application继承自类中重载该回调函数，并在这个回调函数中进行一些应用层面的初始化操作，一般来说，initialize回调接口一般需要：

```
addServant<HelloServantImp>(ServerConfig::Application + "." + ServerConfig::ServerName + ".HelloServerObj");
```

addServant这一步是必然要调用的，不然客户端请求过来了，框架不知道分发到哪个服务提供者处理。

这一步实际上通过Obj名称绑定了一个Servant服务提供者，当客户端请求过来时，可以找到对应的BindAdapter，

由于之前初始化时完成了Adapter名称和Obj名称的映射，因此可以通过BindAdapter找到Obj名称，通过Obj名称能找到对应的服务提供者Servant。


对于非Tars协议的服务，则需要设置请求数据解析回调函数，例如Http服务，则可以校验一个Http请求数据包是否接收完成，请求数据格式是否满足http报文格式。

```
addServantProtocol(ServerConfig::Application + "." + ServerConfig::ServerName + ".HttpServantObj", &TC_NetWorkBuffer::parseHttp);
```

当然，应用也可以在这里初始一些应用特有的一些初始化操作，比如分配必要的内存等。


接下来，就是作一些额外的初始化，然后启动网络线程和业务处理线程等，开始对外提供服务。

```
void Application::waitForShutdown()
{
    //设置属性上报回调
    _epollServer->setCallbackFunctor(reportRspQueue);
    //设置心跳上报回调
    _epollServer->setHeartBeatFunctor(heartBeatFunc);
    _epollServer->waitForShutdown();
    //应用开发可以Application继承自类中重载该回调函数，并在这个回调函数中进行一些应用层面的释放字资源操作，
    destroyApp();
    RemoteNotify::getInstance()->report("stop");
	std::this_thread::sleep_for(std::chrono::milliseconds(100)); //稍微休息一下, 让当前处理包能够回复
}

void TC_EpollServer::waitForShutdown()
{
    //启动逻辑处理线程，如果合并网络线程和逻辑处理线程，则不需要run线程，仅仅当作一个普通业务处理类，分发客户端的情况，进行异步处理和相应
    if(!isMergeHandleNetThread())
        startHandle();

    //创建epoll，采用边缘触发
    createEpoll();

    //启动网络线程
    for (size_t i = 0; i < _netThreadNum; ++i)
    {
        _netThreads[i]->start();
    }

    int64_t iLastCheckTime = TNOWMS;
    while (!_bTerminate)
    {
        int iEvNum = _epoller.wait(300);

        if (_bTerminate)
            break;

        if(TNOWMS - iLastCheckTime > 1000) 
        {
            //在waitForShutdown线程(一般是主线程，当然也可以不是)中定时进行业务属性上报
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
                    //manualListen手工监听开启时，监听延迟到此时才进行
                    if (TC_Epoller::writeEvent(ev))
                    {
                        TC_Socket s;
                        s.init(fd, false);
                        s.listen(1024);
                    }

                    //监听端口有请求
                    if (TC_Epoller::readEvent(ev))
                    {
                        //接受外部连接请求
                        bool ret;
                        do
                        {
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

    //应用退出，释放资源
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

到目前，整个应用的启动流程基本简单过了一遍，但由于篇幅限制，不能过多展开细细探讨，在后续也继续细化。

现在再进行了一些细化流程补充，主要涉及日志初始化，属性上报，调用上报等。

- 本地循环日志初始化

```
LocalRollLogger::getInstance()->logger()->setLogLevel(ServerConfig::LogLevel);
define  LOG (LocalRollLogger::getInstance()->logger())
#define LOG_DEBUG LOG->debug() << FILE_FUNC_LINE << "|"
#define LOG_ERROR LOG->error() << FILE_FUNC_LINE << "|"
```

应用侧可直接调用，也可通过宏来调用
```
LocalRollLogger::getInstance()->logger()->debug() << "debug info" << endl;
LocalRollLogger::getInstance()->logger()->error() << "error info" << endl;
```

如果需要按日志打印级别过滤，则可以通过如果宏定义来调用
```
#define TLOGINFO(msg...)    LOGMSG(LocalRollLogger::INFO_LOG,msg)
#define TLOGDEBUG(msg...)   LOGMSG(LocalRollLogger::DEBUG_LOG,msg)
#define TLOGWARN(msg...)    LOGMSG(LocalRollLogger::WARN_LOG,msg)
#define TLOGERROR(msg...)   LOGMSG(LocalRollLogger::ERROR_LOG,msg)
#define TLOGTARS(msg...)    LOGMSG(LocalRollLogger::TARS_LOG,msg)
#define TLOG_INFO(msg...)    LOG_MSG(LocalRollLogger::INFO_LOG,msg)
#define TLOG_DEBUG(msg...)   LOG_MSG(LocalRollLogger::DEBUG_LOG,msg)
#define TLOG_WARN(msg...)    LOG_MSG(LocalRollLogger::WARN_LOG,msg)
#define TLOG_ERROR(msg...)   LOG_MSG(LocalRollLogger::ERROR_LOG,msg)
#define TLOG_TARS(msg...)    LOG_MSG(LocalRollLogger::TARS_LOG,msg)
```

- 远程日志初始化

```
//只要通信器初始化了，即可调用
RemoteTimeLogger::getInstance()->setLogInfo(_communicator, ServerConfig::Log, ServerConfig::Application, ServerConfig::ServerName, ServerConfig::LogPath, setDivision(), bLogStatReport);
```
远程日志开关
```
RemoteTimeLogger::getInstance()->enableRemote("", false);
/**
 *  按天日志局部使能开关，针对单个日志文件进行使能，请在所有按天日志输出前调用
 */
#define TENREMOTE_FDLOG(swith, sApp, sServer, sFile) (RemoteTimeLogger::getInstance()->enableRemoteEx(sApp, sServer, sFile, swith))
#define TENLOCAL_FDLOG(swith, sApp, sServer, sFile) (RemoteTimeLogger::getInstance()->enableLocalEx(sApp, sServer, sFile, swith))

/**
 * 按天日志全局使能开关，请在所有按天日志输出前调用
 */
#define TENREMOTE(swith) (RemoteTimeLogger::getInstance()->enableRemoteLog(swith))
#define TENLOCAL(swith) (RemoteTimeLogger::getInstance()->enableLocalLog(swith))
```
/**
 * 按天日志
 */
#define DLOG            (RemoteTimeLogger::getInstance()->logger()->any())
#define FDLOG(x)        (RemoteTimeLogger::getInstance()->logger(x)->any())
#define FFDLOG(x,y,z)   (RemoteTimeLogger::getInstance()->logger(x,y,z)->any())

- 初始化配置中心
```
//只要通信器初始化了，即可调用
RemoteConfig::getInstance()->setConfigInfo(_communicator, ServerConfig::Config, ServerConfig::Application, ServerConfig::ServerName, ServerConfig::BasePath,setDivision());
```

可通过web控制台远程下发配置文件，下发命令到到后，cmdLoadConfig是处理器，会向配置中心拉去远程配置文件。

```
bool Application::cmdLoadConfig(const string& command, const string& params, string& result)
```

应用侧还可以通过调用如下两个接口， 主动拉去远程配置文件

```
bool Application::addConfig(const string &filename)
{
    string result;
    if (RemoteConfig::getInstance()->addConfig(filename, result, false))
    {
        RemoteNotify::getInstance()->report(result);
        return true;
    }

    RemoteNotify::getInstance()->report(result);
    return true;
}

bool Application::addAppConfig(const string &filename)
{
    string result = "";
    // true-只获取应用级别配置
    if (RemoteConfig::getInstance()->addConfig(filename, result, true))
    {
        RemoteNotify::getInstance()->report(result);
        return true;
    }

    RemoteNotify::getInstance()->report(result);
    return true;
}

```

- 初始化消息中心

```
RemoteNotify::getInstance()->setNotifyInfo(_communicator, ServerConfig::Notify, ServerConfig::Application, ServerConfig::ServerName, setDivision(), ServerConfig::LocalIp);
```
应用侧可以通过下面的宏定义上报消息

```
/**
 * 通知信息给notify服务, 展示在页面上
 */
//上报普通信息
#define TARS_NOTIFY_NORMAL(info)     {RemoteNotify::getInstance()->notify(NOTIFYNORMAL, info);}

//上报警告信息
#define TARS_NOTIFY_WARN(info)       {RemoteNotify::getInstance()->notify(NOTIFYWARN, info);}

//上报错误信息
#define TARS_NOTIFY_ERROR(info)      {RemoteNotify::getInstance()->notify(NOTIFYERROR, info);}
```

这里没有进行频率限制，如果应用侧可能触发消息上报，建议在应用侧针对key维度进行限频后再上报。

- 注册管理命令

/**
 * 添加前置的命令处理方法
 * 在所有Normal方法之前执行
 * 多个前置方法之间顺序不确定
 */
#define TARS_ADD_ADMIN_CMD_PREFIX(c,f) \
    do { addAdminCommandPrefix(string(c), std::bind(&f, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3)); } while (0);

/**
 * 添加Normal命令处理方法
 * 在所有前置方法最后执行
 * 多个Normal方法之间顺序不确定
 */
#define TARS_ADD_ADMIN_CMD_NORMAL(c,f) \
    do { addAdminCommandNormal(string(c), std::bind(&f, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3)); } while (0);


//动态加载配置文件
TARS_ADD_ADMIN_CMD_PREFIX(TARS_CMD_LOAD_CONFIG, Application::cmdLoadConfig);

//动态设置滚动日志等级
TARS_ADD_ADMIN_CMD_PREFIX(TARS_CMD_SET_LOG_LEVEL, Application::cmdSetLogLevel);

//动态设置按天日志等级
TARS_ADD_ADMIN_CMD_PREFIX(TARS_CMD_SET_DAYLOG_LEVEL, Application::cmdEnableDayLog);

//查看服务状态
TARS_ADD_ADMIN_CMD_PREFIX(TARS_CMD_VIEW_STATUS, Application::cmdViewStatus);

//查看当前链接状态
TARS_ADD_ADMIN_CMD_PREFIX(TARS_CMD_CONNECTIONS, Application::cmdConnections);

//查看编译的TARS版本
TARS_ADD_ADMIN_CMD_PREFIX(TARS_CMD_VIEW_VERSION, Application::cmdViewVersion);

//查看服务buildid(编译时间）
TARS_ADD_ADMIN_CMD_PREFIX(TARS_CMD_VIEW_BID, Application::cmdViewBuildID);

//加载配置文件中的属性信息
TARS_ADD_ADMIN_CMD_PREFIX(TARS_CMD_LOAD_PROPERTY, Application::cmdLoadProperty);

//查看服务支持的管理命令
TARS_ADD_ADMIN_CMD_PREFIX(TARS_CMD_VIEW_ADMIN_COMMANDS, Application::cmdViewAdminCommands);

//设置染色信息
TARS_ADD_ADMIN_CMD_PREFIX(TARS_CMD_SET_DYEING, Application::cmdSetDyeing);

//设置服务的core limit
TARS_ADD_ADMIN_CMD_PREFIX(TARS_CMD_CLOSE_CORE, Application::cmdCloseCoreDump);

//设置是否标准输出
TARS_ADD_ADMIN_CMD_PREFIX(TARS_CMD_CLOSE_COUT, Application::cmdCloseCout);

//设置是否标准输出
TARS_ADD_ADMIN_CMD_PREFIX(TARS_CMD_RELOAD_LOCATOR, Application::cmdReloadLocator);

//设置是否标准输出
TARS_ADD_ADMIN_CMD_PREFIX(TARS_CMD_RESOURCE, Application::cmdViewResource);

管理服务在收到管理命令后，会进行发放处理

```
string AdminServant::notify(const string &command, CurrentPtr current)
{
    RemoteNotify::getInstance()->report("AdminServant::notify:" + command);
    return this->getApplication()->getNotifyObserver()->notify(command, current);
}
```

应用侧可调用TARS_ADD_ADMIN_CMD_PREFIX和TARS_ADD_ADMIN_CMD_NORMAL注册自己的管理命令，建议应用侧使用TARS_ADD_ADMIN_CMD_NORMAL就够了。


到目前为止，整体流程基本都涉及到了，基本还是先解析配置文件获取配置参数，初始化必要的数据结构，监听网络，最后启动线程对外提供服务。

不过，Tars还有很多细节值得细细研究，期待进一步探讨。







