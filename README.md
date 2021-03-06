# TarsNote

记录剖析腾讯微服务Tars框架源代码的点滴。

## 目录

一般多线程网络应用的启动流程大体都遵循如下步骤：

- 加载参数和解析配置文件
- 初始化必要的数据结构、线程和网络资源
- 启动线程和开始接受处理外部请求

无独有偶，Tars应用启动流程也遵循如下步骤，因此也可以按照这个流程去窥探Tars的底层实现。

不过在开始这个旅程之前，需要进一步细化一些知识点出来，毕竟带着目标去学习，印象才会更深刻。

目前考虑到的知识点列表如下：

- [Tars应用启动流程](application_startup.md)
- [Tars连接管理逻辑](server_manage_connection.md)
- [Tars网络线程IO逻辑](server_netthread_io.md)
- [Tars服务器端逻辑](server_side_logic.md)
- [Tars网络数据缓冲TC_NetWorkBuffer](server_network_buffer.md)
- [Tars解析命令行参数](argument_parser.md)
- [Tars解析配置文件](configure_file_parser.md)
- [Tars的数据结构](struct_definition.md)
- [Tars的配置项](configure_option.md)
- [Tars服务端配置](server_side_configuration.md)
- [Tars通信器Communicator的初始化](communicator_initialize.md)
- [Tars的线程](threads.md)
- [Tars的客户端主动发起请求的处理流程](client_request_flow.md)
- [Tars的客户端处理服务端响应的处理流程](client_response_flow.md)
- [EndPoint配置](endpoint_configuration.md)
- [Tars SSL](tars_ssl.md)
- [Tars鉴权机制](auth.md)

以上知识点可以随时进一步细化，并深入研究，可以直接修改该列表，也可在具体知识点文档中细化。