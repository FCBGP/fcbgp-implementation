# README

> **Author**        Basil Guo
>
> **Date**          Sep. 02, 2024
>
> **Description**   

[TOC]

netconf的测试，这个测试比较别扭。

首先，将router的ip地址（config.json中写的就是）配置到本地。

然后，启动libnetconf2的server。它的启动方式是在build/examples/server下直接启动即可。它使用的配置文件在源码examples下，需要修改其中的端口和host，一般改地址为::，端口为830即可。

然后，启动FCServer。

然后，发送topo信息，可以使用test/fcs-test/bin/client，它需要绑定一个地址，这个地址就是第一步中配置的地址，不过应该使用ipv6更好一些。

这时候就可以启动正常的BGP流程了。


