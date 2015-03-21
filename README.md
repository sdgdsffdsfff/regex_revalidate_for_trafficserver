# regex_revalidate_for_trafficserver
trafficserver的正则刷新插件，支持traffic_line -x reload配置
----

[stateam团队站点](http://www.stateam.net) - [www.stateam.net](http://www.stateam.net)

参考：[社区刷新插件](https://github.com/apache/trafficserver/tree/master/plugins/experimental/regex_revalidate) ，[运维团结博文](http://www.ywjt.org/index.php/archives/883)

缘起：社区刷新插件没有实现-x reload配置的功能。

####编译
    tsxs -c revalidate.c -o revalidate.so
    
####配置
在plugin.config中添加
    revalidate.so

####使用
在/sysconfig目录下创建revalidate.conf
给权限
    chmod 666 /sysconfig/revalidate.conf
在需要刷新的时候添加配置

    http://www.coedao.com/pic
    http://www.coedao.com/img

执行
    traffic_line -x
####另外
