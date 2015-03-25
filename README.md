* 插件地址：[regex_revalidate_for_trafficserver](https://github.com/acache/regex_revalidate_for_trafficserver)    

改造trafficserver的正则刷新插件，支持traffic_line -x reload配置,修复小bug

* 团队介绍：[stateam团队站点](http://www.stateam.net) - [www.stateam.net](http://www.stateam.net)   
* 公司介绍：广州可道技术

* 参考：[社区刷新插件](https://github.com/apache/trafficserver/tree/master/plugins/experimental/regex_revalidate) ，[4399运维军团博文](http://www.ywjt.org/index.php/archives/883)

>    缘起：社区刷新插件没有实现-x reload配置的功能；社区正则刷新插件的bug：在源站文件没更新的情况下刷新文件/目录的话cache会一直回源该文件/目录。

####编译
    tsxs -c revalidate.c -o revalidate.so
    
####配置
在plugin.config中添加

    revalidate.so

####使用
在/sysconfig目录下创建revalidate.conf
给权限

    chmod 666 /sysconfig/revalidate.conf

在需要刷新的时候添加配置（与社区版本有差异，只需要写进去正则）

    http://www.coedao.com/pic
    http://www.coedao.com/img

执行

    traffic_line -x
