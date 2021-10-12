package com.xiexin.shiro;

import org.apache.shiro.authc.credential.HashedCredentialsMatcher;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.LinkedHashMap;
import java.util.Map;

/*
*  shiro 的web配置
*  目的： 因为shiro可以和很多项目 适配，  那么我们是 web项目，就需要配置成web的 SecurityManager
*   又因为是 web 项目， 所以 需要使用 过滤器来配置，  需要拦截的请求，和非拦截的请求
* */
@Configuration  // 配置类的注解， 表明该类是配置类， 该注解是配置的 意思，  顶替的是xml中的配置
                // 优先于 其他注解优先 执行
public class ShiroConfig {
    // 1. shiroconfig 需要指明 Realm 是谁，并且 把这个 realm创建出来， 这个创建指的是，优先于其他的 Controller,service等
    // 对象  优先创建
    @Bean
    public Realm getMybatisRealm() {
        MyBatisRealm realm = new MyBatisRealm();
        HashedCredentialsMatcher matcher = new HashedCredentialsMatcher();
        matcher.setHashAlgorithmName("md5");
        matcher.setHashIterations(1024);
        realm.setCredentialsMatcher(matcher);
        return realm;
        }

        //2. 指派 securityManager 因为我们是web项目，所以是  websecurityManager
            @Bean
        public DefaultWebSecurityManager getSecurityManager(Realm realm){
                DefaultWebSecurityManager sm=new DefaultWebSecurityManager();
                sm.setRealm(realm);
                return sm;
            }

            // 以上，就是 仙女和 媒婆就钩在一起了
            // 3. 剩男   subject 他需要 用过滤器来获取
            @Bean
        public ShiroFilterFactoryBean getFilter(DefaultWebSecurityManager sm){
             ShiroFilterFactoryBean shiroFilterFactoryBean=new ShiroFilterFactoryBean();
             shiroFilterFactoryBean.setSecurityManager(sm);

             // 使用过滤器
                Map map=new LinkedHashMap<>();  //这个map是有序的
                // 不拦截的页面！！
                map.put("/page/LoginVue","anon");  // anon  匿名的，任何请求都可以 去访问
                map.put("/page/login","anon");  // anon  匿名的，任何请求都可以 去访问
                map.put("/page/Regin","anon");  // anon  匿名的，任何请求都可以 去访问
                map.put("/admin/loginByShiro","anon");  //登录的方法不拦截
                map.put("/admin/Reg","anon");  //注册的方法不拦截
                map.put("/admin/login","anon");  //注册的方法不拦截
                map.put("/*/**","authc");  //authc 需要登录才可以

                // 把拦截的顺序放入到linkedMap 中！！
                shiroFilterFactoryBean.setFilterChainDefinitionMap(map);
                return shiroFilterFactoryBean;
            }

    }


