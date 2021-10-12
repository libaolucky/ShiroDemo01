package com.xiexin.shirotest;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.realm.text.IniRealm;
import org.apache.shiro.subject.Subject;
import org.junit.jupiter.api.Test;

/*
*  shiro 的认证
*    shiro 最重要的三个： subject(用户的请求,主体) , security Manager（shiro的管理类） , realms (数据库)
*    realms 分为：  ini realm,  自定义的 realm---常用自定义（mybatis...）
*
* */
public class ShiroIni {

    @Test
    public void tets01(){
            // 1. realms
        IniRealm iniRealm = new IniRealm("classpath:shiro.ini");  // 创建出一堆仙女
        //2. security Manager
        DefaultSecurityManager sm = new DefaultSecurityManager();  // 创建  管理仙女的们的 管理者 媒婆
        sm.setRealm(iniRealm);   // 用 set 注入 媒婆 把仙女们  注入到 媒婆家里
        // 以上步骤 是把  realms 注入到了 sm当中， 即 把他们联系在一起，下面就剩一个 subject
        // subject 不是 new 出来的！！！！ 因为 subject 是一个  实打实的对象， 原本就有的
        // 只需用用  shiro的类 做个 接待就可以了   SecurityUtils 安全管理中心  依赖了 security Manager（安全管理者）
        // SecurityUtils 安全管理中心   这个依赖于 security Manager  安全管理者   相当于 相亲广场  依赖于 媒婆
        SecurityUtils.setSecurityManager(sm);  // 接管 sm  用set
        Subject subject = SecurityUtils.getSubject();  // 可以直接 用 subject

        // 就可以使用  subject
        // 拟定一个 虚拟的 账户名和密码
        String username="xiexin";
        String userPwd="123";

        // 在这里 利用 shiro 把 username 和 userpwd 变成一个 Token
        UsernamePasswordToken  usernamePasswordToken=new UsernamePasswordToken(username,userPwd);    // 把 明语  改成 暗号  变成token
        System.out.println("顾客登录的时候把账户名和密码进行 加工后的token  " + usernamePasswordToken);  //前端输入的token

        UsernamePasswordToken  dbToken=new UsernamePasswordToken("xiexin","123");
        System.out.println("数据库中 把账户名和密码  加工后的 token = " + dbToken);  // getPrincipal()  拿的是主体

        //subject.login(usernamePasswordToken); // 注意 ：这个登录的方法是 shiro提供的 ，以后我们不写登录！！！
        // Authentication  认证  Authorization  授权
        // Token 是 用户名和密码加密后的  字符串

        // 调用 getPassword()时候， IncorrectCredentialsException  这是 密码错误
        // UnknownAccountException  账户错误

        try {
            subject.login(usernamePasswordToken);
            System.out.println("登录成功");
        }catch (UnknownAccountException e){
            System.out.println("账户名不对");
            e.printStackTrace();
        }
        catch (IncorrectCredentialsException e){
            System.out.println("密码错误");
            e.printStackTrace();
        }


    }


}
