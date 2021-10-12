package com.xiexin.shirotest;

import org.apache.shiro.crypto.hash.Md5Hash;
import org.junit.jupiter.api.Test;

/*
*  Shiro 的加密 和 认证 测试
* */
public class MyShiro {
    // shiro 有对 明文密码  12345  有加密的功能 让web的密码更安全
    //md5 加密，，， 简单， 但是  不可逆  但是可以 根据 加密后的密码  进行 反推！！！
    // 更加的 安全  就需要加盐！！！  salt

    @Test
    public void testCmd5(){
        Md5Hash md5Hash = new Md5Hash("123456");
        System.out.println("md5Hash = " + md5Hash);

        // 给密码加盐  更安全了
        Md5Hash md5Hash1 = new Md5Hash("123456","lalla");  // 社工  大数据！！！
        System.out.println("md5Hash1 = " + md5Hash1);

        // 给加盐后的 密码  进行  散列处理
        Md5Hash md5Hash2 = new Md5Hash("123456","lalla",1024);
        System.out.println("md5Hash2 = " + md5Hash2);

        Md5Hash md5Hash3 = new Md5Hash("123456","MGH7kU1(",1024);
        System.out.println("md5Hash3 = " + md5Hash3);
    }
}
