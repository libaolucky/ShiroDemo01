package com.xiexin;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

// springboot 项目是为了 简化 ssm 项目而存在的
// ssm 项目配置比较 繁琐， 比如， 需要配置 tomcat , 需要很多个xml, 去配置 第三方依赖
// 而  springboot 简化成 ，该内置的就内置，  多个 xml 配置 改成 一个 propertites / xml 文件
// 说白了 还是ssm ！！！  只不过写起来简单了
@SpringBootApplication   // springboot 应用注解， 标记本项目是 springboot项目，必须有这个注解
@MapperScan("com.xiexin.dao")   // 持久层的dao包 扫描
public class SmartfoodApplication {
        // main方法， 项目一启动 就会执行 该方法
    public static void main(String[] args) {
        // 静态的调用  SpringApplication 应用， 参数为 本项目的 启动类
        System.out.println(" springboot 项目  我启动了");
        SpringApplication.run(SmartfoodApplication.class, args);
    }


}
