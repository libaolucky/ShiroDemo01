package com.xiexin.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

// 热部署 快捷键  ctrl+f9
@Controller
public class IndexController {
    @RequestMapping({"/index","/"})  // 映射多个 html
    public String index(){
        return "index";
    }

}
