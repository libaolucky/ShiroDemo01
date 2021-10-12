package com.xiexin.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/page")
public class PageController {

    @RequestMapping("/studentList")   //  /page/studentList
    public String studentList(){
        return "studentList";
    }

    @RequestMapping("/login")
    public String login(){
        return "login";
    }

    @RequestMapping("/LoginVue")
    public String LoginVue(){
        return "LoginVue";
    }


    @RequestMapping("/Regin")
    public String Regin(){
        return "Regin";
    }

    @RequestMapping("/RegSuccess")
    public String RegSuccess(){
        return "RegSuccess";
    }

}
