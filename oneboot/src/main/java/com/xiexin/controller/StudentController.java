package com.xiexin.controller;

import com.github.pagehelper.PageHelper;
import com.github.pagehelper.PageInfo;
import com.xiexin.bean.Student;
import com.xiexin.bean.StudentExample;
import com.xiexin.respcode.Result;
import com.xiexin.service.StudentService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/student")
public class StudentController {
    @Autowired
    private StudentService studentService;


    //全查  注意 不用 map  公司中 都用 一个类， 好几个类组成的类， 叫做 统一响应类， 每个公司都不一样
    @RequestMapping("/selectAll")    //   /student/selectAll
    public Result selectALL(){

        List<Student> students = studentService.selectByExample(null);
        //Result result = new Result(students);
        //return result;  或

        return new Result(students);//匿名内部类
    }

    //分页查询   带参数的+分页查询
    @RequestMapping("/selectAllByPage")  //  /student/selectAllByPage
    public Result selectAllByPage(Student student,@RequestParam(value = "page",defaultValue = "1",required = true) Integer page,
                                  @RequestParam(value = "limit",defaultValue = "5",required = true)Integer limit){
        System.out.println("student = " + student);
        StudentExample example=new StudentExample();
        StudentExample.Criteria criteria = example.createCriteria();

        // 使用  paghelper 分页
        PageHelper.startPage(page,limit);
        if(null!=student.getStudentSex() && !"".equals(student.getStudentSex())){
            criteria.andStudentSexEqualTo(student.getStudentSex());
        }
        if(null!=student.getStudentName() && !"".equals(student.getStudentName())){
            criteria.andStudentNameEqualTo(student.getStudentName());
        }
        List<Student> students = studentService.selectByExample(example);
        PageInfo pageInfo=new PageInfo(students);
        Result result=new Result(pageInfo);
        return result;
    }
}
