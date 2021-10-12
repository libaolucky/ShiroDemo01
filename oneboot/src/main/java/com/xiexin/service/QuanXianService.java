package com.xiexin.service;

import java.util.List;

import org.apache.ibatis.annotations.Param;

import com.xiexin.bean.QuanXianExample;
import com.xiexin.bean.QuanXian;

public interface QuanXianService {
   
    long countByExample(QuanXianExample example);

    int deleteByExample(QuanXianExample example);

    int deleteByPrimaryKey(Integer id);

    int insert(QuanXian record);

    int insertSelective(QuanXian record);

    List<QuanXian> selectByExample(QuanXianExample example);

    QuanXian selectByPrimaryKey(Integer id);
  
    int updateByExampleSelective(@Param("record") QuanXian record, @Param("example") QuanXianExample example);

    int updateByExample(@Param("record") QuanXian record, @Param("example") QuanXianExample example);

    int updateByPrimaryKeySelective(QuanXian record);

    int updateByPrimaryKey(QuanXian record);

}
