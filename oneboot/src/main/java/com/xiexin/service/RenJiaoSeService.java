package com.xiexin.service;

import java.util.List;

import org.apache.ibatis.annotations.Param;

import com.xiexin.bean.RenJiaoSeExample;
import com.xiexin.bean.RenJiaoSe;

public interface RenJiaoSeService {
   
    long countByExample(RenJiaoSeExample example);

    int deleteByExample(RenJiaoSeExample example);

    int deleteByPrimaryKey(Integer id);

    int insert(RenJiaoSe record);

    int insertSelective(RenJiaoSe record);

    List<RenJiaoSe> selectByExample(RenJiaoSeExample example);

    RenJiaoSe selectByPrimaryKey(Integer id);
  
    int updateByExampleSelective(@Param("record") RenJiaoSe record, @Param("example") RenJiaoSeExample example);

    int updateByExample(@Param("record") RenJiaoSe record, @Param("example") RenJiaoSeExample example);

    int updateByPrimaryKeySelective(RenJiaoSe record);

    int updateByPrimaryKey(RenJiaoSe record);

}
