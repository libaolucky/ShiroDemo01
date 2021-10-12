package com.xiexin.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import com.xiexin.bean.JiaoSeExample;
import com.xiexin.bean.JiaoSe;
import com.xiexin.dao.JiaoSeDAO;
@Service("jiaoSeService")
public class JiaoSeServiceImpl implements JiaoSeService{
	@Autowired(required = false)
	private JiaoSeDAO jiaoSeDAO;
	public long countByExample(JiaoSeExample example){
    	return jiaoSeDAO.countByExample(example);
    }

	public int deleteByExample(JiaoSeExample example){
    	return jiaoSeDAO.deleteByExample(example);
    }

	public int deleteByPrimaryKey(Integer id){
    	return jiaoSeDAO.deleteByPrimaryKey(id);
    }

	public int insert(JiaoSe record){
    	return jiaoSeDAO.insert(record);
    }

	public int insertSelective(JiaoSe record){
    	return jiaoSeDAO.insertSelective(record);
    }

	public List<JiaoSe> selectByExample(JiaoSeExample example){
    	return jiaoSeDAO.selectByExample(example);
    }

	public JiaoSe selectByPrimaryKey(Integer id){
    	return jiaoSeDAO.selectByPrimaryKey(id);
    }
  
	public int updateByExampleSelective(JiaoSe record, JiaoSeExample example){
    	return jiaoSeDAO.updateByExampleSelective(record, example);
    }

	public int updateByExample(JiaoSe record, JiaoSeExample example){
    	return jiaoSeDAO.updateByExample(record, example);
    }

	public int updateByPrimaryKeySelective(JiaoSe record){
    	return jiaoSeDAO.updateByPrimaryKeySelective(record);
    }

	public int updateByPrimaryKey(JiaoSe record){
    	return jiaoSeDAO.updateByPrimaryKey(record);
    }


}
