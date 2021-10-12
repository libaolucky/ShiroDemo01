package com.xiexin.shiro;

import com.xiexin.bean.Admin;
import com.xiexin.bean.AdminExample;
import com.xiexin.service.AdminService;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.List;

/*
*  自定义的 和 mybatis 数据库  结合的 realm
*
*   realm 中， 包含  认证（登录） 和 授权  两个部分
*    登录 为啥要继承 授权的 reaml  有 授权就一定是登录过了！
* */
public class MyBatisRealm extends AuthorizingRealm {
    @Autowired
   private AdminService adminService;
    // 授权
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
        return null;
    }

    // 认证（登录）
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
        //AuthenticationToken 这个参数是啥？  其实就是  UsernamePasswordToken("账户"，“密码)
        String account= (String) authenticationToken.getPrincipal();
        // 拿到账户名后，  能拿到  数据库的 密码
        // 单表的查询
        AdminExample example=new AdminExample();
        AdminExample.Criteria criteria = example.createCriteria();
        criteria.andAdminAccountEqualTo(account);
        List<Admin> admins = adminService.selectByExample(example);
        Admin dbadmin=null;
        if(admins!=null && admins.size()>0){
             dbadmin=admins.get(0);
             // 获取 密码
            String pwd=dbadmin.getAdminPwd();
            System.out.println("pwd = " + pwd);
            String salt= dbadmin.getSalt();
            System.out.println("salt = " + salt);

            //进行 token 认证
            SimpleAuthenticationInfo simpleAuthenticationInfo = new SimpleAuthenticationInfo(account, pwd, ByteSource.Util.bytes(salt),this.getName());
            System.out.println("ByteSource.Util.bytes(salt) = " + ByteSource.Util.bytes(salt));
                return simpleAuthenticationInfo;
        }
        return null;
    }
}
