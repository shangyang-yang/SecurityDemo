package com.atguigu.aclservice.service.impl;

import com.atguigu.aclservice.entity.User;
import com.atguigu.aclservice.service.PermissionService;
import com.atguigu.aclservice.service.UserService;
import com.atguigu.sercurity.entity.SecurityUser;
import org.springframework.beans.BeanUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * @author shangyangyang
 */
@Service("userDetailsService")
public class UserDetailsServiceImpl implements UserDetailsService {

    @Autowired
    private UserService userService;
    @Autowired
    private PermissionService permissionService;

    @Override
    public UserDetails loadUserByUsername(String s) throws UsernameNotFoundException {
        User user = userService.selectByUsername(s);
        //判断
        if(user==null){
            throw new UsernameNotFoundException("用户不存在");
        }
        com.atguigu.sercurity.entity.User curUser=new com.atguigu.sercurity.entity.User();
        BeanUtils.copyProperties(user,curUser);
        //根据用户信息查询出权限的列表信息
        List<String> permissionValueList = permissionService.selectPermissionValueByUserId(user.getId());
        SecurityUser securityUser=new SecurityUser();
        securityUser.setPermissionValueList(permissionValueList);
        return securityUser;
    }

}
