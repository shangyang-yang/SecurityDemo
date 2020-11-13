package com.atguigu.sercurity.filter;

import com.atguigu.sercurity.sercurity.TokenManager;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * @author 23596
 */
public class TokenAuthFilter extends BasicAuthenticationFilter {
    private TokenManager tokenManager;
    private RedisTemplate redisTemplate;

    public TokenAuthFilter(AuthenticationManager authenticationManager,TokenManager tokenManager, RedisTemplate redisTemplate) {
        super(authenticationManager);
        this.tokenManager=tokenManager;
        this.redisTemplate=redisTemplate;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        //获取当前认证成功的用户信息
        UsernamePasswordAuthenticationToken authRequest =getAuthentication(request);
        //如果说有权限信息 梵高权限上下文中
        if(authRequest!=null){
            SecurityContextHolder.getContext().setAuthentication(authRequest);
        }
        chain.doFilter(request,response);
    }

    private UsernamePasswordAuthenticationToken getAuthentication(HttpServletRequest request) {
        //从handler获取token
        String token = request.getHeader("token");
        if(token!=null){
            //token获取用户名
            String username = tokenManager.getUserInfoFromToken(token);
            //从redis种获取对应权限列表
            List<String> permissionValueList = (List) redisTemplate.opsForValue().get(username);

            Collection<GrantedAuthority> authority=new ArrayList<>();

            for(String permissionValue:permissionValueList){
                SimpleGrantedAuthority auth=new SimpleGrantedAuthority(permissionValue);
                authority.add(auth);
            }

            return new UsernamePasswordAuthenticationToken(username,token,authority);
        }
        return null;
    }
}
