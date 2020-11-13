package com.atguigu.sercurity.config;

import com.atguigu.sercurity.filter.TokenLoginFilter;
import com.atguigu.sercurity.sercurity.DefaultPasswordEncoder;
import com.atguigu.sercurity.sercurity.TokenLogoutHandler;
import com.atguigu.sercurity.sercurity.TokenManager;
import com.atguigu.sercurity.sercurity.UnauthorizedEntryPoint;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;


@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
@Configuration
public class TokenWebSecurityConfig extends WebSecurityConfigurerAdapter {
    private TokenManager tokenManager;
    private RedisTemplate redisTemplate;
    private DefaultPasswordEncoder defaultPasswordEncoder;
    private UserDetailsService userDetailsService;


    @Autowired
    public TokenWebSecurityConfig(UserDetailsService userDetailsService,DefaultPasswordEncoder defaultPasswordEncoder,TokenManager tokenManager,RedisTemplate redisTemplate){
        this.tokenManager=tokenManager;
        this.redisTemplate=redisTemplate;
        this.defaultPasswordEncoder=defaultPasswordEncoder;
        this.userDetailsService=userDetailsService;
  }
    /**
     * 配置设置
     */
    //设置退出的地址和 token，redis 操作地址
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.exceptionHandling()
                .authenticationEntryPoint(new UnauthorizedEntryPoint())//没有权限访问
                .and().csrf().disable()
                .authorizeRequests()
                .anyRequest().authenticated()
                .and().logout().logoutUrl("/admin/acl/index/logout")//退出路径
                .addLogoutHandler(new
                        TokenLogoutHandler(tokenManager,redisTemplate)).and()
                .addFilter(new TokenLoginFilter(authenticationManager(),
                        redisTemplate,tokenManager))
                .addFilter(new
                        TokenLoginFilter(authenticationManager(), redisTemplate,
                        tokenManager)).httpBasic();
    }

    /**
     * 配置调用userDetailservice和密码处理
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService).passwordEncoder(defaultPasswordEncoder);
    }

    /**
     * 不进行认证的路径 可以直接访问
     */
    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers("/api/**");
    }
}
