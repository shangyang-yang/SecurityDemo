package com.atguigu.sercurity.sercurity;

import com.atguigu.utils.utils.R;
import com.atguigu.utils.utils.ResponseUtil;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * @author shangyangyang
 * 退出处理器
 */
public class TokenLogoutHandler implements LogoutHandler {

    private TokenManager tokenManager;

    private RedisTemplate redisTemplate;

    public TokenLogoutHandler(TokenManager tokenManager,RedisTemplate redisTemplate){
        this.redisTemplate=redisTemplate;
        this.tokenManager=tokenManager;
    }

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        //1.从handler里面获取到token
        String token = request.getHeader("token");
        //2 token不为空 移除token 从redis删除token
        if(token!=null){
            //移除
            tokenManager.removeToken(token);
            //从token获取用户名
            String userInfo = tokenManager.getUserInfoFromToken(token);
            redisTemplate.delete(userInfo);

        }
        ResponseUtil.out(response, R.ok());
    }
}
