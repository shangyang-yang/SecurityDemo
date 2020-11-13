package com.atguigu.sercurity.sercurity;


import io.jsonwebtoken.CompressionCodecs;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.stereotype.Component;

import java.util.Date;

/**
 * @author shangyangyang
 */
@Component
public class TokenManager {
    /**
     * token的有效时长
     */
    private long tokenEcpiration=24*60*60*1000;
    /**
     * 编码密钥
     */
    private String toKenSignKey="123456";

    /**
     * 使用jwt根据用户名生成token
     */
    public String createToken(String username){
        String token= Jwts.builder().setSubject(username).setExpiration(new Date(System.currentTimeMillis()+tokenEcpiration))
                            .signWith(SignatureAlgorithm.HS512,toKenSignKey).compressWith(CompressionCodecs.GZIP).compact();

        return token;
    }


    /**
     * 根据token字符串得到用户信息
     */
    public String getUserInfoFromToken(String token){
        try {
            String userinfo = Jwts.parser().setSigningKey(toKenSignKey).parseClaimsJws(token).getBody().getSubject();
            return userinfo;
        }catch (Exception e){
            return "解析token失败";
        }

    }

    /**
     * 删除token方法
     */
    public void removeToken(String toKen){

    }
}
