package com.rims.Myauthenticationservice.Security;


import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import com.rims.Myauthenticationservice.Entity.RefreshToken;
import com.rims.Myauthenticationservice.Repository.RefreshTokenRepository;
import com.rims.Myauthenticationservice.Service.TokenCreationService;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.time.Instant;
import java.util.Date;
import java.util.Map;


@Service
public class JwtService {
    private final Key key;
    private final long expMinutes;
    private final Key keyforCreatingRefrehToken;
    private final long expMinutesOfRefreshToken;

    @Autowired
    private RefreshTokenRepository repo; 
    @Autowired
    private TokenCreationService tcs;
    private static final Logger log =
        LoggerFactory.getLogger(JwtService.class);
    public JwtService(@Value("${app.jwt.secret}") String secret,
                      @Value("${app.jwt.exp-minutes}") long expMinutes,
                      @Value("${app.jwt.refresh.secret}") String secretForRefreshToken,
                      @Value("${app.jwt.refresh.exp-minutes}") long expMinutesOfRefreshToken ) {
        log.info("JwtService constructor called");
        log.info("Access exp minutes = {}", expMinutes);
        log.info("Refresh exp minutes = {}", expMinutesOfRefreshToken);
        System.out.println("ACCESS SECRET LENGTH = " + secret.length());
        System.out.println("REFRESH SECRET LENGTH = " + secretForRefreshToken.length());
        this.key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        this.expMinutes = expMinutes;
        this.keyforCreatingRefrehToken = Keys.hmacShaKeyFor(secretForRefreshToken.getBytes(StandardCharsets.UTF_8));
        this.expMinutesOfRefreshToken = expMinutesOfRefreshToken;
    }

    public String generateToken(UserDetails userDetails) {
         log.info("\n"+"generateAccessToken() called"+"\n");
        Instant now = Instant.now();
        return Jwts.builder()
                .setSubject(userDetails.getUsername())
                .addClaims(Map.of("roles", userDetails.getAuthorities().stream().map(a->a.getAuthority()).toList()))
                .setIssuedAt(Date.from(now))
                .setExpiration(Date.from(now.plusSeconds(expMinutes * 60)))
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }
    public String generateRefreshToken(UserDetails userDetails) {
        Instant now = Instant.now();
        String refreshToken =  Jwts.builder()
                .setSubject(userDetails.getUsername())
                .addClaims(Map.of("roles", userDetails.getAuthorities().stream().map(a->a.getAuthority()).toList()))
                .setIssuedAt(Date.from(now))
                .setExpiration(Date.from(now.plusSeconds(expMinutesOfRefreshToken * 60)))
                .signWith(keyforCreatingRefrehToken, SignatureAlgorithm.HS256)
                .compact();
        RefreshToken rf =  tcs.SaveREfreshToken(refreshToken);         
        return refreshToken;
    }

    public String extractUsername(String token) {
        return parse(token).getBody().getSubject();
    }

    public boolean isTokenValid(String token, UserDetails userDetails) {
        try {
            var claims = parse(token).getBody();
            return userDetails.getUsername().equals(claims.getSubject()) &&
                   claims.getExpiration().after(new Date());
        } catch (JwtException | IllegalArgumentException ex) {
            return false;
        }
    }

    public boolean isTRefreshokenValid(String Refreshtoken, UserDetails userDetails) {
        try {
            var claims = parseRtoken(Refreshtoken).getBody();
            //Boolean isRefreshTokenExpired = repo.findByrToken(Refreshtoken).get().getIsExpired();
            //if the token is expired by jwts then set the token as expired in db also
            if(claims.getExpiration().after(new Date())){
                tcs.ExpireToken(Refreshtoken);
            }
            return userDetails.getUsername().equals(claims.getSubject()) 
                    && claims.getExpiration().after(new Date());
        } catch (JwtException | IllegalArgumentException ex) {
            return false;
        }
    }

    private Jws<Claims> parse(String token) {
        return Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
    }
    private Jws<Claims> parseRtoken(String Refreshtoken) {
        return Jwts.parserBuilder().setSigningKey(keyforCreatingRefrehToken).build().parseClaimsJws(Refreshtoken);
    }
    
}
