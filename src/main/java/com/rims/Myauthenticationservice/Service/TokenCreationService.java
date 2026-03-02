package com.rims.Myauthenticationservice.Service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.rims.Myauthenticationservice.Entity.RefreshToken;
import com.rims.Myauthenticationservice.Repository.RefreshTokenRepository;

@Service
public class TokenCreationService {

    @Autowired
    private RefreshTokenRepository repo;

    public TokenCreationService(RefreshTokenRepository repo){
        this.repo = repo;
    }

    public RefreshToken SaveREfreshToken(String generatedRefreshToken)
    {
        RefreshToken tokenTobeSaved = new RefreshToken();
        tokenTobeSaved.setrToken(generatedRefreshToken);
        tokenTobeSaved.setIsExpired(false);
        return repo.save(tokenTobeSaved);
    }
    public void ExpireToken(String refreshToken){
        RefreshToken tokenTobeExpired = repo.findByrToken(refreshToken).get();
        tokenTobeExpired.setIsExpired(true);
    }
}
