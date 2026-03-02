package com.rims.Myauthenticationservice.Repository;

import com.rims.Myauthenticationservice.Entity.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.List;
import java.util.Optional;


@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken,Long>{
    public Optional<RefreshToken>  findByrToken(String rToken);
}
