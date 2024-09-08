package com.jwt.repository;

import com.jwt.model.Token;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface TokenRepository extends JpaRepository<Token,Integer> {
    @Query("select t from Token t " +
            "inner join User u on t.user.id=u.id " +
            "where t.user.id=:userId and t.loggedOut=false")
    List<Token> findAllAccessTokenByUser(Integer userId);

    Optional<Token> findByAccessToken(String token);

    Optional<Token> findByRefreshToken(String token);
}
