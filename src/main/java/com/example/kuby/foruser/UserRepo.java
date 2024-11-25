package com.example.kuby.foruser;

import com.example.kuby.foruser.UserEntity;
import com.example.kuby.security.models.enums.Provider;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface UserRepo extends JpaRepository<UserEntity, UUID> {
    Optional<UserEntity> findByEmailAndProvider(String email, Provider provider);
     @Query("SELECT new com.example.kuby.foruser.UserCache(u.id, u.email, u.provider, u.roles, u.isEmailSubmitted) " +
            "FROM UserEntity u WHERE u.email = :email AND u.provider = :provider")
    Optional<UserCache> findUserCacheByEmailAndProvider(@Param("email") String email,
                                              @Param("provider") Provider provider);
    Boolean existsByEmailAndProvider(String email, Provider provider);
    Optional<UserEntity> findByProviderIdAndProvider(String ProviderId, Provider provider);
    @Modifying
    @Transactional
    @Query("UPDATE UserEntity u SET u.isEmailSubmitted = true WHERE u.email = :email AND u.provider = :provider")
    int updateIsEmailSubmittedByEmailAndProvider(@Param("email") String email, @Param("provider") Provider provider);
}
