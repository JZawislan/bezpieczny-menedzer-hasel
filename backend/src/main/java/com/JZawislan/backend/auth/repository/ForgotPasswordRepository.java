package com.JZawislan.backend.auth.repository;

import com.JZawislan.backend.auth.model.AppUser;
import com.JZawislan.backend.auth.model.ForgotPassword;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;

import java.util.Optional;

public interface ForgotPasswordRepository extends JpaRepository<ForgotPassword, Integer> {

    @Query("select fp from ForgotPassword fp where fp.otp = ?1 and fp.appUser = ?2")
    Optional<ForgotPassword> findByOtpAndAppUser(Integer otp, AppUser appUser);
}
