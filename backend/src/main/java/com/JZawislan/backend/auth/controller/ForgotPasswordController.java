package com.JZawislan.backend.auth.controller;

import com.JZawislan.backend.auth.dto.ChangePassword;
import com.JZawislan.backend.auth.dto.MailBody;
import com.JZawislan.backend.auth.model.AppUser;
import com.JZawislan.backend.auth.model.ForgotPassword;
import com.JZawislan.backend.auth.repository.AppUserRepository;
import com.JZawislan.backend.auth.repository.ForgotPasswordRepository;
import com.JZawislan.backend.auth.service.EmailService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.parameters.P;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.Date;
import java.util.Objects;
import java.util.Random;

@RestController
@RequestMapping("/api/auth/forgot-password")
public class ForgotPasswordController {

    private final AppUserRepository userRepository;
    private final EmailService emailService;
    private final ForgotPasswordRepository forgotPasswordRepository;
    private final PasswordEncoder passwordEncoder;

    public ForgotPasswordController(AppUserRepository userRepository, EmailService emailService, ForgotPasswordRepository forgotPasswordRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.emailService = emailService;
        this.forgotPasswordRepository = forgotPasswordRepository;
        this.passwordEncoder = passwordEncoder;
    }

    // send mail for email verification
    @PostMapping("/verifyMail/{email}")
    public ResponseEntity<String> verifyEmail(@PathVariable String email) {
        AppUser user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("Wprowadź poprawny adres e-mail"));

        int otp = otpGenerator();
        MailBody mailBody = MailBody.builder()
                .to(email)
                .text("Kod do zresetowania hasła : " + otp)
                .subject("Resetowanie hasła - BSK Menedżer")
                .build();
        ForgotPassword forgotPassword = ForgotPassword.builder()
                .otp(otp)
                .expiration(new Date(System.currentTimeMillis() + 15 * 60 * 1000)) // OTP ważne przez 15 minut
                .appUser(user)
                .build();
        emailService.sendSimpleMessage(mailBody);
        forgotPasswordRepository.save(forgotPassword);

        return ResponseEntity.ok("Email został wysłany do weryfikacji");
    }

    @PostMapping("/verifyOtp/{otp}/{email}")
    public ResponseEntity<String> verifyOtp(@PathVariable Integer otp,@PathVariable String email) {
        AppUser user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("Wprowadź poprawny adres e-mail"));
         ForgotPassword forgotPassword = forgotPasswordRepository.findByOtpAndAppUser(otp, user)
                .orElseThrow(() ->new RuntimeException("Nieprawidłowy kod OTP dla e-maila: " + email));
         if(forgotPassword.getExpiration().before(Date.from(Instant.now()))) {
             forgotPasswordRepository.deleteById(forgotPassword.getFpid());
             return new ResponseEntity<>("OTP wygasło! ", HttpStatus.EXPECTATION_FAILED);
         }

         return ResponseEntity.ok("OTP jest poprawny! Możesz teraz zresetować swoje hasło.");
    }
    @PostMapping("/changePassword/{email}")
    public ResponseEntity<String> changePasswordHandler(@RequestBody ChangePassword changePassword, @PathVariable String email) {
        if(!Objects.equals(changePassword.password(), changePassword.repeatPassoword())){
            return new ResponseEntity<>("Hasła nie są takie same!", HttpStatus.BAD_REQUEST);
        }
        String encodedPassword = passwordEncoder.encode(changePassword.password());
        userRepository.updatePassword(email, encodedPassword);

        return ResponseEntity.ok("Hasło zostało zresetowane pomyślnie!");

    }

    private Integer otpGenerator(){
        Random random = new Random();
        return random.nextInt(100_000,999_999);
    }
}
