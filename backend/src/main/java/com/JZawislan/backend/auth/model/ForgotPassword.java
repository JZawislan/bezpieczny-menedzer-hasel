package com.JZawislan.backend.auth.model;

import jakarta.persistence.*;
import lombok.*;

import java.util.Date;

@Entity
@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
@Builder
public class ForgotPassword {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer fpid;

    @Column(nullable = false)
    private Integer otp; //jednorazowy kod
    @Column(nullable = false)
    private Date expiration;

    @OneToOne
    private AppUser appUser;

}
