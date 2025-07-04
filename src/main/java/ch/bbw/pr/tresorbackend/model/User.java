package ch.bbw.pr.tresorbackend.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * User
 * @author Peter Rutschmann
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "user")
public class User {
   @Id
   @GeneratedValue(strategy = GenerationType.IDENTITY)
   private Long id;

   @Column(nullable = false, name="first_name")
   private String firstName;

   @Column(nullable = false, name="last_name")
   private String lastName;

   @Column(nullable = false, unique = true)
   private String email;

   @Column(nullable = false)
   private String password;

   @Column(nullable = false, name = "encryption_salt")
   private String encryptionSalt;

   @Column(nullable = false, name="password_salt")
   private String passwordSalt;

   @Column(nullable = false)
   private String role; // z.B. "USER" oder "ADMIN"

   @Column(name = "provider")
   private String provider; // z.B. "google"

   @Column(name = "provider_id")
   private String providerId; // z.B. Google-Sub-ID
}