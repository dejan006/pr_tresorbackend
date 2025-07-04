package ch.bbw.pr.tresorbackend.controller;

import ch.bbw.pr.tresorbackend.model.ConfigProperties;
import ch.bbw.pr.tresorbackend.model.EmailAdress;
import ch.bbw.pr.tresorbackend.model.RegisterUser;
import ch.bbw.pr.tresorbackend.model.User;
import ch.bbw.pr.tresorbackend.service.PasswordEncryptionService;
import ch.bbw.pr.tresorbackend.service.UserService;
import ch.bbw.pr.tresorbackend.util.HashUtil;
import ch.bbw.pr.tresorbackend.util.PasswordStrengthValidator;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import java.util.List;
import java.util.stream.Collectors;
import ch.bbw.pr.tresorbackend.service.CaptchaService;

/**
 * UserController
 * @author Peter Rutschmann
 */
@RestController
@AllArgsConstructor
@RequestMapping("api/users")
public class UserController {

   private UserService userService;
   private PasswordEncryptionService passwordService;
   private final ConfigProperties configProperties;
   private final CaptchaService captchaService;

   // Pepper aus application.properties file
   @Value("${app.security.pepper}")
   private String pepper;
   private static final Logger logger = LoggerFactory.getLogger(UserController.class);

   @Autowired
   public UserController(ConfigProperties configProperties, UserService userService,
                      PasswordEncryptionService passwordService, CaptchaService captchaService) {
      this.configProperties = configProperties;
      this.userService = userService;
      this.passwordService = passwordService;
      this.captchaService = captchaService;

   System.out.println("UserController.UserController: cross origin: " + configProperties.getOrigin());
   logger.info("UserController initialized: " + configProperties.getOrigin());
   logger.debug("UserController.UserController: Cross Origin Config: {}", configProperties.getOrigin());

   }

   // build create User REST API
   @CrossOrigin(origins = "${CROSS_ORIGIN}")
   @PostMapping
   public ResponseEntity<String> createUser(
         @Valid @RequestBody RegisterUser registerUser,
         BindingResult bindingResult) {

      // Input-Validation
      if (bindingResult.hasErrors()) {
         JsonArray arr = new JsonArray();
         bindingResult.getFieldErrors().forEach(fe ->
             arr.add(fe.getField() + ": " + fe.getDefaultMessage())
         );
         JsonObject err = new JsonObject();
         err.add("message", arr);
         return ResponseEntity
               .badRequest()
               .body(new Gson().toJson(err));
      }

      // Passwortstärke
      String clearPassword = registerUser.getPassword();
      if (!PasswordStrengthValidator.isValid(clearPassword)) {
         JsonObject err = new JsonObject();
         err.addProperty("message",
             "Passwort muss mindestens 8 Zeichen lang sein, "
             + "einen Gross- und Kleinbuchstaben, "
             + "eine Ziffer und ein Sonderzeichen enthalten.");
         return ResponseEntity
               .badRequest()
               .body(new Gson().toJson(err));
      }
      System.out.println("getCAPTCHA................................." + registerUser.getCaptcha());
      // Captcha
      String captchaToken = registerUser.getCaptcha();
         if (captchaToken == null || !captchaService.verifyCaptcha(captchaToken)) {
            JsonObject err = new JsonObject();
            err.addProperty("message", "Captcha Verifikation fehlgeschlagen. Bitte versuche es erneut.");
            return ResponseEntity.badRequest().body(new Gson().toJson(err));
         }
      System.out.println("Verifikation vom token"+ captchaService.verifyCaptcha(captchaToken));

      // Salt generieren für encryption
      String encryptionSalt = HashUtil.generateSalt();

      // Salt generieren für hashing
      String passwordSalt = HashUtil.generateSalt();

      // Passwort hashen
      String passwordHash;
      try {
         passwordHash = HashUtil.hashPassword(
               registerUser.getPassword(),
               passwordSalt,
               pepper
         );
      } catch (Exception e) {
         return ResponseEntity
               .status(HttpStatus.INTERNAL_SERVER_ERROR)
               .body("Error hashing password");
      }

      // Objekt user bauen + save
      User user = new User(
            null,
            registerUser.getFirstName(),
            registerUser.getLastName(),
            registerUser.getEmail(),
            passwordHash,        
            encryptionSalt,      
            passwordSalt,        
            "USER", // Standardrolle
            null,   // provider
            null    // providerId
      );
      userService.createUser(user);

      JsonObject resp = new JsonObject();
      resp.addProperty("answer", "User Saved");
      return ResponseEntity
            .status(HttpStatus.CREATED)
            .body(new Gson().toJson(resp));
   }
   @CrossOrigin(origins = "${CROSS_ORIGIN}")
   @GetMapping("{id}")
   public ResponseEntity<User> getUserById(@PathVariable("id") Long userId) {
      User user = userService.getUserById(userId);
      return new ResponseEntity<>(user, HttpStatus.OK);
   }
   @CrossOrigin(origins = "${CROSS_ORIGIN}")
   @GetMapping
   public ResponseEntity<List<User>> getAllUsers() {
      List<User> users = userService.getAllUsers();
      return new ResponseEntity<>(users, HttpStatus.OK);
   }
   @CrossOrigin(origins = "${CROSS_ORIGIN}")
   @PutMapping("{id}")
   public ResponseEntity<User> updateUser(@PathVariable("id") Long userId,
                                          @RequestBody User user) {
      user.setId(userId);
      User updatedUser = userService.updateUser(user);
      return new ResponseEntity<>(updatedUser, HttpStatus.OK);
   }
   @CrossOrigin(origins = "${CROSS_ORIGIN}")
   @DeleteMapping("{id}")
   public ResponseEntity<String> deleteUser(@PathVariable("id") Long userId) {
      userService.deleteUser(userId);
      return new ResponseEntity<>("User successfully deleted!", HttpStatus.OK);
   }

   @CrossOrigin(origins = "${CROSS_ORIGIN}")
   @PostMapping("/byemail")
   public ResponseEntity<String> getUserIdByEmail(@RequestBody EmailAdress email, BindingResult bindingResult) {
      System.out.println("UserController.getUserIdByEmail: " + email);
      //input validation
      if (bindingResult.hasErrors()) {
         List<String> errors = bindingResult.getFieldErrors().stream()
               .map(fieldError -> fieldError.getField() + ": " + fieldError.getDefaultMessage())
               .collect(Collectors.toList());
         System.out.println("UserController.createUser " + errors);

         JsonArray arr = new JsonArray();
         errors.forEach(arr::add);
         JsonObject obj = new JsonObject();
         obj.add("message", arr);
         String json = new Gson().toJson(obj);

         System.out.println("UserController.createUser, validation fails: " + json);
         return ResponseEntity.badRequest().body(json);
      }

      System.out.println("UserController.getUserIdByEmail: input validation passed");

      User user = userService.findByEmail(email.getEmail());
      if (user == null) {
         System.out.println("UserController.getUserIdByEmail, no user found with email: " + email);
         JsonObject obj = new JsonObject();
         obj.addProperty("message", "No user found with this email");
         String json = new Gson().toJson(obj);

         System.out.println("UserController.getUserIdByEmail, fails: " + json);
         return ResponseEntity.badRequest().body(json);
      }
      System.out.println("UserController.getUserIdByEmail, user find by email");
      JsonObject obj = new JsonObject();
      obj.addProperty("answer", user.getId());
      String json = new Gson().toJson(obj);
      System.out.println("UserController.getUserIdByEmail " + json);
      return ResponseEntity.accepted().body(json);
   }

}
