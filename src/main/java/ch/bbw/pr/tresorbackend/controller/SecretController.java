package ch.bbw.pr.tresorbackend.controller;

import ch.bbw.pr.tresorbackend.model.Secret;
import ch.bbw.pr.tresorbackend.model.NewSecret;
import ch.bbw.pr.tresorbackend.model.EncryptCredentials;
import ch.bbw.pr.tresorbackend.model.User;
import ch.bbw.pr.tresorbackend.service.SecretService;
import ch.bbw.pr.tresorbackend.service.UserService;
import ch.bbw.pr.tresorbackend.util.EncryptUtil;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import javax.crypto.SecretKey;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

/**
 * SecretController
 * @author Peter Rutschmann
 */
@RestController
@AllArgsConstructor
@RequestMapping("api/secrets")
public class SecretController {

   private SecretService secretService;
   private UserService userService;

   // create secret REST API
   @CrossOrigin(origins = "${CROSS_ORIGIN}")
   @PostMapping
   public ResponseEntity<String> createSecret2(@Valid @RequestBody NewSecret newSecret, BindingResult bindingResult) {
      //input validation
      if (bindingResult.hasErrors()) {
         List<String> errors = bindingResult.getFieldErrors().stream()
               .map(fieldError -> fieldError.getField() + ": " + fieldError.getDefaultMessage())
               .collect(Collectors.toList());
         System.out.println("SecretController.createSecret " + errors);

         JsonArray arr = new JsonArray();
         errors.forEach(arr::add);
         JsonObject obj = new JsonObject();
         obj.add("message", arr);
         String json = new Gson().toJson(obj);

         System.out.println("SecretController.createSecret, validation fails: " + json);
         return ResponseEntity.badRequest().body(json);
      }
      System.out.println("SecretController.createSecret, input validation passed");

      User user = userService.findByEmail(newSecret.getEmail());
      // Salt und Key ableiten
      String salt = user.getEncryptionSalt();
      SecretKey key;
      try {
         key = EncryptUtil.createSecretKey(newSecret.getEncryptPassword(), salt);
      } catch (Exception e) {
         return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
               .body("Error deriving encryption key");
      }

      // JSON serialisieren und verschlüsseln
      String plainJson = newSecret.getContent().toString();
      String encrypted;
      try {
         encrypted = EncryptUtil.encrypt(plainJson, key);
      } catch (Exception e) {
         return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
               .body("Error encrypting content");
      }

      // Secret speichern
      Secret secret = new Secret(null, user.getId(), encrypted);
      secretService.createSecret(secret);
      System.out.println("SecretController.createSecret, secret saved in db");

      JsonObject obj = new JsonObject();
      obj.addProperty("answer", "Secret saved");
      String json = new Gson().toJson(obj);
      System.out.println("SecretController.createSecret " + json);
      return ResponseEntity.accepted().body(json);
   }

   // Build Get Secrets by userId REST API
   @CrossOrigin(origins = "${CROSS_ORIGIN}")
   @PostMapping("/byuserid")
   public ResponseEntity<List<Secret>> getSecretsByUserId(@RequestBody EncryptCredentials credentials) {
      System.out.println("SecretController.getSecretsByUserId " + credentials);

      User user = userService.findByEmail(credentials.getEmail());
      // Salt und Key ableiten
      String salt = user.getEncryptionSalt();
      SecretKey key;
      try {
         key = EncryptUtil.createSecretKey(credentials.getEncryptPassword(), salt);
      } catch (Exception e) {
         return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
      }

      List<Secret> secrets = secretService.getSecretsByUserId(user.getId());
      if (secrets.isEmpty()) {
         System.out.println("SecretController.getSecretsByUserId secret isEmpty");
         return ResponseEntity.notFound().build();
      }
      
      //Decrypt content
      List<Secret> result = new ArrayList<>();
      for(Secret secret: secrets) {
         try {
            String clear = EncryptUtil.decrypt(secret.getContent(), key);
            secret.setContent(clear);
         } catch (Exception e) {
            System.out.println("SecretController.getSecretsByUserId decrypt error: " + e + " " + secret);
            secret.setContent("not encryptable. Wrong password?");
         }
         result.add(secret);
      }

      System.out.println("SecretController.getSecretsByUserId " + result);
      return ResponseEntity.ok(result);
   }

   // Build Get Secrets by email REST API
   @CrossOrigin(origins = "${CROSS_ORIGIN}")
   @PostMapping("/byemail")
   public ResponseEntity<List<Secret>> getSecretsByEmail(@RequestBody EncryptCredentials credentials) {
      System.out.println("SecretController.getSecretsByEmail " + credentials);
      return getSecretsByUserId(credentials);
   }

   // Build Get All Secrets REST API
   // http://localhost:8080/api/secrets
   @CrossOrigin(origins = "${CROSS_ORIGIN}")
   @GetMapping
   public ResponseEntity<List<Secret>> getAllSecrets() {
      List<Secret> secrets = secretService.getAllSecrets();
      return new ResponseEntity<>(secrets, HttpStatus.OK);
   }

   // Build Update Secret REST API
   // http://localhost:8080/api/secrets/1
   @CrossOrigin(origins = "${CROSS_ORIGIN}")
   @PutMapping("{id}")
   public ResponseEntity<String> updateSecret(
         @PathVariable("id") Long secretId,
         @Valid @RequestBody NewSecret newSecret,
         BindingResult bindingResult) {
      //input validation
      if (bindingResult.hasErrors()) {
         List<String> errors = bindingResult.getFieldErrors().stream()
               .map(fieldError -> fieldError.getField() + ": " + fieldError.getDefaultMessage())
               .collect(Collectors.toList());
         System.out.println("SecretController.updateSecret " + errors);

         JsonArray arr = new JsonArray();
         errors.forEach(arr::add);
         JsonObject obj = new JsonObject();
         obj.add("message", arr);
         String json = new Gson().toJson(obj);

         System.out.println("SecretController.updateSecret, validation fails: " + json);
         return ResponseEntity.badRequest().body(json);
      }

      //get Secret with id
      Secret dbSecret = secretService.getSecretById(secretId);
      if(dbSecret == null){
         System.out.println("SecretController.updateSecret, secret not found in db");
         JsonObject resp = new JsonObject();
         resp.addProperty("answer", "Secret not found in db");
         String json = new Gson().toJson(resp);
         return ResponseEntity.badRequest().body(json);
      }
      User user = userService.findByEmail(newSecret.getEmail());

      //check if Secret in db has not same userid
      if(!dbSecret.getUserId().equals(user.getId())){
         System.out.println("SecretController.updateSecret, not same user id");
         JsonObject resp = new JsonObject();
         resp.addProperty("answer", "Secret has not same user id");
         String json = new Gson().toJson(resp);
         return ResponseEntity.badRequest().body(json);
      }
      // Salt und Key ableiten
      String salt2 = user.getEncryptionSalt();
      SecretKey key2;
      try {
         key2 = EncryptUtil.createSecretKey(newSecret.getEncryptPassword(), salt2);
      } catch (Exception e) {
         return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
               .body("Error deriving encryption key");
      }
      //check if Secret can be decrypted with password
      try {
         EncryptUtil.decrypt(dbSecret.getContent(), key2);
      } catch (Exception e) {
         System.out.println("SecretController.updateSecret, invalid password");
         JsonObject resp = new JsonObject();
         resp.addProperty("answer", "Password not correct.");
         String json = new Gson().toJson(resp);
         return ResponseEntity.badRequest().body(json);
      }
      //modify Secret in db.
      String newJson = newSecret.getContent().toString();
      String newEncrypted;
      try {
         newEncrypted = EncryptUtil.encrypt(newJson, key2);
      } catch (Exception e) {
         return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
               .body("Error encrypting content");
      }
      dbSecret.setContent(newEncrypted);
      secretService.updateSecret(dbSecret);
      System.out.println("SecretController.updateSecret, secret updated in db");
      JsonObject resp = new JsonObject();
      resp.addProperty("answer", "Secret updated");
      String json = new Gson().toJson(resp);
      return ResponseEntity.accepted().body(json);
   }

   // Build Delete Secret REST API
   @CrossOrigin(origins = "${CROSS_ORIGIN}")
   @DeleteMapping("{id}")
   public ResponseEntity<String> deleteSecret(@PathVariable("id") Long secretId) {
      //todo: Some kind of brute force delete, perhaps test first userid and encryptpassword
      secretService.deleteSecret(secretId);
      System.out.println("SecretController.deleteSecret successfully: " + secretId);
      return new ResponseEntity<>("Secret successfully deleted!", HttpStatus.OK);
   }
}