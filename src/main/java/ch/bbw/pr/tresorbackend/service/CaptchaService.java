package ch.bbw.pr.tresorbackend.service;

import ch.bbw.pr.tresorbackend.model.CaptchaResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.HashMap;
import java.util.Map;

@Service
public class CaptchaService {

    @Value("${recaptcha.secret}")
    private String secret;

    @Value("${recaptcha.url}")
    private String verifyUrl;

    /**
     * Verifiziert das reCAPTCHA Token beim Google reCAPTCHA API.
     *
     * @param token Das reCAPTCHA-Token vom Client (Frontend)
     * @return true wenn gültig, sonst false
     */
    public boolean verifyCaptcha(String token) {
        RestTemplate restTemplate = new RestTemplate();

        // Anfrage Parameter vorbereiten
        Map<String, String> params = new HashMap<>();
        params.put("secret", secret);
        params.put("response", token);

        // Anfrage an Google senden
        ResponseEntity<CaptchaResponse> response = restTemplate.postForEntity(
                verifyUrl + "?secret={secret}&response={response}",
                null,
                CaptchaResponse.class,
                params
        );

        CaptchaResponse captchaResponse = response.getBody();
        return captchaResponse != null && captchaResponse.isSuccess();
    }
}
