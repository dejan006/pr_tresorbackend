package ch.bbw.pr.tresorbackend.util;

import java.util.regex.Pattern;

public class PasswordStrengthValidator {
    // Regex: min. 8 Zeichen, 1 Grossbuchstabe, 1 Kleinbuchstabe, 1 Ziffer, 1 Sonderzeichen
    private static final String PASSWORD_PATTERN =
        "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[!@#$%^&*()_+\\-={}\\[\\]:;\"'<>,.?/]).{8,}$";

    private static final Pattern pattern = Pattern.compile(PASSWORD_PATTERN);

    public static boolean isValid(String password) {
        if (password == null) {
            return false;
        }
        return pattern.matcher(password).matches();
    }
}