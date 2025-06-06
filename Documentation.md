# Technische Dokumentation – Sicherheitsoptimierung der Tresor-Applikation

## Überblick

Im Rahmen eines Sicherheits-Refactorings wurde die bestehende Tresor-Applikation um mehrere sicherheitsrelevante Funktionen erweitert. Ziel war es, sowohl die sichere Speicherung von Benutzerpasswörtern als auch die geschützte Ablage sensibler Daten („Secrets“) zu gewährleisten. Darüber hinaus wurden kleinere Anpassungen im Frontend vorgenommen, um Darstellungsprobleme zu beheben.
Diese Dokumentation beschreibt die wichtigsten technischen Änderungen sowie die dahinterliegende Motivation.

---
> **Hinweis**: Aufgrund eines kürzlich erfolgten Wechsels auf einen neuen Laptop ist die Git-Historie nicht vollständig. Einige Commits, die während der Entwicklungszeit entstanden sind, fehlen daher im Repository.

## 1. Sichere Passwortverarbeitung

### Hintergrund
Klassische Passwortspeicherung birgt hohe Risiken – selbst bei Verschlüsselung besteht die Gefahr, dass Schlüssel kompromittiert werden. Daher wurde ein nicht umkehrbares Verfahren zur Passwortverarbeitung gewählt: das sogenannte Hashing mit Salt und Pepper.

### Umsetzung im System
- **Hashing-Algorithmus**: PBKDF2 mit HMAC-SHA256
- **Salt**: Benutzerindividuell, zufällig generiert
- **Pepper**: Geheimwert aus Anwendungskonfiguration
- **Iterationen**: 100'000 zur Absicherung gegen Brute-Force

#### Codeintegration
**`HashUtil.java`**
- `generateSalt()` erstellt eine zufällige Salt-Zeichenkette (Base64-kodiert)
- `hashPassword(...)` erzeugt das gehashte Passwort unter Einbezug von Salt und Pepper

**`UserController.java`**
- Bei Neuregistrierung wird ein Salt erzeugt und der Pepper aus der Konfiguration geladen:
  ```java
  String passwordSalt = HashUtil.generateSalt();
  String passwordHash = HashUtil.hashPassword(userPassword, passwordSalt, pepper);
  ```
- Die generierten Werte werden in der Benutzerdatenbank abgelegt.

#### Datenbankanpassung

Die Benutzertabelle wurde erweitert:
```sql
ALTER TABLE user ADD COLUMN password_salt VARCHAR(24) NOT NULL;
```

---

## 2. Verschlüsselte Speicherung von Secrets

### Motivation

Secrets enthalten sensible Daten, die keinesfalls unverschlüsselt gespeichert werden dürfen. Eine AES-Verschlüsselung im CBC-Modus mit nutzerindividuell abgeleitetem Schlüssel wurde implementiert.

### Technische Umsetzung

- **Verschlüsselung**: AES/CBC/PKCS5Padding
- **Key-Erzeugung**: Nutzerpasswort + individueller Encryption-Salt
- **IV**: Zufallswert, gemeinsam mit dem verschlüsselten Text gespeichert

#### Implementierung

**`EncryptUtil.java`**
- `deriveKey(...)` leitet mit PBKDF2 den Verschlüsselungsschlüssel ab
- `encrypt(...)` / `decrypt(...)` für Ver- und Entschlüsselung

**`SecretController.java`**
- Beim Speichern:
  ```java
  SecretKey key = EncryptUtil.deriveKey(secretPassword, userSalt);
  String encrypted = EncryptUtil.encrypt(secretContent, key);
  ```
- Beim Abrufen wird derselbe Prozess umgekehrt durchgeführt

**`NewSecret.java`**
- Enthält `email`, `content` und `encryptPassword` zur Handhabung der Secrets

#### Änderungen in der Datenbank

```sql
ALTER TABLE user ADD COLUMN encryption_salt VARCHAR(24) NOT NULL;
ALTER TABLE secret MODIFY COLUMN content LONGTEXT NOT NULL;
```

---

## 3. Frontend: JSON-Darstellungsfehler behoben

### Problemstellung

Im React-Frontend wurden Secrets nicht korrekt dargestellt. Inhalte erschienen als Zeichenketten mit einzeln aufgelisteten Buchstaben.

### Korrektur

Durch die Nutzung von `JSON.parse()` konnte das Problem behoben werden.

**`Secrets.js`**  
Vorher:
```jsx
setSecrets(data);
```

Nachher:
```jsx
const parsed = data.map(secret => ({
  ...secret,
  content: JSON.parse(secret.content)
}));
setSecrets(parsed);
```

---

## Zusammenfassung der Änderungen

| Komponente               | Dateien                                 | Beschreibung                                               |
|--------------------------|-----------------------------------------|------------------------------------------------------------|
| Passwortsicherheit       | `HashUtil.java`, `UserController.java`  | Hashing mit Salt & Pepper, Speicherung sicherer Werte      |
|                          | `application.properties`                | Konfigurierter Pepper-Wert                                 |
|                          | Datenbank                               | Spalte für Salt hinzugefügt                                |
| Secrets-Verschlüsselung  | `EncryptUtil.java`, `SecretController.java` | AES-Verschlüsselung mit individuellem Key                 |
|                          | `NewSecret.java`                        | Modell erweitert um notwendige Felder                      |
|                          | Datenbank                               | Salt-Spalte & Anpassung des Datentyps `content`            |
| Frontend-Fehlerbehebung  | `Secrets.js`                            | JSON korrekt geparst und dargestellt                       |

---

## Reflexion und genutzte Tools
Während der Umsetzung stellte sich besonders die Integration der Verschlüsselung als Herausforderung heraus. Insbesondere die Wahl des passenden Datentyps in der Datenbank für verschlüsselte Inhalte erforderte mehrere Tests – `LONGTEXT` erwies sich als notwendig.

### Verwendete Technologien und Tools
- **IDE**: Visual Studio Code mit Java-Support
- **Datenbank**: MySQL (lokal gestartet)
- **Datenbankmanagement**: MySQL VSCode-Erweiterung
- **Dokumentation**: Markdown

## 4. Frontend: Passwortstärke-Validierung

### Ziel

Die Benutzer sollen bereits bei der Eingabe ihres Passworts visuelles Feedback zur Stärke des Passworts erhalten, um schwache Passwörter frühzeitig zu vermeiden.

### Umsetzung

- **Bibliothek:** [zxcvbn](https://github.com/dropbox/zxcvbn) von Dropbox wurde installiert (`npm install zxcvbn`).
- **Ort der Änderung:** `RegisterUser.js` im Frontend (`src/pages/user/`)
- **Verhalten:**
  - Bei jeder Eingabe im Passwortfeld wird mit zxcvbn ein Score zwischen 0 (schwach) und 4 (sehr stark) berechnet.
  - Der Score wird als Text ("Schwach", "Mittel", "Stark") angezeigt.
  - Zusätzlich zeigt das System Hinweise zur Verbesserung des Passworts.
  - Der Registrieren-Button bleibt deaktiviert, solange die Passwortstärke unter dem Schwellenwert (Score < 2) liegt.

**Codeauszug:**

```jsx
import zxcvbn from 'zxcvbn';

const handlePasswordChange = (e) => {
  const pw = e.target.value;
  setCredentials(prev => ({ ...prev, password: pw }));
  const result = zxcvbn(pw);
  setPasswordScore(result.score);
  setPasswordFeedback(result.feedback.warning || result.feedback.suggestions.join(' '));
};

{passwordScore !== null && (
  <div>
    <p>Stärke: <strong>{passwordScore <= 1 ? 'Schwach' : passwordScore === 2 ? 'Mittel' : 'Stark'}</strong></p>
    <p>{passwordFeedback}</p>
  </div>
)}
```