# LAB19-SEC : CTF Android — Snake : Exploitation SnakeYAML + Désérialisation Arbitraire

**ÉCOLE NATIONALE DES SCIENCES APPLIQUÉES DE MARRAKECH — ENSA Marrakech**

| | |
|---|---|
| **Réalisé par** | Chaoulid Hafssa |
| **Filière** | Génie — GCDSTE / Sécurité |
| **Établissement** | ENSA Marrakech |
| **Année universitaire** | 2025 – 2026 |

> Rapport de Travaux Pratiques — Module : Cybersécurité / SOC & Analyse Mobile

---

## Présentation du challenge

Snake est un challenge CTF Android qui s'appuie sur une vulnérabilité réelle et documentée : **CVE-2022-1471**, affectant la bibliothèque SnakeYAML (versions < 2.0). Cette faille permet à un attaquant de forcer l'instanciation arbitraire de classes Java via un fichier YAML malformé, sans jamais modifier l'APK de cette partie.

L'application cumule plusieurs couches de protection pour compliquer l'analyse :

- Détection de root
- Détection d'émulateur
- Détection de Frida (côté natif)
- Logique du flag enfouie dans une classe native non invoquée normalement

**Flux d'attaque global :**

```
Patch Smali (neutraliser les détections)
    → Intent ciblé (SNAKE=BigBoss)
        → Lecture de Skull_Face.yml
            → Désérialisation SnakeYAML (CVE-2022-1471)
                → Instanciation de BigBoss("Snaaaaaaaaaaaaaake")
                    → Appel JNI → flag dans logcat
```

---

## Environnement et outils

| Outil | Rôle dans ce lab |
|---|---|
| **Jadx-GUI** | Analyse statique du code Java décompilé |
| **apktool** | Décompilation en Smali et recompilation |
| **apksigner** | Signature de l'APK recompilé |
| **ADB** | Installation, transfert de fichiers, logcat |
| **Émulateur Android API ≤ 28** | Meilleure compatibilité avec les protections |
| **Éditeur texte** | Édition des fichiers Smali |

---

## Étape 1 — Préparation de l'environnement

### Installer l'APK d'origine

```bash
adb install snake.apk
```

Lancer l'application manuellement → elle se ferme immédiatement. Ce comportement confirme que les protections anti-root/anti-émulateur sont actives. Un patching est indispensable avant tout test.

> **Pourquoi API ≤ 28 ?** Les versions d'Android plus récentes ont renforcé les restrictions sur les permissions de stockage externe (`READ/WRITE_EXTERNAL_STORAGE`). L'API 28 offre un accès direct à `/sdcard/` sans les complexités du scoped storage d'Android 10+.

---

## Étape 2 — Analyse statique avec Jadx-GUI

### 2.1 Ouvrir l'APK

Lancer Jadx-GUI → *Fichier → Ouvrir le fichier* → sélectionner `snake.apk`.

### 2.2 Ce que révèle `MainActivity`

Dans la méthode `onCreate` (ou une méthode appelée depuis celle-ci), on observe la logique suivante :

**Condition d'entrée :**
```java
String extra = getIntent().getStringExtra("SNAKE");
if ("BigBoss".equals(extra)) {
    // déclenche la lecture du fichier
}
```

**Lecture du fichier YAML :**
```java
File file = new File("/sdcard/Snake/Skull_Face.yml");
Yaml yaml = new Yaml();
yaml.load(new FileInputStream(file));  // point d'exploitation
```

**Ce chemin d'exécution :**
- L'extra Intent `SNAKE` doit valoir exactement `BigBoss`
- L'application cherche `/sdcard/Snake/Skull_Face.yml`
- Le contenu est parsé par `SnakeYAML`

### 2.3 La classe `BigBoss` — cible de l'exploitation

Dans `com.pwnsec.snake.BigBoss` :

```java
public class BigBoss {
    static {
        System.loadLibrary("native-lib");
    }

    public BigBoss(String param) {
        if ("Snaaaaaaaaaaaaaake".equals(param)) {
            Log.d("PWNSEC", stringFromJNI());
        }
    }

    private native String stringFromJNI();
}
```

**Points clés :**
- `BigBoss` charge une librairie native au chargement de la classe
- Son constructeur attend exactement la chaîne `Snaaaaaaaaaaaaaake`
- Si la condition est vraie, la fonction JNI `stringFromJNI()` génère et loggue le flag
- Cette classe n'est **jamais instanciée normalement** dans le flux Java → elle est conçue pour être atteinte uniquement par l'exploitation YAML

### 2.4 Protections identifiées

| Protection | Mécanisme | Où chercher dans Jadx |
|---|---|---|
| **Détection root** | `Build.TAGS`, `File.exists("/system/app/Superuser.apk")`, `exec("su")` | Classes utilitaires, `onCreate` |
| **Détection émulateur** | `ro.hardware`, `ro.product.model`, `ro.kernel.qemu` | Méthodes `isEmulator()` ou équivalentes |
| **Détection Frida** | Scan de ports (27042), scan `/proc/self/maps` | Librairie native, code JNI |

---

## Étape 3 — Patch Smali : neutraliser les détections

### 3.1 Décompiler l'APK

```bash
apktool d snake.apk -o snake_smali
cd snake_smali/smali/com/pwnsec/snake/
```

### 3.2 Localiser les méthodes de détection

Dans Jadx, noter les noms de classes contenant des chaînes comme `"root"`, `"su"`, `"emulator"`, `"frida"`, `"test-keys"`, `"ro.hardware"`. Ce sont les classes à modifier dans les fichiers Smali correspondants.

### 3.3 Stratégies de patch

**Stratégie A — Forcer le retour `false` (méthode de détection retourne boolean)**

Avant :
```smali
# ... logique de détection ...
if-nez v0, :cond_detected
const/4 v0, 0x0
return v0

:cond_detected
const/4 v0, 0x1
return v0
```

Après :
```smali
const/4 v0, 0x0    # forcer false = "pas de problème détecté"
return v0
```

**Stratégie B — Court-circuiter avec `goto`**

Remplacer toutes les conditions `if-nez` / `if-eqz` par un `goto` pointant directement vers le chemin d'exécution normal :

```smali
goto :cond_safe    # sauter la logique de détection
```

**Stratégie C — `return-void` dans `showDialog` / méthode de fermeture**

Même principe que pour UnCrackable : vider la méthode qui ferme l'app.

### 3.4 Recompiler et signer

```bash
# Recompilation
apktool b snake_smali -o snake_patched.apk

# Signature — Linux/Mac
apksigner sign --ks ~/.android/debug.keystore snake_patched.apk

# Signature — Windows
apksigner sign --ks "%USERPROFILE%\.android\debug.keystore" snake_patched.apk
# Mot de passe : android

# Installation
adb install -r snake_patched.apk
```

> **Bonne pratique :** faire une copie des fichiers Smali avant modification et patcher un check à la fois pour identifier facilement ce qui fonctionne.

---

## Étape 4 — Création du payload YAML (exploitation CVE-2022-1471)

### 4.1 Créer le dossier sur le stockage externe

```bash
adb shell mkdir -p /sdcard/Snake
```

### 4.2 Créer le fichier `Skull_Face.yml`

Contenu du fichier :

```yaml
!!com.pwnsec.snake.BigBoss ["Snaaaaaaaaaaaaaake"]
```

**Anatomie du payload :**

| Partie | Rôle |
|---|---|
| `!!com.pwnsec.snake.BigBoss` | Global tag YAML → demande à SnakeYAML d'instancier cette classe Java |
| `["Snaaaaaaaaaaaaaake"]` | Argument passé au constructeur de `BigBoss` |

**Pourquoi ça marche (CVE-2022-1471) ?**

SnakeYAML (< 2.0) en mode `unsafe` (utilisation de `new Yaml()` sans `SafeConstructor`) permet les **global tags** (`!!`). Ces tags ordonnent au parseur d'instancier directement une classe Java arbitraire avec les paramètres fournis. C'est une désérialisation non contrôlée — identique dans le principe aux gadgets Java de deserialization, mais via YAML.

### 4.3 Transférer le fichier sur l'appareil

```bash
adb push Skull_Face.yml /sdcard/Snake/Skull_Face.yml
```

---

## Étape 5 — Lancement avec l'Intent ciblé

```bash
adb shell am start -n com.pwnsec.snake/.MainActivity -e SNAKE BigBoss
```

**Décomposition de la commande :**

| Fragment | Signification |
|---|---|
| `am start` | Démarre une Activity via Activity Manager |
| `-n com.pwnsec.snake/.MainActivity` | Package + nom de la classe Activity |
| `-e SNAKE BigBoss` | Extra de type String : clé = `SNAKE`, valeur = `BigBoss` |

**Ce qui se passe en arrière-plan :**

```
am start → MainActivity.onCreate()
    → getIntent().getStringExtra("SNAKE") == "BigBoss" ✓
        → lecture de /sdcard/Snake/Skull_Face.yml
            → SnakeYAML.load()
                → instanciation de BigBoss("Snaaaaaaaaaaaaaake")
                    → condition vérifiée ✓
                        → stringFromJNI() → Log.d("PWNSEC", flag)
```

---

## Étape 6 — Récupération du flag via logcat

```bash
# Filtre ciblé
adb logcat | grep -i "PWNSEC"

# Alternative plus large
adb logcat | grep -i "snake"
```

**Flag attendu :**

```
PWNSEC{W3'r3_N0t_T00l5_0f_The_g0v3rnm3n7_0R_4ny0n3_3ls3}
```

Le flag n'est jamais affiché à l'écran de l'app — il est uniquement écrit dans les logs Android via `Log.d()`. D'où l'importance de `logcat`.

---

## Analyse de la vulnérabilité — CVE-2022-1471

### Contexte

SnakeYAML est une bibliothèque Java de parsing YAML très répandue dans les applications Android et backend. La version 1.33 (et antérieures) souffre d'une désérialisation arbitraire via les **global tags YAML**.

### Mécanisme

```
Fichier YAML malveillant
        ↓
SnakeYAML parser (mode unsafe)
        ↓
new Yaml().load(input)   ← point vulnérable
        ↓
Instanciation de TOUTE classe Java accessible
        ↓
Exécution de code arbitraire (constructeur, méthode statique...)
```

### Correction (SnakeYAML ≥ 2.0)

```java
// Utilisation sécurisée
LoaderOptions options = new LoaderOptions();
Yaml yaml = new Yaml(new SafeConstructor(options));
```

`SafeConstructor` interdit les global tags et limite le parsing aux types YAML standards uniquement.

---

## Pourquoi la fonction native génère-t-elle le flag ?

La logique du flag est dans `stringFromJNI()` — une fonction C/C++ compilée dans `libnative-lib.so`. Cette approche complique l'extraction statique :

- Le flag n'apparaît pas en clair dans le bytecode Dalvik (Jadx ne peut pas le voir directement)
- Il est généré dynamiquement à l'exécution (calculs sur des chaînes, XOR, concaténation…)
- La détection de Frida côté natif empêche l'instrumentation dynamique directe
- La seule voie propre : déclencher le code natif via le flux normal de l'app, après patch

---

## Résumé des actions et commandes

```bash
# 1. Décompiler
apktool d snake.apk -o snake_smali

# 2. Patcher les fichiers Smali (édition manuelle)

# 3. Recompiler
apktool b snake_smali -o snake_patched.apk

# 4. Signer
apksigner sign --ks ~/.android/debug.keystore snake_patched.apk

# 5. Installer
adb install -r snake_patched.apk

# 6. Créer le dossier sur l'appareil
adb shell mkdir -p /sdcard/Snake

# 7. Préparer et pousser le payload YAML
echo '!!com.pwnsec.snake.BigBoss ["Snaaaaaaaaaaaaaake"]' > Skull_Face.yml
adb push Skull_Face.yml /sdcard/Snake/Skull_Face.yml

# 8. Déclencher l'exploitation
adb shell am start -n com.pwnsec.snake/.MainActivity -e SNAKE BigBoss

# 9. Capturer le flag
adb logcat | grep -i "PWNSEC"
```

---

## Conclusion

Ce challenge illustre plusieurs réalités importantes de la sécurité mobile :

**Sur la désérialisation :** CVE-2022-1471 est une vulnérabilité de classe critique — elle permet à un fichier de configuration (YAML) de devenir un vecteur d'exécution de code arbitraire. En contexte Android, où les apps lisent souvent des fichiers du stockage externe, cela devient particulièrement dangereux.

**Sur les protections client :** les vérifications anti-root, anti-émulateur et anti-Frida implémentées en Java/Kotlin restent vulnérables au patch Smali. Elles ralentissent l'analyste mais ne constituent pas une barrière insurmontable.

**Sur la défense en profondeur :** placer la logique critique dans du code natif (JNI) améliore la résistance à l'analyse statique, mais n'est pas suffisant seul si le déclenchement de ce code peut être forcé via une vulnérabilité de désérialisation.
