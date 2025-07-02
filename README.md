# Projet Yharnam — PE Injector

---

## 📖 Présentation

Cet outil est un **injecteur PE 64-bits** conforme au TP de virologie/malware.
Il réalise :

1. **Infection de fichiers** : pour chaque `.exe` 64-bits dans le répertoire courant (sauf lui-même),

   * il crée une nouvelle section nommée `.yarna`,
   * injecte dans cette section un stub assembleur minimal qui affiche une `MessageBoxA`,
   * modifie le *AddressOfEntryPoint* du PE pour démarrer dans la section infectée,
   * puis saute à l’EP original pour conserver le comportement légitime.

2. **Injection en mémoire** : s’il trouve un process cible (e.g. `notepad.exe`), via **`VirtualAllocEx` + `WriteProcessMemory` + `CreateRemoteThread`**, il injecte le même stub
   dans l’espace d’un process 64‑bits de la même session pour y afficher une `MessageBoxA`.

---

## ⚙️ Fonctionnalités

| Fonction               | Description                                                                             |
| ---------------------- | --------------------------------------------------------------------------------------- |
| **Infection statique** | Parcours tous les PE/64-bits du répertoire courant et les « contamine » automatiquement |
| **Injection process**  | Recherche et infecte `notepad.exe` en mémoire (session courante)                        |
| **MessageBox visible** | Le stub assembleur affiche un message ("pwnme 2600" par défaut)                         |
| **Build conditionnel** | Compilation x64 uniquement (NASM + MSVC). Non supporté en 32-bits sans adaptation.      |

> ⚠️ **Limitation** : l’injecteur cible uniquement les applications 64-bits de la même session et du même niveau d’intégrité.

---

## 🐞 Problèmes rencontrés

1. **Mismatch de taille du stub**  : lors des premiers tests, le tableau d'octets n'était pas aligné à 68 ou 64 bytes selon l'assemblage, causant des crash. Nous avons donc ajusté la définition du stub et vérifié sa taille à l'exécution avant injection.

2. **API non trouvée en 32‑bits** : sur certaines machines 32‑bits, la résolution par RVA (*GetRemoteAddressByRVA*) échouait car les adresses et alignements diffèrent. Nous avons finalement ciblé uniquement la plateforme x64 pour garantir la cohérence.

3. **Fallback sur une chaîne inline** : initialement, le payload était chargé depuis la ressource RCDATA via `LoadResource`. Des problèmes de chargement et d’offset ont conduit à remplacer cette approche par l’écriture directe de la chaîne `"pwnme 2600"` dans le process cible via `VirtualAllocEx` + `WriteProcessMemory`.

---

## 🔍 Chargement du payload

Le payload se compose :

1. **Message** : une chaîne ASCII (`"pwnme 2600"`) écrite dans la mémoire du process cible.
2. **Stub assembleur x64** : un petit shellcode (<64 bytes) qui :

   * appelle `MessageBoxA(NULL, msg, msg, MB_OK)`,
   * puis `ExitThread(0)` pour terminer le thread injecté.

La séquence est ajustée *à chaud* dans le code C :

```c
// 1) allocation + écriture de la chaîne
LPVOID remoteMsg = VirtualAllocEx(...);
WriteProcessMemory(hProc, remoteMsg, "pwnme 2600", ...);

// 2) calcul des adresses de MessageBoxA et ExitThread dans le process cible
DWORD64 addrMsg = GetRemoteAddressByRVA(pid, "user32.dll", GetProcAddress(u32, "MessageBoxA"));
DWORD64 addrExit = GetRemoteAddressByRVA(pid, "kernel32.dll", GetProcAddress(k32, "ExitThread"));

// 3) patch du stub x64 avec ces adresses et l’adresse de remoteMsg
memcpy(stub + slot1, &remoteMsg, 8);
memcpy(stub + slot4, &addrMsg, 8);
memcpy(stub + slot5, &addrExit, 8);

// 4) injection du stub + exécution via CreateRemoteThread
VirtualAllocEx(..., PAGE_EXECUTE_READWRITE);
WriteProcessMemory(...);
CreateRemoteThread(...);
```

---

## 🛠️ Prérequis

* **Windows 10/11 64-bits**
* **NASM** (≥ 2.14) pour l’assemblage du stub (optionnel si stub inline)
* **Microsoft Visual C++ Build Tools** (`cl.exe`, `link.exe`)
* **RC.exe** pour compiler d’éventuelles ressources (non requises si stub inline)

---

## 🏗️ Compilation

Ouvrez un **Invite de commandes x64** (Developer Command Prompt) :

```bat
cd pe-injector
nmake -f Makefile    # ou make selon setup
.\injector.exe
```

Le Makefile assemble (`payload.asm`), compile la ressource (`payload.rc`) et l’injecteur (`injector.c`).

---

## 🚀 Usage

```bat
> injector.exe
[DEBUG] Lancement injector.exe
[DEBUG] InfectFile: path=MyApp.exe
[DEBUG] Successfully infected: MyApp.exe
[DEBUG] Found notepad.exe (PID=1234), injecting…
[DEBUG] Injection succeeded for notepad.exe (PID=1234)
[DEBUG] Fin injector.exe
```
![image](https://github.com/user-attachments/assets/16a03478-47d7-4531-8875-99ecb27a9389)

---

## 🔒 Bonus & Extensions

* **Injection dynamique** : à chaque exécution, tous les PE/64-bits sont infectés.
* **Injection process** : `notepad.exe` est automatiquement ciblé.
* **Packing / Chiffrement** : non implémenté (stub en clair dans la section `.yarna`).

---
