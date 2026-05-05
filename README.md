# PQC Detector

> Détection automatique de faiblesses dans les implémentations post-quantiques par IA

![Python](https://img.shields.io/badge/Python-3.10+-blue)
![Accuracy](https://img.shields.io/badge/Accuracy-100%25-green)
![NIST](https://img.shields.io/badge/NIST-PQC%202024-orange)
![License](https://img.shields.io/badge/License-MIT-lightgrey)

---

## Description

**PQC Detector** est un outil d'analyse statique qui détecte automatiquement les faiblesses de sécurité dans du code Python utilisant les algorithmes de cryptographie post-quantique (Kyber, Dilithium).

Les algorithmes PQC comme **Kyber** et **Dilithium** sont mathématiquement solides — mais une mauvaise implémentation peut les rendre complètement vulnérables. Ce projet combine un **parser AST** et un modèle **CodeBERT fine-tuné** pour identifier ces erreurs automatiquement.

---

## Faiblesses détectées

| Type | Description | Sévérité |
|------|-------------|----------|
| `weak_randomness` | `random.randint` utilisé au lieu de `os.urandom` | 🔴 Critique |
| `key_and_nonce_reuse` | Même clé/nonce réutilisée pour plusieurs chiffrements AES-GCM | 🔴 Critique |
| `insufficient_security_parameters` | `security_level=512` (NIST L1) au lieu de `768` (NIST L3) | 🟠 Élevée |
| `unchecked_signature_verification` | Retour de `verify()` ignoré — toute signature est acceptée | 🔴 Critique |

---

## Architecture

```
Code source Python (PQC)
         ↓
   [Couche 1 — Parser AST]
   Extraction : imports, appels, fonctions
         ↓
   [Couche 2 — Feature Extraction]
   CSPRNG · paramètres NIST · réutilisation de clé
         ↓
   [Couche 3 — Modèle IA]
   CodeBERT fine-tuné + détecteurs à base de règles
         ↓
   [Couche 4 — Rapport]
   Type · Sévérité · Suggestion de correction
```

---

## Installation

```bash
# Cloner le repo
git clone https://github.com/USERNAME/pqc-detector.git
cd pqc-detector

# Installer les dépendances Python
pip install -r requirements.txt

# Installer les dépendances frontend
cd frontend && npm install && cd ..
```

---

## Utilisation

### Ligne de commande
```bash
# Analyser un fichier Python
python cli.py mon_fichier.py

# Rapport en JSON
python cli.py mon_fichier.py --json

# Sauvegarder le rapport
python cli.py mon_fichier.py --save rapport.json
```

### Interface web
```bash
# Terminal 1 — Backend
uvicorn api:app --reload --port 8000

# Terminal 2 — Frontend
cd frontend && npm run dev
# → http://localhost:5173
```

### Tests end-to-end
```bash
python test.py
```

---

## Résultats

```
PQC Detector - end-to-end test on 26 files
─────────────────────────────────────────
verdict accuracy  : 26/26 (100.0%)
precision         : 100.0%
recall            : 100.0%
f1                : 100.0%
weakness-type detection rate : 24/24 (100.0%)
```

---

## Structure du projet

```
pqc_detector/
├── dataset/
│   ├── vulnerable/       # 24 exemples de code PQC avec faiblesses
│   └── clean/            # 2 exemples de code PQC corrects
├── parser.py             # Extraction AST + features
├── model.py              # Fine-tuning de CodeBERT
├── cli.py                # Interface en ligne de commande
├── api.py                # Backend FastAPI
├── test.py               # Tests end-to-end
├── frontend/             # Interface React + TypeScript
└── requirements.txt
```

---

## Stack technique

| Composant | Technologie |
|-----------|-------------|
| Parsing AST | Python `ast` module |
| Modèle IA | CodeBERT (`microsoft/codebert-base`) |
| ML Framework | HuggingFace Transformers |
| Backend API | FastAPI + Uvicorn |
| Frontend | React + TypeScript + Vite |
| Tests | Script end-to-end custom |

---

## Auteur

Achraf HAMOUDA — **ENSA Beni Mellal**
Filière : Intelligence Artificielle & Cybersécurité
Module : Cryptographie
Année universitaire : 2025 / 2026
