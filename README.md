# PQC Detector

> Détection automatique de faiblesses dans les implémentations post-quantiques par IA

![Python](https://img.shields.io/badge/Python-3.10+-blue)
![Accuracy](https://img.shields.io/badge/Accuracy-100%25-green)
![NIST](https://img.shields.io/badge/NIST-PQC%202024-orange)

## Description
Outil d'analyse statique qui détecte automatiquement les faiblesses de sécurité dans du code Python utilisant les algorithmes post-quantiques (Kyber, Dilithium).

## Faiblesses détectées
| Type | Description | Sévérité |
|------|-------------|----------|
| `weak_randomness` | `random.randint` au lieu de `os.urandom` | 🔴 Critique |
| `key_and_nonce_reuse` | Même clé/nonce réutilisée | 🔴 Critique |
| `insufficient_security_parameters` | `security_level=512` au lieu de `768` | 🟠 Élevée |
| `unchecked_signature_verification` | `verify()` ignoré | 🔴 Critique |

## Architecture
