# Rapport éthique et légal

## Règle fondamentale

> **Ne scannez jamais une machine sans autorisation explicite de son propriétaire.**

Scanner un système sans permission est illégal dans la plupart des pays, même sans intention malveillante.

## Cadre légal

| Pays | Loi applicable |
|------|---------------|
| Belgique | Loi du 28 novembre 2000 sur la criminalité informatique |
| France | Articles 323-1 à 323-7 du Code pénal |
| Union Européenne | Directive NIS2 (2022/2555) |

Un scan de ports non autorisé peut être qualifié d'**accès frauduleux à un système informatique**.

## Usages autorisés

- Scan de **votre propre infrastructure** (machine perso, serveur personnel)
- Scan dans un **réseau de laboratoire isolé** (VM, environnement de test)
- Scan dans le cadre d'un **pentest avec contrat signé**
- Scan dans le cadre d'un **programme de bug bounty** (périmètre défini)

## Usages interdits

- Scanner des serveurs publics sans autorisation
- Scanner le réseau d'une entreprise, école ou FAI sans accord écrit
- Utiliser les résultats d'un scan pour exploiter des vulnérabilités sur des systèmes tiers

## Discrétion et détection

### Comment un scan peut être détecté
- **IDS/IPS** (Snort, Suricata) — détectent les scans de ports par signature
- **Logs pare-feu** — chaque tentative de connexion peut être enregistrée
- **Honeypots** — ports délibérément ouverts pour piéger les scanners

### Réduire l'empreinte (dans un cadre autorisé)
- Utiliser le **SYN scan** (moins de traces dans les logs applicatifs)
- Réduire le nombre de threads (`--threads 20`)
- Ajouter un délai entre les ports (`--delay 0.1`)
- Limiter la plage de ports scannés

## Note

Ce projet est destiné à un **usage éducatif et de laboratoire uniquement**.
L'auteur décline toute responsabilité en cas d'utilisation abusive ou illégale.
