# NetTrace

```
  _   _      _   _____
 | \ | | ___| |_|_   _| __ __ _  ___ ___
 |  \| |/ _ \ __| | || '__/ _` |/ __/ _ \
 | |\  |  __/ |_  | || | | (_| | (_|  __/
 |_| \_|\___|\__| |_||_|  \__,_|\___\___|
```

> Reconnaissance passive de domaines, complète et sans clé API.

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Version](https://img.shields.io/badge/Version-2.1-orange)](https://github.com/Rooot3301/NETTRACE)

NetTrace regroupe une douzaine de sources d'analyse OSINT dans un seul outil en ligne de commande. Tu lui donnes un domaine, il te sort tout ce qu'on peut apprendre à son sujet sans jamais l'attaquer : WHOIS, DNS, certificats, sécurité email, sous-domaines, historique, et un score de maturité avec des recommandations concrètes. Le tout dans un terminal soigné (grâce à `rich`), exportable en 4 formats, et **sans aucune clé API payante**.

Par défaut, tout est **passif** : NetTrace ne consulte que des sources publiques. Les rares actions qui touchent la cible (scan de ports, confirmation de takeover) sont réservées au flag `--active`.

---

## Installation

```bash
git clone https://github.com/Rooot3301/NETTRACE.git
cd NETTRACE
pip install -r requirements.txt
```

Python 3.8+. Dépendances : `requests`, `dnspython`, `python-whois`, `python-dateutil`, `rich`.

### Outils optionnels (pour plus de sous-domaines)

```bash
# subfinder
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
# amass
go install -v github.com/owasp-amass/amass/v4/...@master
```

S'ils sont installés, NetTrace les utilise automatiquement. Sinon il se rabat sur crt.sh.

---

## Prise en main

```bash
# Menu interactif (le plus simple pour commencer)
python nettrace.py

# Analyse directe d'un domaine
python nettrace.py -d example.com

# Générer un rapport HTML
python nettrace.py -d example.com -o rapport.html -f html

# Comparer deux domaines côte à côte
python nettrace.py --compare example.com google.com

# Analyser une liste de domaines et tout sortir dans un CSV
python nettrace.py --batch domaines.txt -o resultats.csv

# Sortie JSON brute, pour un pipeline
python nettrace.py -d example.com --json | jq '.scoring.score'

# Scan actif (ports TCP) — seulement sur des systèmes autorisés
python nettrace.py -d example.com --active
```

### Options

```
  -d, --domain       Domaine à analyser
  -o, --output       Fichier de sortie
  -f, --format       json | txt | html | csv   (défaut : json)
  --compare D1 D2    Compare deux domaines
  --batch FILE       Analyse une liste (un domaine par ligne) ; -o pour un CSV combiné
  --active           Active le scan de ports + la confirmation HTTP des takeovers
  --json             Sortie JSON pure (pour les pipelines)
  --no-cache         Ignore le cache local
  --clear-cache      Vide le cache et quitte
  -v, --verbose      Mode détaillé
  -i, --interactive  Menu interactif
```

---

## Ce que NetTrace analyse

### Reconnaissance passive (par défaut)

- **WHOIS** — registrar, dates de création/expiration, âge du domaine, registrant, statuts, name servers, DNSSEC.
- **DNS** — enregistrements A, AAAA, MX, TXT, NS, CNAME, SOA.
- **DNSSEC** — détecté via la présence de DNSKEY / RRSIG.
- **Zone Transfer (AXFR)** — teste le transfert de zone sur les name servers ; signale ceux qui sont vulnérables.
- **Sous-domaines** — via crt.sh (Certificate Transparency), plus subfinder et amass si disponibles.
- **Subdomain takeover** — repère les CNAME orphelins pointant vers une trentaine de services connus (GitHub Pages, Heroku, S3, Azure, Netlify, Shopify, Fastly, Zendesk…).
- **GeoIP & ASN** — pays, ville, ASN, organisation et hébergeur de chaque IP.
- **CDN** — détection via l'organisation/ASN et les en-têtes (Cloudflare, Akamai, Fastly, CloudFront…).
- **HTTP / TLS** — statut, redirection HTTP→HTTPS, en-tête Server, certificat (émetteur, SAN, expiration) et **vérification de la chaîne + du hostname**.
- **En-têtes de sécurité** — HSTS, CSP, X-Frame-Options, etc., notés sur 100.
- **WAF & technologies** — fingerprinting du pare-feu applicatif et de la stack (nginx, WordPress, Shopify…).
- **Sécurité email** — SPF, DMARC, DKIM (18 sélecteurs testés), BIMI, MTA-STS, notés sur 100.
- **Wayback Machine** — première/dernière capture, nombre de snapshots, et URLs archivées potentiellement sensibles.
- **Google Dorks** — plus de 50 requêtes prêtes à copier, réparties en 8 catégories.

### Mode actif (`--active`, sur autorisation uniquement)

- **Scan de ports TCP** — 20 ports courants, multi-threadé, avec récupération de bannières.
- **Confirmation HTTP des takeovers** — envoie des requêtes pour confirmer un takeover suspecté (la détection, elle, reste passive).

---

## Le Trust & Maturity Score

NetTrace calcule un score unifié sur 100, à partir de 7 facteurs pondérés :

| Facteur | Poids |
|---|---|
| Âge du domaine | 25 |
| Sécurité email (SPF/DMARC/DKIM) | 20 |
| Complétude DNS | 15 |
| HTTPS + en-têtes de sécurité | 15 |
| Présence de sous-domaines | 10 |
| Complétude WHOIS | 10 |
| Présence d'archives | 5 |

| Score | Niveau |
|---|---|
| 80–100 | Trusted / Established |
| 60–79 | Moderate Trust |
| 40–59 | Low Trust |
| 0–39 | Untrusted / Immature |

Le score s'accompagne de recommandations concrètes et priorisées (par exemple : « SPF +all autorise n'importe qui à usurper votre domaine », « AXFR ouvert sur ce name server », « certificat TLS expire dans 12 jours »).

> **À garder en tête.** Ce score mesure la **maturité et l'hygiène de configuration** d'un domaine — pas sa dangerosité. Un domaine de phishing tout récent derrière Cloudflare, avec un HTTPS valide, peut très bien décrocher un bon score. Pour un verdict de malveillance, croise avec une source de réputation (VirusTotal, etc.). NetTrace génère d'ailleurs le lien VirusTotal du domaine à la fin de chaque analyse.

---

## Exports

| Format | Pour quoi faire |
|---|---|
| `json` | Données complètes et structurées |
| `html` | Rapport autonome dark-theme, consultable hors-ligne |
| `txt` | Rapport lisible en clair |
| `csv` | Une ligne par domaine, pour Excel ou un SIEM (le mode batch en produit un multi-lignes) |

---

## Structure du projet

```
nettrace.py              # Point d'entrée et orchestration
config.py                # Configuration et signatures
cache.py                 # Cache local (~/.nettrace/cache/)
requirements.txt
requirements-dev.txt     # Dépendances de test
LICENSE                  # MIT
modules/
├── whois_analysis.py    # WHOIS
├── dns_analysis.py      # DNS + AXFR + DNSSEC
├── http_analysis.py     # HTTP/TLS + WAF/CDN
├── geo_analysis.py      # GeoIP + ASN
├── subdomain_analysis.py# crt.sh + détection de takeover
├── email_security.py    # SPF/DMARC/DKIM/BIMI/MTA-STS
├── port_scanner.py      # Scan de ports (mode actif)
├── archive.py           # Wayback Machine
├── scoring.py           # Trust & Maturity Score
└── dorks.py             # Google Dorks
exporters/
├── json_exporter.py
├── txt_exporter.py
├── csv_exporter.py
└── html_exporter.py
tests/                   # Suite pytest
```

---

## Tests

```bash
pip install -r requirements-dev.txt
pytest -q
```

La suite couvre le parsing SPF, les dates WHOIS, le calcul du score, le cache (variantes passive/active) et l'export CSV.

---

## Éthique

NetTrace est fait pour la reconnaissance légitime : audit de tes propres domaines, exercices de pentest autorisés, recherche, CTF. Par défaut il n'interroge que des sources publiques. Le mode `--active` envoie du trafic vers la cible — ne l'utilise que sur des systèmes que tu es autorisé à tester.

---

## Changelog

### v2.1 (2026-09)
- Correctif : l'export CSV échouait silencieusement en mode passif.
- Correctif : `--active` renvoyait un résultat en cache sans les ports (cache désormais séparé passif/actif).
- Correctif : la confirmation HTTP de takeover ne s'exécute plus qu'en mode `--active` ; détection CNAME parallélisée.
- Correctif : `datetime.utcnow()` déprécié remplacé, dépendance inutilisée retirée, fichier `LICENSE` ajouté.
- Perf : modules d'analyse exécutés en parallèle (4-5× plus rapide).
- Ajout : vérification du certificat TLS, `--batch` en CLI, export CSV combiné.
- Ajout : score renommé « Trust & Maturity » avec avertissement explicite.
- Ajout : suite de tests pytest (30 tests).

### v2.0 (2026-03)
- Réécriture complète en architecture modulaire.
- Interface `rich`, 12 modules d'analyse, détection de takeover, exports HTML/CSV.

### v1.0
- WHOIS, DNS, sous-domaines (crt.sh), score de confiance, export JSON/TXT.

---

**Auteur :** [Root3301](https://github.com/Rooot3301) · [Signaler un bug](https://github.com/Rooot3301/NETTRACE/issues)

Si le projet t'est utile, une étoile fait toujours plaisir.
