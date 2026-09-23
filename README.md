# NetTrace v2 — Advanced OSINT Domain Analysis Tool

```
  _   _      _   _____
 | \ | | ___| |_|_   _| __ __ _  ___ ___
 |  \| |/ _ \ __| | || '__/ _` |/ __/ _ \
 | |\  |  __/ |_  | || | | (_| | (_|  __/
 |_| \_|\___|\__| |_||_|  \__,_|\___\___|
```

> Reconnaissance passive complète de domaines — **zéro clé API requise**

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Version](https://img.shields.io/badge/Version-2.0-orange)](https://github.com/Rooot3301/NETTRACE)

**NetTrace v2** est un outil OSINT et de pentest de domaines entièrement réécrit. Il agrège **12 sources d'analyse distinctes** dans une interface terminal moderne (powered by `rich`), exporte en 4 formats et ne nécessite **aucune clé API payante**.

## Fonctionnalités

### Reconnaissance passive
| Module | Détail |
|--------|--------|
| **WHOIS** | Registrar, dates création/expiration, âge du domaine, statuts |
| **DNS complet** | A, AAAA, MX, TXT, NS, CNAME, SOA + détection DNSSEC |
| **Zone Transfer (AXFR)** | Test de transfert de zone sur tous les NS découverts |
| **Sous-domaines** | crt.sh (cert transparency) + subfinder + amass (optionnels) |
| **Subdomain Takeover** | Détection CNAME orphelins (28 services : GitHub Pages, Heroku, S3, Netlify…) |
| **GeoIP & ASN** | Localisation de chaque IP, ASN, organisation, détection CDN |
| **HTTP/TLS** | Headers de sécurité, info certificat TLS, technologies détectées |
| **WAF/CDN Detection** | Fingerprinting Cloudflare, Akamai, Imperva, F5, Sucuri… |
| **Sécurité Email** | SPF, DMARC, DKIM (18 sélecteurs testés), BIMI, MTA-STS |
| **Wayback Machine** | Première apparition, snapshots, URLs sensibles archivées |
| **Google Dorks** | 50+ dorks générés en 8 catégories, prêts à copier |
| **Score de risque** | Score unifié 0-100 avec 7 facteurs pondérés + recommandations |

### Pentest actif (opt-in)
| Module | Détail |
|--------|--------|
| **Port Scan** | 20 ports communs via socket (flag `--active` requis) |

### Interface & exports
- Terminal **rich** : tableaux, panneaux colorés, barres de progression, spinners
- Export **JSON** (structuré, machine-readable)
- Export **HTML** (rapport standalone dark theme, offline)
- Export **TXT** (rapport lisible)
- Export **CSV** (une ligne par domaine, pour analyse batch/SIEM)
- Mode **comparaison** (`--compare domain1 domain2`)
- Mode **batch** (fichier de domaines)
- **Cache local** 24h (`~/.nettrace/cache/`)

## Installation

```bash
git clone https://github.com/Rooot3301/NETTRACE.git
cd NETTRACE
pip install -r requirements.txt
```

### Outils optionnels (plus de sous-domaines)
```bash
# subfinder
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# amass
go install -v github.com/owasp-amass/amass/v4/...@master
```

## Usage

### Mode interactif (par défaut)
```bash
python nettrace.py
python nettrace.py -i
```

### Analyse directe
```bash
python nettrace.py -d example.com
python nettrace.py -d example.com -o report.html -f html
python nettrace.py -d example.com -o report.json --verbose
```

### Scan actif de ports (opt-in)
```bash
python nettrace.py -d example.com --active
```

### Comparer deux domaines
```bash
python nettrace.py --compare example.com google.com
```

### Output machine-readable (pipelines/SIEM)
```bash
python nettrace.py -d example.com --json | jq '.risk_score'
```

### Gestion du cache
```bash
python nettrace.py --clear-cache
python nettrace.py -d example.com --no-cache
```

## Options CLI

```
  -d, --domain       Domaine à analyser
  -o, --output       Fichier de sortie
  -f, --format       json | txt | html | csv  (défaut: json)
  --active           Active le scan de ports TCP
  --compare D1 D2    Compare deux domaines côte à côte
  --no-cache         Ignore le cache local
  --json             Output JSON pur (pas de rich, pour pipelines)
  -v, --verbose      Mode verbeux
  -i, --interactive  Menu interactif
  --clear-cache      Vide le cache et quitte
```

## Score de risque

Score unifié 0-100, 7 facteurs pondérés :

| Facteur | Poids |
|---------|-------|
| Âge du domaine | 25 pts |
| Complétude DNS | 15 pts |
| Sécurité email (SPF/DMARC/DKIM) | 20 pts |
| HTTPS + security headers | 15 pts |
| Infrastructure sous-domaines | 10 pts |
| Complétude WHOIS | 10 pts |
| Présence archives | 5 pts |

| Score | Niveau |
|-------|--------|
| 80–100 | LOW RISK |
| 60–79 | MEDIUM RISK |
| 40–59 | ELEVATED RISK |
| 0–39 | HIGH RISK |

## Sécurité email

- **SPF** : validité, mécanisme `+all` vs `-all`
- **DMARC** : policy `p=none/quarantine/reject`, `rua=`
- **DKIM** : 18 sélecteurs testés (`default`, `google`, `mail`, `selector1/2`…)
- **BIMI** : record `default._bimi`
- **MTA-STS** : record `_mta-sts`

## Subdomain Takeover

28 services détectés : GitHub Pages, Heroku, AWS S3, Azure, Zendesk, Shopify, Fastly, Netlify, WordPress.com, Surge.sh, Ghost.io, Webflow, Squarespace, Wix, Bitbucket, Intercom, Pantheon, Unbounce, Statuspage, Freshdesk…

## Exports

| Format | Usage |
|--------|-------|
| `json` | Données complètes structurées |
| `html` | Rapport dark theme standalone (offline) |
| `txt` | Rapport lisible |
| `csv` | 24 colonnes pour SIEM/Excel/batch |

## Structure

```
nettrace.py              # Point d'entrée
config.py                # Configuration et constantes
cache.py                 # Cache local (~/.nettrace/cache/)
requirements.txt
modules/
├── dns_analysis.py      # DNS + AXFR + DNSSEC
├── whois_analysis.py    # WHOIS
├── http_analysis.py     # HTTP/TLS + WAF/CDN
├── geo_analysis.py      # GeoIP + ASN (ip-api.com)
├── subdomain_analysis.py # crt.sh + takeover detection
├── email_security.py    # SPF/DMARC/DKIM/BIMI/MTA-STS
├── port_scanner.py      # TCP scan opt-in
├── archive.py           # Wayback Machine CDX API
├── scoring.py           # Score de risque unifié
└── dorks.py             # Google Dorks (50+)
exporters/
├── json_exporter.py
├── txt_exporter.py
├── csv_exporter.py
└── html_exporter.py     # Rapport HTML self-contained
```

## Dépendances

```
requests, dnspython, python-whois, python-dateutil, rich
```

Aucune clé API. Toutes les sources sont gratuites et publiques.

## Éthique

- Reconnaissance passive par défaut (sources publiques uniquement)
- `--active` (scan ports) : usage sur systèmes autorisés uniquement
- Pas d'exploitation, pas de scan intrusif

## Changelog

### v2.0 (2026-03)
- Réécriture complète en architecture modulaire
- Interface `rich` (tableaux, panels, progress bars, spinners)
- 7 nouveaux modules : HTTP/TLS, GeoIP, Email Security, Archive, Port Scanner, Dorks, Risk Score
- Détection subdomain takeover (28 services)
- Export HTML dark theme standalone
- Export CSV pour SIEM
- Mode `--compare` deux domaines
- Cache local 24h
- Output `--json` machine-readable
- Correction bug doublon argparse v1

### v1.0
- WHOIS, DNS, Sous-domaines (crt.sh), Score de confiance, Export JSON/TXT

---

**Author:** [Root3301](https://github.com/Rooot3301) — Issues: [github.com/Rooot3301/NETTRACE/issues](https://github.com/Rooot3301/NETTRACE/issues)

<div align="center"><b>Si ce projet t'aide, une étoile c'est cool</b></div>