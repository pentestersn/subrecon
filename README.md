<div align="center">

```
 ____  _  _  ____  ____  ____  __  __  __ _
(  __)( \/ )(  _ \(  _ \(  __)/  \(  )(  ( \
 ) _)  )  /  ) __/ )   / ) _)(  O ) )( /    /
(____)(__/  (__)  (__\_)(____) \__/(__)\___)
              [ by genieyou ]
```

# subrecon

**Subdomain Enumeration & Organisation Discovery**

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Sources](https://img.shields.io/badge/Sources-11-orange?style=flat-square)]()
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey?style=flat-square)]()

</div>

---

## C'est quoi

**SubRecon** interroge **11 sources passives en parallèle**, résout le DNS sur chaque résultat, et peut retrouver **tous les domaines d'une organisation** via les certificats SSL + WHOIS/RDAP + BGP.

---

## Sources

| Source | Gratuit | Clé requise |
|--------|---------|-------------|
| **crt.sh** — Certificate Transparency | ✅ | ❌ |
| **CertSpotter** — Certificate Transparency | ✅ | ❌ |
| **HackerTarget** — Passive DNS | ✅ | ❌ |
| **AlienVault OTX** — Threat Intelligence | ✅ | ❌ |
| **URLScan.io** — Web Scans | ✅ | ❌ |
| **Wayback Machine** — Web Archive | ✅ | ❌ |
| **VirusTotal** — Multi-source | ✅ | ✅ gratuit |
| **SecurityTrails** — DNS History | ✅ | ✅ gratuit |
| **Shodan** — Internet Scan | ❌ | ✅ payant |
| **BinaryEdge** — Internet Scan + Certs | ❌ | ✅ payant |
| **BGP/ASN** — DNS inverse sur plages IP | ✅ | ❌ |

---

## Installation

```bash
git clone https://github.com/genieyou/subrecon.git
cd subrecon
pip install -r requirements.txt
```

---

## Utilisation

```bash
# un domaine
python3 subrecon.py -d example.com

# plusieurs domaines depuis un fichier
python3 subrecon.py -f domains.txt

# avec les clés API pour plus de résultats
python3 subrecon.py -d example.com \
  --vt-key TON_VT_KEY \
  --st-key TON_ST_KEY \
  --be-key TON_BE_KEY

# recherche par organisation (trouve tous les domaines + ASNs)
python3 subrecon.py --org "Example Corp"

# sans résolution DNS (plus rapide)
python3 subrecon.py -d example.com --no-resolve
```

---

## Options

| Option | Défaut | Description |
|--------|--------|-------------|
| `-d` | — | Domaine unique |
| `-f` | — | Fichier de domaines |
| `--org` | — | Recherche par organisation |
| `-o` | `subrecon_results.txt` | Fichier de sortie |
| `-t` | `100` | Threads DNS |
| `--no-resolve` | — | Skip la résolution DNS |
| `--nameservers` | `8.8.8.8 1.1.1.1 9.9.9.9` | Serveurs DNS |
| `--vt-key` | — | VirusTotal API key |
| `--st-key` | — | SecurityTrails API key |
| `--shodan-key` | — | Shodan API key |
| `--be-key` | — | BinaryEdge API key |

---

## Fichiers générés

```
subrecon_results.txt         ← résultats complets (IP, CNAME, statut)
subrecon_results_all.txt     ← liste brute (compatible httpx/nuclei/nmap)
subrecon_results_alive.txt   ← subs vivants seulement
subrecon_results_sources.txt ← stats par source
subrecon_results_org_domains.txt ← (mode --org) domaines de l'organisation
```

---

## Pipeline

```bash
# scanner les services HTTP
cat subrecon_results_alive.txt | httpx -silent -status-code -title

# chercher des vulns
cat subrecon_results_alive.txt | nuclei -t nuclei-templates/

# combiner avec asn-recon
python3 subrecon.py --org "Target Corp"
python3 asn_recon.py -f subrecon_results_org_domains.txt
```

---

## Clés API gratuites

- **VirusTotal** : https://www.virustotal.com/gui/join-us
- **SecurityTrails** : https://securitytrails.com/app/signup

---

## Disclaimer

> Usage éthique uniquement — bug bounty, pentest autorisé, audit de sa propre infra.  
> L'auteur n'est pas responsable d'une utilisation abusive.

---

## Licence

MIT — voir [LICENSE](LICENSE)

---

<div align="center">Made with 💙 by <a href="https://github.com/pentestersn"><b>youssef destefani</b></a></div>
