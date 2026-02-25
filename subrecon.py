#!/usr/bin/env python3
"""
by genieyou — SubRecon Tool
Subdomain Enumeration | Organisation Discovery | BGP/ASN Integration

uza comme ca frero:
  python3 subrecon.py -d example.com
  python3 subrecon.py -f domains.txt -t 100
  python3 subrecon.py -d example.com --vt-key XXXXX --st-key XXXXX --be-key XXXXX
  python3 subrecon.py --org "Example Corp" -o resultats.txt

installe ca avant:
  pip install dnspython requests

sources passives (toutes lancees en parallele):
  - crt.sh              (certificate transparency, gratuit)
  - certspotter         (certificate transparency, gratuit)
  - hackertarget        (passive dns, gratuit)
  - alienvault otx      (threat intel, gratuit)
  - urlscan.io          (web scans, gratuit)
  - wayback machine     (web archive, gratuit)
  - virustotal          (multi-source, cle api gratuite)
  - securitytrails      (dns history, cle api gratuite)
  - shodan              (internet scan, cle api)
  - binaryedge          (internet scan, cle api)
  - bgp/asn             (integration avec asn-recon, gratuit)

recherche par organisation:
  - certificats ssl cn+san via crt.sh
  - whois/rdap via arin
  - decouverte asn via bgp
"""

import argparse
import json
import os
import re
import socket
import sys
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from urllib.parse import quote

# requests pour les appels api, obligatoire
try:
    import requests
    requests.packages.urllib3.disable_warnings()
except ImportError:
    print("[!] pip install requests")
    sys.exit(1)

# dnspython pour resoudre les sous-domaines trouves
try:
    import dns.resolver
    import dns.exception
except ImportError:
    print("[!] pip install dnspython")
    sys.exit(1)

# ─────────────────────────────────────────────────────────
# couleurs terminal
# ─────────────────────────────────────────────────────────
R  = "\033[91m"   # rouge = erreur
G  = "\033[92m"   # vert = trouve / ok
Y  = "\033[93m"   # jaune = warning / info
B  = "\033[94m"   # bleu = info
M  = "\033[95m"   # magenta = source name
C  = "\033[96m"   # cyan = titres
W  = "\033[97m"   # blanc = donnee brute
RS = "\033[0m"    # reset
BD = "\033[1m"    # gras

# lock threading pour les prints propres sans collision
print_lock = threading.Lock()

def safe_print(msg):
    with print_lock:
        print(msg)


def banner():
    art = (
        " ____  _  _  ____  ____  ____  __  __  __ _ \n"
        "(  __)( \\/ )(  _ \\(  _ \\(  __)/  \\(  )(  ( \\\n"
        " ) _)  )  /  ) __/ )   / ) _)(  O ) )( /    /\n"
        "(____)(__/  (__)  (__\\_)(____) \\__/(__)\\____)"
    )
    print(f"\n{C}{BD}{art}{RS}")
    print(f"{Y}{BD}              [ by genieyou ]{RS}")
    print(f"{B}   Subdomain Enumeration & Organisation Discovery{RS}")
    print(f"{B}   Sources: crt.sh | certspotter | alienvault | hackertarget{RS}")
    print(f"{B}            urlscan | wayback | virustotal | securitytrails{RS}")
    print(f"{B}            shodan | binaryedge | bgp/asn{RS}\n")


# ─────────────────────────────────────────────────────────
# resolver dns global reutilisable
# ─────────────────────────────────────────────────────────
_resolver = None

def get_resolver(nameservers=None):
    global _resolver
    if _resolver is None:
        _resolver = dns.resolver.Resolver()
        _resolver.nameservers = nameservers or ["8.8.8.8", "1.1.1.1", "9.9.9.9", "8.8.4.4"]
        _resolver.timeout  = 3
        _resolver.lifetime = 5
    return _resolver


# ─────────────────────────────────────────────────────────
# resolution dns d un sous-domaine (A, AAAA, CNAME)
# ─────────────────────────────────────────────────────────
def resolve_domain(domain):
    """
    essaie de resoudre A, AAAA et CNAME pour un domaine
    retourne un dict {domain, ips, cname, alive}
    """
    result = {"domain": domain, "ips": [], "cname": None, "alive": False}
    resolver = get_resolver()

    # enregistrement A (ipv4)
    try:
        ans = resolver.resolve(domain, "A")
        result["ips"] = [str(r) for r in ans]
        result["alive"] = True
    except Exception:
        pass

    # enregistrement AAAA (ipv6)
    try:
        ans = resolver.resolve(domain, "AAAA")
        result["ips"] += [str(r) for r in ans]
        result["alive"] = True
    except Exception:
        pass

    # CNAME - utile pour detecter cloudflare, akamai, aws cloudfront etc
    try:
        ans = resolver.resolve(domain, "CNAME")
        result["cname"] = str(ans[0]).rstrip(".")
    except Exception:
        pass

    return result


# ─────────────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════
#  SOURCES PASSIVES
# ══════════════════════════════════════════════════════════
# ─────────────────────────────────────────────────────────

def source_crtsh(domain, session, **kwargs):
    """
    crt.sh = logs publics des certificats ssl/tls (certificate transparency)
    chaque fois qu un cert est emis, y est logue ici
    c est souvent la source la + riche, surtout pr les wildcard certs
    """
    found = set()
    # on interroge aussi les sous-sous-domaines avec le double wildcard
    for url in [
        f"https://crt.sh/?q=%.{domain}&output=json",
        f"https://crt.sh/?q=%.%.{domain}&output=json",
    ]:
        try:
            r = session.get(url, timeout=30)
            if r.status_code == 200:
                for entry in r.json():
                    # name_value peut contenir plusieurs noms separes par \n
                    for raw in (entry.get("name_value","") + "\n" + entry.get("common_name","")).split("\n"):
                        name = raw.strip().lower().lstrip("*.")
                        if name.endswith(f".{domain}") or name == domain:
                            found.add(name)
        except Exception:
            pass
    return found, "crt.sh"


def source_certspotter(domain, session, **kwargs):
    """
    certspotter de sslmate, autre moteur d indexation des certs ssl
    complementaire a crt.sh car pas exactement les memes certs indexes
    """
    found = set()
    try:
        url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
        r = session.get(url, timeout=20)
        if r.status_code == 200:
            for entry in r.json():
                for name in entry.get("dns_names", []):
                    name = name.lower().lstrip("*.")
                    if name.endswith(f".{domain}") or name == domain:
                        found.add(name)
    except Exception:
        pass
    return found, "certspotter"


def source_hackertarget(domain, session, **kwargs):
    """
    hackertarget = api gratuite sans cle
    utilise plusieurs sources de dns passif en arriere plan
    bonne source pour les sous-domaines peu connus
    """
    found = set()
    try:
        r = session.get(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=20)
        if r.status_code == 200 and "error" not in r.text.lower()[:50]:
            for line in r.text.strip().split("\n"):
                if "," in line:
                    sub = line.split(",")[0].strip().lower()
                    if sub.endswith(f".{domain}") or sub == domain:
                        found.add(sub)
    except Exception:
        pass
    return found, "hackertarget"


def source_alienvault(domain, session, **kwargs):
    """
    alienvault otx = plateforme de threat intelligence
    bonne source car contient des sous-domaines issus de rapports de malware,
    scans de securite, ioc etc = souvent des subs que les autres ont pas
    """
    found = set()
    page  = 1
    while True:
        try:
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns?limit=500&page={page}"
            r = session.get(url, timeout=20)
            if r.status_code != 200:
                break
            data = r.json()
            entries = data.get("passive_dns", [])
            if not entries:
                break
            for e in entries:
                h = e.get("hostname", "").lower()
                if h.endswith(f".{domain}") or h == domain:
                    found.add(h)
            if not data.get("has_next"):
                break
            page += 1
        except Exception:
            break
    return found, "alienvault"


def source_urlscan(domain, session, **kwargs):
    """
    urlscan.io = service qui scan des pages web et archive les resultats
    enormement de sous-domaines indexes, surtout ceux avec du trafic http/s
    """
    found = set()
    try:
        url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=10000"
        r = session.get(url, timeout=25)
        if r.status_code == 200:
            for result in r.json().get("results", []):
                pg = result.get("page", {}).get("domain", "").lower()
                if pg.endswith(f".{domain}") or pg == domain:
                    found.add(pg)
    except Exception:
        pass
    return found, "urlscan"


def source_wayback(domain, session, **kwargs):
    """
    wayback machine (web.archive.org) = des annees d historique du web
    plein de sous-domaines plus utilises mais qui peuvent indiquer de la surface d attaque
    ou des patterns de nommage interessants
    """
    found = set()
    try:
        url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey&limit=50000"
        r = session.get(url, timeout=30)
        if r.status_code == 200:
            for entry in r.json()[1:]:  # on saute la premiere ligne = headers
                try:
                    match = re.match(r"https?://([^/:]+)", entry[0].lower())
                    if match:
                        sub = match.group(1)
                        if sub.endswith(f".{domain}") or sub == domain:
                            found.add(sub)
                except Exception:
                    pass
    except Exception:
        pass
    return found, "wayback"


def source_virustotal(domain, session, vt_key=None, **kwargs):
    """
    virustotal api v3 = agregateur de nombreuses sources
    necessiste une cle api (plan gratuit = 4 req/min)
    une des meilleures sources car aggregate plein de moteurs
    """
    found = set()
    if not vt_key:
        return found, "virustotal"  # pas de cle = on skip proprement
    try:
        headers = {"x-apikey": vt_key}
        cursor  = None
        while True:
            url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains?limit=40"
            if cursor:
                url += f"&cursor={cursor}"
            r = session.get(url, headers=headers, timeout=20)
            if r.status_code != 200:
                break
            data = r.json()
            for item in data.get("data", []):
                sub = item.get("id", "").lower()
                if sub.endswith(f".{domain}") or sub == domain:
                    found.add(sub)
            cursor = data.get("meta", {}).get("cursor")
            if not cursor:
                break
            time.sleep(0.3)  # rate limit virustotal plan gratuit
    except Exception:
        pass
    return found, "virustotal"


def source_securitytrails(domain, session, st_key=None, **kwargs):
    """
    securitytrails = historique dns complet, une des meilleures sources
    voit les sous-domaines meme apres qu ils ont ete supprimes du dns
    cle gratuite sur leur site (500 req/mois)
    """
    found = set()
    if not st_key:
        return found, "securitytrails"
    try:
        headers = {"apikey": st_key, "Content-Type": "application/json"}
        page    = 1
        while True:
            url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains?children_only=false&include_inactive=true&page={page}"
            r = session.get(url, headers=headers, timeout=20)
            if r.status_code != 200:
                break
            data = r.json()
            for sub in data.get("subdomains", []):
                found.add(f"{sub}.{domain}".lower())
            total_pages = data.get("meta", {}).get("total_pages", 1)
            if page >= total_pages:
                break
            page += 1
    except Exception:
        pass
    return found, "securitytrails"


def source_shodan(domain, session, shodan_key=None, **kwargs):
    """
    shodan = moteur de recherche pour les appareils connectes a internet
    son api dns retourne les sous-domaines qu il a scannes
    """
    found = set()
    if not shodan_key:
        return found, "shodan"
    try:
        url = f"https://api.shodan.io/dns/domain/{domain}?key={shodan_key}"
        r   = session.get(url, timeout=20)
        if r.status_code == 200:
            for sub in r.json().get("subdomains", []):
                found.add(f"{sub}.{domain}".lower())
    except Exception:
        pass
    return found, "shodan"


def source_binaryedge(domain, session, be_key=None, **kwargs):
    """
    binaryedge = scanner internet comme shodan mais specialise dans les certificats
    et les enumerations de sous-domaines, souvent + a jour que shodan pour les certs
    api payante mais plan d essai disponible
    """
    found = set()
    if not be_key:
        return found, "binaryedge"
    try:
        headers = {"X-Key": be_key}
        page    = 1
        while True:
            url = f"https://api.binaryedge.io/v2/query/domains/subdomain/{domain}?page={page}"
            r   = session.get(url, headers=headers, timeout=20)
            if r.status_code != 200:
                break
            data = r.json()
            events = data.get("events", [])
            if not events:
                break
            for sub in events:
                sub = sub.lower()
                if sub.endswith(f".{domain}") or sub == domain:
                    found.add(sub)
            # pagination - binaryedge retourne 100 par page
            total   = data.get("total", 0)
            page_sz = data.get("pagesize", 100)
            if page * page_sz >= total:
                break
            page += 1
            time.sleep(0.5)  # respecter le rate limit
    except Exception:
        pass
    return found, "binaryedge"


def source_bgp_asn(domain, session, **kwargs):
    """
    integration bgp/asn : on recupere les sous-domaines via le dns inverse
    sur les plages d adresses ip appartenant a l organisation du domaine
    cette source trouve des subs que les autres trouvent pas car basee sur les ips
    """
    found = set()
    try:
        # d abord on resout le domaine pour avoir ses ips
        resolver = get_resolver()
        ips = []
        try:
            ans = resolver.resolve(domain, "A")
            ips = [str(r) for r in ans]
        except Exception:
            pass

        if not ips:
            return found, "bgp/asn"

        # pour chaque ip on trouve l asn
        for ip in ips[:3]:  # on prend max 3 ips pour pas trop taper les apis
            try:
                # team cymru pour trouver l asn de l ip
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(10)
                s.connect(("whois.cymru.com", 43))
                s.send(f" -v {ip}\r\n".encode())
                resp = b""
                while True:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    resp += chunk
                s.close()

                # parser la reponse pour extraire l asn
                for line in resp.decode("utf-8", errors="ignore").split("\n"):
                    if "|" in line and not line.strip().startswith("AS"):
                        parts = [p.strip() for p in line.split("|")]
                        if len(parts) >= 1 and parts[0].isdigit():
                            asn_num = parts[0]
                            # recuperer les prefixes de cet asn
                            url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn_num}"
                            r   = session.get(url, timeout=15)
                            if r.status_code == 200:
                                prefixes = [p["prefix"] for p in r.json().get("data", {}).get("prefixes", []) if ":" not in p.get("prefix","")]
                                # on cherche des ptr records sur les /24 qui correspondent
                                for prefix in prefixes[:5]:  # max 5 prefixes pr pas exploser
                                    # on extrait juste le /24 pour faire quelques ptrs
                                    parts_ip = prefix.split("/")
                                    if len(parts_ip) == 2 and int(parts_ip[1]) <= 24:
                                        base = ".".join(parts_ip[0].split(".")[:3])
                                        # on teste quelques ips du /24
                                        for last in range(1, 30):  # juste les 30 premieres
                                            test_ip = f"{base}.{last}"
                                            try:
                                                rev = dns.resolver.resolve(
                                                    ".".join(reversed(test_ip.split())) + ".in-addr.arpa", "PTR"
                                                )
                                                for ptr in rev:
                                                    h = str(ptr).rstrip(".").lower()
                                                    if h.endswith(f".{domain}") or h == domain:
                                                        found.add(h)
                                            except Exception:
                                                pass
            except Exception:
                pass
    except Exception:
        pass
    return found, "bgp/asn"


# ─────────────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════
#  RECHERCHE PAR ORGANISATION
# ══════════════════════════════════════════════════════════
# ─────────────────────────────────────────────────────────

def org_crtsh(org_name, session):
    """
    cherche tous les domaines ou le champ O= du certificat ssl
    contient le nom de l organisation
    extremement efficace pour mapper toute la surface d une entreprise
    """
    found = set()
    try:
        url = f"https://crt.sh/?O={quote(org_name)}&output=json"
        r   = session.get(url, timeout=30)
        if r.status_code == 200:
            for entry in r.json():
                for raw in (entry.get("name_value","") + "\n" + entry.get("common_name","")).split("\n"):
                    name = raw.strip().lower().lstrip("*.")
                    if "." in name and not name.startswith("."):
                        found.add(name)
    except Exception:
        pass
    return found


def org_rdap(org_name, session):
    """
    arin rdap = registre des ressources internet en amerique du nord
    permet de trouver les asn associes a une organisation
    """
    found_asns = set()
    try:
        url = f"https://rdap.arin.net/registry/entities?fn={quote(org_name)}&role=registrant"
        r   = session.get(url, timeout=20)
        if r.status_code == 200:
            for entity in r.json().get("entitySearchResults", []):
                handle = entity.get("handle", "")
                if handle.startswith("AS"):
                    found_asns.add(handle)
    except Exception:
        pass
    return found_asns


def org_get_cidrs(asn_set, session):
    """
    pour chaque asn trouve par rdap, recupere les prefixes bgp via ripe stat
    integration directe avec la logique de asn-recon
    """
    all_cidrs = {}
    for asn in asn_set:
        asn_num = re.sub(r"[^0-9]", "", asn)
        try:
            url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn_num}"
            r   = session.get(url, timeout=20)
            if r.status_code == 200:
                prefixes = [
                    p["prefix"] for p in r.json().get("data", {}).get("prefixes", [])
                    if p.get("prefix")
                ]
                if prefixes:
                    all_cidrs[asn] = prefixes
        except Exception:
            pass
    return all_cidrs


# ─────────────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════
#  PIPELINE D ENUMERATION PRINCIPAL
# ══════════════════════════════════════════════════════════
# ─────────────────────────────────────────────────────────

def enumerate_domain(domain, session, args):
    """
    lance toutes les sources passives en parallele pour un domaine
    affiche les resultats en live dans le terminal
    retourne un set de tous les sous-domaines trouves (dedupliques)
    """
    domain    = domain.lower().strip()
    all_found = set()           # tous les subs uniques
    source_stats = {}           # {source: nb_trouves}

    # callback appelee en temps reel des qu un sub est trouve
    def live_callback(subdomain, source):
        safe_print(f"  {G}[+]{RS} {W}{subdomain:<60}{RS} {M}[{source}]{RS}")

    # construction de la liste des sources avec leurs kwargs
    # chaque source prend (domain, session, **kwargs) et retourne (set, nom)
    sources = [
        (source_crtsh,        {"domain": domain, "session": session}),
        (source_certspotter,  {"domain": domain, "session": session}),
        (source_hackertarget, {"domain": domain, "session": session}),
        (source_alienvault,   {"domain": domain, "session": session}),
        (source_urlscan,      {"domain": domain, "session": session}),
        (source_wayback,      {"domain": domain, "session": session}),
        (source_virustotal,   {"domain": domain, "session": session, "vt_key":     args.vt_key}),
        (source_securitytrails,{"domain": domain,"session": session, "st_key":     args.st_key}),
        (source_shodan,       {"domain": domain, "session": session, "shodan_key": args.shodan_key}),
        (source_binaryedge,   {"domain": domain, "session": session, "be_key":     args.be_key}),
        (source_bgp_asn,      {"domain": domain, "session": session}),
    ]

    safe_print(f"  {B}[*]{RS} Lancement de {len(sources)} sources en parallèle...\n")

    # on lance tout en meme temps, chaque source dans son propre thread
    with ThreadPoolExecutor(max_workers=len(sources)) as executor:
        futures = {
            executor.submit(fn, **fkwargs): fn.__name__
            for fn, fkwargs in sources
        }

        for future in as_completed(futures):
            fn_name = futures[future]
            try:
                found, source_name = future.result()

                # on calcule les nouveaux (pas encore dans all_found)
                new_subs = found - all_found
                all_found |= found
                source_stats[source_name] = len(found)

                # afficher les nouveaux en live
                for sub in sorted(new_subs):
                    live_callback(sub, source_name)

                # afficher le bilan de la source
                status = f"{G}[+]{RS}" if found else f"{Y}[-]{RS}"
                safe_print(
                    f"\n  {status} {M}{source_name:<22}{RS}"
                    f" {G}{len(found)}{RS} subs"
                    + (f" {Y}(+{len(new_subs)} new){RS}" if new_subs else "")
                    + "\n"
                )

            except Exception as e:
                safe_print(f"  {R}[!]{RS} {fn_name} erreur: {e}\n")

    return all_found, source_stats


# ─────────────────────────────────────────────────────────
# RESOLUTION DNS DE TOUS LES SOUS-DOMAINES
# ─────────────────────────────────────────────────────────

def resolve_all(subdomains, threads=100):
    """
    resout A/AAAA/CNAME pour tous les subs en parallele
    retourne une liste de dicts
    """
    results = []
    total   = len(subdomains)
    done    = 0

    safe_print(f"\n  {B}[*]{RS} Résolution DNS de {total:,} sous-domaines ({threads} threads)...")

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(resolve_domain, sub): sub for sub in subdomains}
        for future in as_completed(futures):
            done += 1
            result = future.result()
            results.append(result)
            # barre de progression toutes les 100 ips
            if done % 100 == 0 or done == total:
                alive  = sum(1 for r in results if r["alive"])
                pct    = done / total * 100
                filled = int(pct / 4)
                bar    = "█" * filled + "░" * (25 - filled)
                with print_lock:
                    print(f"\r  [{bar}] {pct:.0f}% ({done}/{total}) | {G}{alive} alive{RS}", end="", flush=True)
    print()
    return results


# ─────────────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════
#  SAUVEGARDE TXT
# ══════════════════════════════════════════════════════════
# ─────────────────────────────────────────────────────────

def save_txt(all_data, output_file, args, elapsed):
    """
    sauvegarde les resultats en plusieurs fichiers txt:
    - fichier principal detaille (avec ips, cname, statut)
    - fichier liste brute des subs (compatible httpx, nuclei, etc)
    - fichier liste des subs vivants seulement
    """
    base = output_file.replace(".txt", "")

    # ── fichier principal ──
    with open(output_file, "w", encoding="utf-8") as f:
        f.write("=" * 70 + "\n")
        f.write("  SUBRECON — Subdomain Enumeration  by genieyou\n")
        f.write(f"  Date     : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"  Domaines : {', '.join(all_data.keys())}\n")
        total = sum(len(d["subdomains"]) for d in all_data.values())
        f.write(f"  Total    : {total} sous-domaines\n")
        f.write(f"  Durée    : {elapsed:.1f}s\n")
        f.write("=" * 70 + "\n")

        for domain, data in all_data.items():
            resolved_map = {r["domain"]: r for r in data.get("resolved", [])}
            alive_count  = sum(1 for r in data.get("resolved", []) if r["alive"])

            f.write(f"\n{'─'*70}\n")
            f.write(f"  {domain}  ({len(data['subdomains'])} subs, {alive_count} alive)\n")
            f.write(f"{'─'*70}\n\n")

            # trier par sous-domaine
            for sub in sorted(data["subdomains"]):
                info  = resolved_map.get(sub, {})
                ips   = ", ".join(info.get("ips", [])) if info.get("ips") else "unresolved"
                cname = f"  CNAME -> {info['cname']}" if info.get("cname") else ""
                alive = f"{G}[✓]{RS}" if info.get("alive") else f"{R}[✗]{RS}"
                # version sans couleurs pour le fichier
                alive_txt = "[✓]" if info.get("alive") else "[✗]"
                f.write(f"  {alive_txt} {sub:<55} {ips}{cname}\n")

    print(f"  {G}[+]{RS} Résultats complets  -> {output_file}")

    # ── liste brute de tous les subs ──
    subs_file = f"{base}_all.txt"
    with open(subs_file, "w", encoding="utf-8") as f:
        for domain, data in all_data.items():
            for sub in sorted(data["subdomains"]):
                f.write(f"{sub}\n")
    print(f"  {G}[+]{RS} Liste brute         -> {subs_file}  {Y}(compatible httpx/nuclei/nmap){RS}")

    # ── liste des subs vivants seulement ──
    alive_file = f"{base}_alive.txt"
    alive_count = 0
    with open(alive_file, "w", encoding="utf-8") as f:
        for domain, data in all_data.items():
            resolved_map = {r["domain"]: r for r in data.get("resolved", [])}
            for sub in sorted(data["subdomains"]):
                if resolved_map.get(sub, {}).get("alive"):
                    f.write(f"{sub}\n")
                    alive_count += 1
    print(f"  {G}[+]{RS} Subs vivants        -> {alive_file}  {Y}({alive_count} subs){RS}")

    # ── stats par source ──
    if any(data.get("source_stats") for data in all_data.values()):
        stats_file = f"{base}_sources.txt"
        with open(stats_file, "w", encoding="utf-8") as f:
            f.write("# Résultats par source\n\n")
            for domain, data in all_data.items():
                f.write(f"[{domain}]\n")
                for src, count in sorted(data.get("source_stats", {}).items(), key=lambda x: -x[1]):
                    f.write(f"  {src:<25} {count} subdomains\n")
                f.write("\n")
        print(f"  {G}[+]{RS} Stats par source    -> {stats_file}")


# ─────────────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════
# ─────────────────────────────────────────────────────────

def main():
    banner()

    parser = argparse.ArgumentParser(
        description="genieyou SubRecon — Subdomain Enumeration & Org Discovery",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
exemples:
  python3 subrecon.py -d example.com
  python3 subrecon.py -f domains.txt -t 150
  python3 subrecon.py --org "Example Corp"
  python3 subrecon.py -d example.com --vt-key XXXX --st-key XXXX --be-key XXXX
  python3 subrecon.py -d example.com --no-resolve
        """
    )

    # ── cibles (mutuellement exclusives) ──
    target = parser.add_mutually_exclusive_group()
    target.add_argument("-d", "--domain",   help="domaine unique a enumerer")
    target.add_argument("-f", "--file",     help="fichier de domaines (1 par ligne)")
    target.add_argument("--org",            help="nom d organisation (cherche domaines + ASNs)")

    # ── options generales ──
    parser.add_argument("-o", "--output",   default="subrecon_results.txt", help="fichier de sortie")
    parser.add_argument("-t", "--threads",  type=int, default=100,          help="threads resolution dns (defaut: 100)")
    parser.add_argument("--no-resolve",     action="store_true",            help="skip la resolution dns des resultats")
    parser.add_argument("--nameservers",    nargs="+", default=["8.8.8.8","1.1.1.1","9.9.9.9"],
                        help="serveurs dns a utiliser")

    # ── cles api (toutes optionnelles) ──
    keys = parser.add_argument_group("API keys (optionnel — ameliore les resultats)")
    keys.add_argument("--vt-key",           help="VirusTotal API key (gratuit sur virustotal.com)")
    keys.add_argument("--st-key",           help="SecurityTrails API key (gratuit sur securitytrails.com)")
    keys.add_argument("--shodan-key",       help="Shodan API key (shodan.io)")
    keys.add_argument("--be-key",           help="BinaryEdge API key (binaryedge.io)")

    args = parser.parse_args()

    # verif qu on a au moins une cible
    if not args.domain and not args.file and not args.org:
        parser.print_help()
        sys.exit(1)

    # init resolver dns et session http
    get_resolver(args.nameservers)
    session = requests.Session()
    session.headers["User-Agent"] = "genieyou-subrecon/2.0"
    session.verify = False  # on desactive la verif ssl pour eviter des erreurs sur certains sites

    # liste des domaines a traiter
    domains = []
    if args.domain:
        domains = [args.domain.lower().strip()]
    elif args.file:
        if not os.path.exists(args.file):
            print(f"{R}[!] fichier introuvable: {args.file}{RS}")
            sys.exit(1)
        with open(args.file) as f:
            domains = [l.strip().lower() for l in f if l.strip() and not l.startswith("#")]
        print(f"{G}[+] {len(domains)} domaine(s) chargé(s) depuis {args.file}{RS}\n")

    start_time = time.time()
    all_data   = {}

    # ══════════════════════════════════════════
    # MODE ORGANISATION — cherche les domaines d une orga
    # ══════════════════════════════════════════
    if args.org:
        print(f"{BD}{'═'*60}\n  RECHERCHE ORGANISATION: {C}{args.org}{RS}{BD}\n{'═'*60}{RS}\n")

        # 1. certificats ssl : le champ O= du cert contient le nom de l orga
        print(f"  {B}[*]{RS} Recherche certificats SSL pour: {C}{args.org}{RS}")
        cert_domains = org_crtsh(args.org, session)
        print(f"  {G}[+]{RS} crt.sh (O=) : {G}{len(cert_domains)}{RS} domaines\n")

        # 2. rdap pour les asn
        print(f"  {B}[*]{RS} Recherche ARIN RDAP...")
        found_asns = org_rdap(args.org, session)
        print(f"  {G}[+]{RS} ASNs trouvés : {G}{len(found_asns)}{RS}")
        for asn in sorted(found_asns):
            print(f"    {B}▶{RS} {asn}")

        # 3. prefixes bgp de chaque asn
        if found_asns:
            print(f"\n  {B}[*]{RS} Récupération des préfixes BGP...")
            cidr_map = org_get_cidrs(found_asns, session)
            for asn, cidrs in cidr_map.items():
                print(f"  {G}[+]{RS} {asn} : {G}{len(cidrs)}{RS} CIDRs")
                for cidr in cidrs:
                    print(f"    {B}▶{RS} {cidr}")

        # 4. affichage + sauvegarde des domaines trouves
        if cert_domains:
            # extraire les domaines racines uniques depuis les sous-domaines
            root_domains = set()
            for d in cert_domains:
                parts = d.split(".")
                if len(parts) >= 2:
                    root_domains.add(".".join(parts[-2:]))

            print(f"\n  {C}Domaines racines trouvés ({len(root_domains)}):{RS}")
            for rd in sorted(root_domains)[:50]:
                print(f"    {G}▶{RS} {rd}")
            if len(root_domains) > 50:
                print(f"    {Y}... +{len(root_domains)-50} autres{RS}")

            # sauvegarde
            org_file = args.output.replace(".txt", "_org_domains.txt")
            with open(org_file, "w") as f:
                f.write(f"# Domaines trouvés pour: {args.org}\n")
                f.write(f"# Date: {datetime.now().strftime('%Y-%m-%d %H:%M')}\n")
                f.write(f"# Total: {len(cert_domains)} subdomains / {len(root_domains)} domaines racines\n\n")
                f.write("# === DOMAINES RACINES ===\n")
                for rd in sorted(root_domains):
                    f.write(f"{rd}\n")
                f.write("\n# === TOUS LES SOUS-DOMAINES ===\n")
                for d in sorted(cert_domains):
                    f.write(f"{d}\n")

            print(f"\n  {G}[+]{RS} Sauvegardé -> {org_file}")
            print(f"  {Y}[i]{RS} Relance avec: {C}python3 subrecon.py -f {org_file}{RS}")

        elapsed = time.time() - start_time
        print(f"\n{G}[✓] Recherche organisation terminée en {elapsed:.1f}s{RS}\n")
        sys.exit(0)

    # ══════════════════════════════════════════
    # MODE ENUMERATION NORMALE (domaines)
    # ══════════════════════════════════════════
    for domain in domains:
        print(f"{BD}{'═'*60}\n  DOMAINE: {C}{domain}{RS}{BD}\n{'═'*60}{RS}\n")

        # enumeration passive multi-sources
        found, source_stats = enumerate_domain(domain, session, args)

        print(f"\n  {BD}{G}[✓] {len(found)} sous-domaines uniques trouvés pour {domain}{RS}\n")

        # resolution dns si pas desactivee
        resolved = []
        if not args.no_resolve and found:
            resolved = resolve_all(found, threads=args.threads)
            alive    = sum(1 for r in resolved if r["alive"])
            print(f"  {G}[✓]{RS} {alive}/{len(found)} sous-domaines vivants\n")

        all_data[domain] = {
            "subdomains":   found,
            "resolved":     resolved,
            "source_stats": source_stats,
        }

    # ══════════════════════════════════════════
    # SAUVEGARDE
    # ══════════════════════════════════════════
    elapsed = time.time() - start_time

    print(f"{BD}{'═'*60}\n  SAUVEGARDE\n{'═'*60}{RS}")
    save_txt(all_data, args.output, args, elapsed)

    # ══════════════════════════════════════════
    # RESUME FINAL
    # ══════════════════════════════════════════
    total_found = sum(len(d["subdomains"]) for d in all_data.values())
    total_alive = sum(
        sum(1 for r in d.get("resolved", []) if r["alive"])
        for d in all_data.values()
    )

    print(f"""
{BD}{'─'*50}
  RESUME  by genieyou
{'─'*50}{RS}
  domaines scannés   : {len(all_data)}
  sous-domaines      : {G}{BD}{total_found}{RS}
  vivants (DNS ok)   : {G}{BD}{total_alive}{RS}
  durée totale       : {elapsed:.1f}s
{BD}{'─'*50}{RS}
""")


# point d entree
if __name__ == "__main__":
    main()
