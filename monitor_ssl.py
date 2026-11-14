#!/usr/bin/env python3
"""Monitor certyfikatow SSL/TLS - daty waznosci certyfikatow dla listy adresow
(BIP, poczta, serwery wewnetrzne). Dla kazdego adresu: podmiot (CN), wystawca,
wazny od/do, dni do wygasniecia, SAN i status OK / OSTRZEZENIE / WYGASL / BLAD.

Certyfikat pobiera biblioteka standardowa (ssl, socket). Gdy jest nieufny,
samopodpisany albo ma niezgodna nazwe, program nadal odczytuje daty (drugie
polaczenie bez weryfikacji) i opisuje problem w kolumnie Uwagi. Odczyt pol
certyfikatu (ssl nie dekoduje certyfikatu bez weryfikacji) robi asn1crypto.
Program tylko laczy sie z podanymi adresami - nic nie wysyla poza uzgodnieniem TLS.

Uruchomienie: python monitor_ssl.py                          (okno)
              python monitor_ssl.py [plik|folder] [--prog 30] [--timeout 5] [--out folder]
                                                              (wsadowo; domyslnie INPUT/)
              python monitor_ssl.py --selftest                (test)
"""
import argparse
import concurrent.futures
import datetime
import os
import re
import socket
import ssl
import sys
import threading

if getattr(sys, "frozen", False):
    APP_DIR = os.path.dirname(sys.executable)
else:
    APP_DIR = os.path.dirname(os.path.abspath(__file__))

PROG = 30       # dni: ponizej = OSTRZEZENIE
TIMEOUT = 5.0   # sekundy na pojedyncze polaczenie
WATKI = 16
NAGLOWKI = {"host", "adres", "address", "domena", "domain", "serwer", "server", "url", "nazwa"}
KOLORY = {"OK": "C6EFCE", "OSTRZEZENIE": "FFEB9C", "WYGASL": "FFC7CE", "BLAD": "D9D9D9"}
KOLUMNY = ["Status", "Adres", "Dni do wygaśnięcia", "Ważny do (UTC)", "Ważny od (UTC)",
           "Podmiot (CN)", "Wystawca", "SAN", "Uwagi"]
# kody weryfikacji OpenSSL -> opis (bez polskich znakow: trafia tez do konsoli)
KODY = {10: "certyfikat wygasl", 9: "certyfikat jeszcze niewazny", 18: "samopodpisany",
        19: "samopodpisany w lancuchu", 20: "niezaufany wystawca (brak certyfikatu posredniego?)",
        21: "niezaufany wystawca (niepelny lancuch)", 62: "niezgodna nazwa", 64: "niezgodna nazwa (IP)"}

# ---------------------------------------------------------------- adresy ----


def parsuj_adres(tekst):
    """'https://host:8443/x' / 'host' / '[::1]:443' -> (host, port). ValueError gdy zly."""
    s = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", tekst.strip())
    s = re.split(r"[/?#]", s)[0].rsplit("@", 1)[-1]
    m = re.fullmatch(r"\[([^\]]+)\](?::(\d+))?", s)
    if m:
        host, port = m.groups()
    elif s.count(":") == 1:
        host, port = s.split(":")
    else:
        host, port = s, None  # takze goly IPv6
    host = host.strip(".")
    if not host or not re.fullmatch(r"\d*", port or ""):
        raise ValueError(tekst)
    port = int(port) if port else 443
    if not 1 <= port <= 65535:
        raise ValueError(tekst)
    try:
        host = host.encode("idna").decode("ascii")  # domeny z polskimi znakami
    except UnicodeError:
        raise ValueError(tekst)
    return host, port


def wczytaj_adresy(tekst):
    """Tekst (TXT/CSV: adres w pierwszej kolumnie, # = komentarz) -> [(oryginal, host|None, port)].
    Duplikaty pomijane, zle linie zostaja z host=None (wynik BLAD)."""
    wyn, widziane = [], set()
    for linia in tekst.splitlines():
        linia = linia.strip().lstrip("\ufeff")
        if not linia or linia.startswith("#"):
            continue
        tok = re.split(r"[;,\t ]+", linia)[0].strip("\"'")
        if tok.lower() in NAGLOWKI:
            continue
        try:
            host, port = parsuj_adres(tok)
            klucz = (host.lower(), port)
            if klucz in widziane:
                continue
            widziane.add(klucz)
            wyn.append((tok, host, port))
        except ValueError:
            wyn.append((tok, None, 0))
    return wyn


def czytaj_plik(sciezka):
    with open(sciezka, "rb") as f:
        b = f.read()
    try:
        return b.decode("utf-8-sig")
    except UnicodeDecodeError:
        return b.decode("cp1250", "replace")


def tekst_z_wejscia(sciezka):
    """Plik albo folder (wszystkie *.txt i *.csv) -> polaczony tekst z adresami."""
    if os.path.isdir(sciezka):
        pliki = sorted(os.path.join(sciezka, n) for n in os.listdir(sciezka)
                       if n.lower().endswith((".txt", ".csv")))
    else:
        pliki = [sciezka]
    return "\n".join(czytaj_plik(p) for p in pliki)

# ----------------------------------------------------------- certyfikat ----


def _handshake(host, port, timeout, ctx):
    with socket.create_connection((host, port), timeout=timeout) as s:
        with ctx.wrap_socket(s, server_hostname=host) as t:
            return t.getpeercert(binary_form=True)


def pobierz(host, port, timeout=TIMEOUT, cafile=None):
    """-> (certyfikat DER, uwaga). Najpierw polaczenie z weryfikacja; gdy certyfikat
    jest nieufny/niezgodny, drugie bez weryfikacji (CERT_NONE), zeby i tak odczytac daty."""
    try:
        return _handshake(host, port, timeout, ssl.create_default_context(cafile=cafile)), ""
    except ssl.SSLCertVerificationError as e:
        uwaga = KODY.get(e.verify_code) or "certyfikat niezaufany (kod %s)" % e.verify_code
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return _handshake(host, port, timeout, ctx), uwaga


def _nazwa(name, *pola):
    n = name.native
    for p in pola:
        v = n.get(p)
        if v:
            return ", ".join(v) if isinstance(v, list) else str(v)
    return ""


def opisz(der):
    """Certyfikat DER -> slownik pol (asn1crypto)."""
    from asn1crypto import x509
    c = x509.Certificate.load(der)
    wazn = c["tbs_certificate"]["validity"]
    cn, org = _nazwa(c.issuer, "common_name"), _nazwa(c.issuer, "organization_name")
    return {
        "cn": _nazwa(c.subject, "common_name", "organization_name") or c.subject.human_friendly,
        "wystawca": "%s (%s)" % (cn, org) if cn and org else cn or org or c.issuer.human_friendly,
        "od": wazn["not_before"].native, "do": wazn["not_after"].native,
        "san": "; ".join(str(n.native) for n in (c.subject_alt_name_value or [])),
    }


def opisz_blad(e):
    if isinstance(e, TimeoutError):  # = socket.timeout
        return "przekroczono limit czasu"
    if isinstance(e, socket.gaierror):
        return "nie znaleziono nazwy hosta"
    if isinstance(e, ConnectionRefusedError):
        return "polaczenie odrzucone (port zamkniety?)"
    if isinstance(e, ssl.SSLError):
        return "blad TLS: %s" % (e.reason or type(e).__name__)
    return "blad polaczenia (%s)" % type(e).__name__


def status(dni, prog):
    return "WYGASL" if dni < 0 else "OSTRZEZENIE" if dni < prog else "OK"


def sprawdz(adres, host, port, timeout=TIMEOUT, prog=PROG, teraz=None, cafile=None):
    """Jeden adres -> slownik wyniku (nigdy nie rzuca wyjatku)."""
    w = {"adres": "%s:%s" % (host, port) if host else adres, "status": "BLAD", "dni": None,
         "od": None, "do": None, "cn": "", "wystawca": "", "san": "", "uwagi": ""}
    if not host:
        w["uwagi"] = "niepoprawny adres"
        return w
    try:
        der, uwaga = pobierz(host, port, timeout, cafile)
        w.update(opisz(der))
    except Exception as e:  # siec/TLS/dekodowanie - kazdy blad to wiersz BLAD, nie awaria
        w["uwagi"] = opisz_blad(e)
        return w
    teraz = teraz or datetime.datetime.now(datetime.timezone.utc)
    w["dni"] = (w["do"] - teraz).days  # zaokraglone w dol: 9,9 dnia = 9
    w["status"] = status(w["dni"], prog)
    w["uwagi"] = uwaga
    return w


def sprawdz_liste(adresy, timeout=TIMEOUT, prog=PROG, po_wyniku=None, **kw):
    """Rownolegle (ThreadPool); po_wyniku(wynik) wolane z watkow roboczych."""
    wyniki = []

    def jeden(a):
        w = sprawdz(*a, timeout=timeout, prog=prog, **kw)
        if po_wyniku:
            po_wyniku(w)
        return w

    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, min(WATKI, len(adresy)))) as ex:
        wyniki = list(ex.map(jeden, adresy))
    return sortuj(wyniki)


def sortuj(wyniki):
    """Od najblizszego wygasniecia (wygasle na poczatku), bledy na koncu."""
    return sorted(wyniki, key=lambda w: (w["dni"] is None, w["dni"] or 0, w["adres"]))

# ---------------------------------------------------------------- raport ----


def raport(wyniki, out_dir, prog, teraz):
    from openpyxl import Workbook
    from openpyxl.styles import Alignment, Font, PatternFill
    from openpyxl.utils import get_column_letter

    wb = Workbook()
    ws = wb.active
    ws.title = "Certyfikaty"
    ws.append(KOLUMNY)
    for c in ws[1]:
        c.font = Font(bold=True)
        c.fill = PatternFill("solid", start_color="DDEBF7")
    for w in wyniki:
        ws.append([w["status"], w["adres"], w["dni"],
                   w["do"].replace(tzinfo=None) if w["do"] else None,
                   w["od"].replace(tzinfo=None) if w["od"] else None,
                   w["cn"], w["wystawca"], w["san"], w["uwagi"]])
        ws.cell(ws.max_row, 1).fill = PatternFill("solid", start_color=KOLORY[w["status"]])
        for k in (4, 5):
            ws.cell(ws.max_row, k).number_format = "yyyy-mm-dd hh:mm"
    for row in ws.iter_rows(min_row=2):
        for c in row:
            if isinstance(c.value, str) and c.value[:1] == "=":
                c.data_type = "s"  # CN/SAN pochodza z cudzego serwera - nie wolno ich uznac za formule
    for i, szer in enumerate((14, 32, 12, 18, 18, 30, 36, 50, 44), 1):
        ws.column_dimensions[get_column_letter(i)].width = szer
    for row in ws.iter_rows(min_row=2):
        row[7].alignment = Alignment(wrap_text=True, vertical="top")
    ws.freeze_panes = "C2"
    ws.auto_filter.ref = ws.dimensions

    p = wb.create_sheet("Podsumowanie")
    p.append(["Data kontroli", teraz.strftime("%Y-%m-%d %H:%M UTC")])
    p.append(["Próg ostrzeżenia (dni)", prog])
    p.append(["Liczba adresów", len(wyniki)])
    p.append([])
    for s in KOLORY:
        p.append([s, sum(1 for w in wyniki if w["status"] == s)])
        p.cell(p.max_row, 1).fill = PatternFill("solid", start_color=KOLORY[s])
    z_data = [w for w in wyniki if w["dni"] is not None]
    if z_data:
        n = z_data[0]  # wyniki sa posortowane
        p.append([])
        p.append(["Najbliższe wygaśnięcie", "%s (%s dni, %s)" % (n["adres"], n["dni"], n["do"].strftime("%Y-%m-%d"))])
    p.column_dimensions["A"].width = 26
    p.column_dimensions["B"].width = 60
    for r in p.iter_rows(max_col=1):
        r[0].font = Font(bold=True)

    os.makedirs(out_dir, exist_ok=True)
    plik = os.path.join(out_dir, "certyfikaty_%s.xlsx" % datetime.datetime.now().strftime("%Y-%m-%d_%H%M%S"))
    wb.save(plik)
    return plik

# ------------------------------------------------------------------- run ----


def run(tekst, out_dir, prog=PROG, timeout=TIMEOUT, log=print, po_wyniku=None, **kw):
    """tekst z adresami -> (wyniki posortowane, sciezka raportu XLSX)."""
    adresy = wczytaj_adresy(tekst)
    if not adresy:
        raise ValueError("brak adresow do sprawdzenia")
    log("Sprawdzam %d adresow (limit %s s, prog %d dni)..." % (len(adresy), timeout, prog))
    teraz = datetime.datetime.now(datetime.timezone.utc)
    wyniki = sprawdz_liste(adresy, timeout, prog, po_wyniku, teraz=teraz, **kw)
    for w in wyniki:
        log("%-12s %-40s %s %s" % (w["status"], w["adres"], "" if w["dni"] is None else "%4d dni" % w["dni"], w["uwagi"]))
    plik = raport(wyniki, out_dir, prog, teraz)
    log("Raport: %s" % plik)
    return wyniki, plik

# ------------------------------------------------------------------- GUI ----


def gui():
    import tkinter as tk
    from tkinter import filedialog, messagebox, scrolledtext, ttk

    root = tk.Tk()
    root.title("Monitor certyfikatów SSL")
    root.geometry("1150x740")
    pad = dict(padx=6, pady=3)
    v_out = tk.StringVar(value=os.path.join(APP_DIR, "OUTPUT"))
    v_prog = tk.StringVar(value=str(PROG))
    v_time = tk.StringVar(value=str(int(TIMEOUT)))
    stan = {"plik": None}

    ttk.Label(root, text="Adresy do sprawdzenia (jeden w wierszu: host albo host:port, domyślnie port 443; "
                         "# = komentarz):").pack(anchor="w", **pad)
    ramka = ttk.Frame(root)
    ramka.pack(fill="x", **pad)
    txt = tk.Text(ramka, height=7, font=("Consolas", 10))
    txt.pack(side="left", fill="x", expand=True)
    przyc = ttk.Frame(ramka)
    przyc.pack(side="left", padx=6, anchor="n")

    def wczytaj():
        for p in filedialog.askopenfilenames(initialdir=os.path.join(APP_DIR, "INPUT"),
                                             filetypes=[("Listy adresów", "*.txt *.csv"), ("Wszystkie", "*.*")]):
            txt.insert("end", czytaj_plik(p).rstrip() + "\n")

    ttk.Button(przyc, text="Wczytaj z pliku…", command=wczytaj).pack(fill="x", pady=2)
    ttk.Button(przyc, text="Wyczyść", command=lambda: txt.delete("1.0", "end")).pack(fill="x", pady=2)
    wejscie = os.path.join(APP_DIR, "INPUT")
    if os.path.isdir(wejscie):
        txt.insert("1.0", tekst_z_wejscia(wejscie))  # listy z INPUT/ od razu w polu

    o = ttk.Frame(root)
    o.pack(fill="x", **pad)
    ttk.Label(o, text="Ostrzegaj poniżej (dni):").pack(side="left", **pad)
    ttk.Spinbox(o, from_=1, to=365, width=5, textvariable=v_prog).pack(side="left", **pad)
    ttk.Label(o, text="Limit czasu (s):").pack(side="left", **pad)
    ttk.Spinbox(o, from_=1, to=60, width=5, textvariable=v_time).pack(side="left", **pad)
    ttk.Label(o, text="Folder wyjściowy:").pack(side="left", **pad)
    ttk.Entry(o, textvariable=v_out, width=50).pack(side="left", **pad)

    h = ttk.Frame(root)
    h.pack(fill="x", **pad)
    btn = ttk.Button(h, text="Sprawdź")
    btn.pack(side="left", padx=6)
    b_x = ttk.Button(h, text="Otwórz raport", state="disabled", command=lambda: os.startfile(stan["plik"]))
    b_x.pack(side="left", padx=6)
    ttk.Button(h, text="Otwórz folder", command=lambda: (
        os.makedirs(v_out.get(), exist_ok=True), os.startfile(v_out.get()))).pack(side="left", padx=6)
    postep = ttk.Label(h, text="", foreground="gray")
    postep.pack(side="left", padx=12)

    kol = ("status", "adres", "dni", "do", "cn", "wystawca", "uwagi")
    nazwy = ("Status", "Adres", "Dni", "Ważny do (UTC)", "Podmiot (CN)", "Wystawca", "Uwagi")
    rt = ttk.Frame(root)
    rt.pack(fill="both", expand=True, **pad)
    t = ttk.Treeview(rt, columns=kol, show="headings")
    for k, n, szer in zip(kol, nazwy, (100, 200, 45, 120, 180, 190, 270)):
        t.heading(k, text=n)
        t.column(k, width=szer, anchor="e" if k == "dni" else "w")
    for s, kolor in KOLORY.items():
        t.tag_configure(s, background="#" + kolor)
    sb = ttk.Scrollbar(rt, orient="vertical", command=t.yview)
    t.configure(yscrollcommand=sb.set)
    sb.pack(side="right", fill="y")
    t.pack(side="left", fill="both", expand=True)
    szczegoly = {}

    def pokaz_szczegoly(_):
        w = szczegoly.get(t.focus())
        if w:
            messagebox.showinfo("Szczegóły", "\n".join("%s: %s" % (k, v) for k, v in (
                ("Adres", w["adres"]), ("Status", w["status"]), ("Podmiot", w["cn"]), ("Wystawca", w["wystawca"]),
                ("Ważny od", w["od"]), ("Ważny do", w["do"]), ("SAN", w["san"]), ("Uwagi", w["uwagi"])) if v))

    t.bind("<Double-1>", pokaz_szczegoly)

    log_box = scrolledtext.ScrolledText(root, height=4)
    log_box.pack(fill="x", **pad)

    def log(msg):
        def put():
            log_box.insert("end", str(msg) + "\n")
            log_box.see("end")
        root.after(0, put)

    def wiersz(w):
        i = t.insert("", "end", tags=(w["status"],), values=(
            w["status"], w["adres"], "" if w["dni"] is None else w["dni"],
            w["do"].strftime("%Y-%m-%d %H:%M") if w["do"] else "", w["cn"], w["wystawca"], w["uwagi"]))
        szczegoly[i] = w

    def koniec(wyniki, plik):
        t.delete(*t.get_children())
        szczegoly.clear()
        for w in wyniki:
            wiersz(w)
        stan["plik"] = plik
        b_x.config(state="normal")
        postep.config(text="Gotowe: %d adresów" % len(wyniki))

    def start():
        # zmienne Tk czytamy tu (watek okna), nie w watku roboczym
        try:
            prog, timeout = int(v_prog.get()), float(v_time.get())
        except ValueError:
            messagebox.showerror("Błąd", "Próg (dni) i limit czasu (s) muszą być liczbami.")
            return
        tekst, out = txt.get("1.0", "end"), v_out.get().strip('" ')
        log_box.delete("1.0", "end")
        t.delete(*t.get_children())
        szczegoly.clear()
        btn.config(state="disabled")
        licznik = {"n": 0, "razem": len(wczytaj_adresy(tekst))}
        blokada = threading.Lock()

        def po_wyniku(w):
            with blokada:
                licznik["n"] += 1
                n = licznik["n"]
            root.after(0, lambda: (wiersz(w), postep.config(text="%d / %d" % (n, licznik["razem"]))))

        def work():
            try:
                wyniki, plik = run(tekst, out, prog, timeout, log, po_wyniku)
                root.after(0, lambda: koniec(wyniki, plik))
            except Exception as e:
                log("BLAD: %s" % e)
            finally:
                root.after(0, lambda: btn.config(state="normal"))

        threading.Thread(target=work, daemon=True).start()

    btn.config(command=start)
    if "--selftest" in sys.argv:
        root.after(200, root.destroy)
    import aktualizacja
    aktualizacja.start(root, "DawidBochno/Monitor-certyfikatow-SSL", "main", "monitor_ssl.py")
    root.mainloop()

# -------------------------------------------------------------- selftest ----


def _serwer(cert, klucz):
    """Lokalny serwer TLS na 127.0.0.1 (port losowy) -> (port, stop)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, klucz)
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    srv.settimeout(0.2)
    stop = threading.Event()

    def petla():
        while not stop.is_set():
            try:
                c, _ = srv.accept()
            except socket.timeout:
                continue
            try:
                ctx.wrap_socket(c, server_side=True).close()
            except (ssl.SSLError, OSError):
                c.close()  # klient przerwal przy niezaufanym certyfikacie - oczekiwane
        srv.close()

    threading.Thread(target=petla, daemon=True).start()
    return srv.getsockname()[1], stop.set


def _certy(tmp):
    """Certyfikaty testowe (biblioteka cryptography - tylko do testu): -> {nazwa: (cert.pem, key.pem)}, ca.pem."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    import ipaddress
    teraz = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
    dzien = datetime.timedelta(days=1)

    def zrob(cn, od, do, san=(), ca=None, jest_ca=False):
        klucz = ec.generate_private_key(ec.SECP256R1())
        nazwa = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
        wyst_nazwa, wyst_klucz = (ca[0].subject, ca[1]) if ca else (nazwa, klucz)
        b = (x509.CertificateBuilder().subject_name(nazwa).issuer_name(wyst_nazwa)
             .public_key(klucz.public_key()).serial_number(x509.random_serial_number())
             .not_valid_before(teraz + od * dzien).not_valid_after(teraz + do * dzien)
             .add_extension(x509.BasicConstraints(ca=jest_ca, path_length=None), critical=True)
             .add_extension(x509.SubjectKeyIdentifier.from_public_key(klucz.public_key()), critical=False))
        if jest_ca:
            b = b.add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False),
                                critical=True)
        if ca:
            b = b.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca[1].public_key()),
                                critical=False)
        if san:
            b = b.add_extension(x509.SubjectAlternativeName(
                [x509.IPAddress(ipaddress.ip_address(s)) if s[0].isdigit() else x509.DNSName(s) for s in san]),
                critical=False)
        return b.sign(wyst_klucz, hashes.SHA256()), klucz

    def zapisz(nazwa, cert, klucz):
        c, k = os.path.join(tmp, nazwa + ".pem"), os.path.join(tmp, nazwa + ".key")
        with open(c, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        with open(k, "wb") as f:
            f.write(klucz.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                        serialization.NoEncryption()))
        return c, k

    ca = zrob("Testowy CA", -10, 3000, jest_ca=True)
    ca_pem = zapisz("ca", *ca)[0]
    wyn = {
        "dobry": zapisz("dobry", *zrob("dobry.test", -10, 200, ["127.0.0.1", "dobry.test"], ca)),
        "niezgodny": zapisz("niezgodny", *zrob("inny.test", -10, 100, ["inny.test"], ca)),
        "krotki": zapisz("krotki", *zrob("krotki.test", -300, 10, ["127.0.0.1"])),  # samopodpisany
        "wygasly": zapisz("wygasly", *zrob("wygasly.test", -100, -5, ["127.0.0.1"])),
    }
    return wyn, ca_pem


def selftest():
    import tempfile
    # --- adresy
    assert parsuj_adres("example.com") == ("example.com", 443)
    assert parsuj_adres("https://Example.com:8443/x?y") == ("Example.com", 8443)
    assert parsuj_adres("[::1]:444") == ("::1", 444) and parsuj_adres("::1") == ("::1", 443)
    assert parsuj_adres("bip.zażółć.pl")[0].startswith("bip.xn--")
    for zly in ("host:abc", "host:0", "host:70000", ":443", ""):
        try:
            parsuj_adres(zly)
            assert False, zly
        except ValueError:
            pass
    a = wczytaj_adresy("\ufeffadres;uwagi\n# komentarz\na.pl\nA.pl:443, dup\nb.pl:8443;BIP\nzly:port\n\n")
    assert [(x[1], x[2]) for x in a] == [("a.pl", 443), ("b.pl", 8443), (None, 0)], a
    # --- status
    assert [status(d, 30) for d in (-1, 0, 29, 30, 500)] == ["WYGASL", "OSTRZEZENIE", "OSTRZEZENIE", "OK", "OK"]
    # --- raport: tekst z certyfikatu zaczynajacy sie od "=" nie moze byc formula
    from openpyxl import load_workbook
    zl = {"adres": "=A1", "status": "BLAD", "dni": None, "od": None, "do": None, "cn": '=HYPERLINK("http://x","y")',
          "wystawca": "", "san": "=1+1", "uwagi": ""}
    c = load_workbook(raport([zl], tempfile.mkdtemp(), 30, datetime.datetime.now(datetime.timezone.utc)))["Certyfikaty"]["F2"]
    assert c.data_type == "s" and c.value.startswith("="), c.data_type
    assert wczytaj_adresy('"a.pl";x')[0][1] == "a.pl"
    # --- sortowanie
    s = sortuj([{"dni": None, "adres": "z"}, {"dni": 50, "adres": "b"}, {"dni": -3, "adres": "a"}])
    assert [x["adres"] for x in s] == ["a", "b", "z"]

    # --- serwery TLS na 127.0.0.1 (certy z biblioteki cryptography - tylko test/CI)
    try:
        import cryptography  # noqa: F401
    except ImportError:
        assert not os.environ.get("CI"), "w CI wymagana biblioteka cryptography"
        print("brak biblioteki cryptography - pomijam test z serwerem TLS (pip install cryptography)")
    else:
        tmp = tempfile.mkdtemp()
        certy, ca_pem = _certy(tmp)
        stopy, porty = [], {}
        for n, (c, k) in certy.items():
            porty[n], stop = _serwer(c, k)
            stopy.append(stop)
        zamkniety = socket.socket()
        zamkniety.bind(("127.0.0.1", 0))
        porty["zamkniety"] = zamkniety.getsockname()[1]
        zamkniety.close()
        martwy = socket.socket()  # przyjmuje polaczenia, ale nigdy nie odpowiada na TLS
        martwy.bind(("127.0.0.1", 0))
        martwy.listen(5)
        porty["martwy"] = martwy.getsockname()[1]
        try:
            def spr(n, **kw):
                return sprawdz("x", "127.0.0.1", porty[n], timeout=kw.pop("timeout", 3), cafile=ca_pem, **kw)

            w = spr("dobry")
            assert w["status"] == "OK" and w["uwagi"] == "", w
            assert 198 <= w["dni"] <= 200 and w["cn"] == "dobry.test", w
            assert "127.0.0.1" in w["san"] and "dobry.test" in w["san"], w["san"]
            assert "Testowy CA" in w["wystawca"] and w["od"] < w["do"], w
            w = spr("niezgodny")  # zaufany lancuch, ale nazwa nie pasuje - daty mimo to odczytane
            assert w["status"] == "OK" and "niezgodna nazwa" in w["uwagi"] and w["cn"] == "inny.test", w
            w = spr("krotki")
            assert w["status"] == "OSTRZEZENIE" and 9 <= w["dni"] <= 10, w
            assert "samopodpisany" in w["uwagi"] and w["wystawca"] == "krotki.test", w
            assert spr("krotki", prog=5)["status"] == "OK"  # prog ustawialny
            w = spr("wygasly")
            assert w["status"] == "WYGASL" and -6 <= w["dni"] <= -5 and w["cn"] == "wygasly.test", w
            w = spr("zamkniety")
            assert w["status"] == "BLAD" and "odrzucone" in w["uwagi"] and w["dni"] is None, w
            w = spr("martwy", timeout=1)
            assert w["status"] == "BLAD" and "limit czasu" in w["uwagi"], w
            assert sprawdz("x", None, 0)["uwagi"] == "niepoprawny adres"
            # data wstrzykiwana: ten sam certyfikat w przyszlosci -> WYGASL
            przyszlosc = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=400)
            assert spr("dobry", teraz=przyszlosc)["status"] == "WYGASL"

            # --- run(): plik CSV z naglowkiem i separatorem ';', raport XLSX
            wej = os.path.join(tmp, "lista.csv")
            with open(wej, "w", encoding="utf-8") as f:
                f.write("adres;opis\n")
                for n in ("dobry", "krotki", "wygasly", "zamkniety", "niezgodny"):
                    f.write("127.0.0.1:%d;%s\n" % (porty[n], n))
                f.write("zly:adres\n")
            wyniki, plik = run(tekst_z_wejscia(wej), os.path.join(tmp, "out"), 30, 3, lambda m: None, cafile=ca_pem)
            assert [w["status"] for w in wyniki] == ["WYGASL", "OSTRZEZENIE", "OK", "OK", "BLAD", "BLAD"], \
                [(w["status"], w["adres"]) for w in wyniki]
            from openpyxl import load_workbook
            wb = load_workbook(plik)
            assert wb.sheetnames == ["Certyfikaty", "Podsumowanie"]
            ws = wb["Certyfikaty"]
            assert [r[0].value for r in ws.iter_rows(min_row=2)] == [w["status"] for w in wyniki]
            assert ws["A2"].fill.start_color.rgb.endswith(KOLORY["WYGASL"])
            assert ws["A3"].fill.start_color.rgb.endswith(KOLORY["OSTRZEZENIE"])
            assert ws["A6"].fill.start_color.rgb.endswith(KOLORY["BLAD"])
            assert ws["D2"].value is not None and ws["C2"].value < 0
            pod = {r[0].value: r[1].value for r in wb["Podsumowanie"].iter_rows()}
            assert pod["OK"] == 2 and pod["WYGASL"] == 1 and pod["BLAD"] == 2 and pod["Liczba adresów"] == 6, pod
            assert "Najbliższe wygaśnięcie" in pod
            # folder: tylko *.txt i *.csv
            os.replace(wej, os.path.join(tmp, "out", "a.csv"))
            with open(os.path.join(tmp, "out", "b.txt"), "w") as f:
                f.write("b.pl\n")
            assert "b.pl" in tekst_z_wejscia(os.path.join(tmp, "out")) and "xlsx" not in tekst_z_wejscia(os.path.join(tmp, "out"))
            print("serwer TLS: 6 przypadkow (OK, niezgodna nazwa, <30 dni, wygasly, zamkniety port, brak odpowiedzi) OK")
        finally:
            for stop in stopy:
                stop()
            martwy.close()

    import aktualizacja
    aktualizacja.selftest()
    print("selftest OK")


def main():
    ap = argparse.ArgumentParser(description="Monitor certyfikatow SSL")
    ap.add_argument("wejscie", nargs="?", help="plik TXT/CSV albo folder z listami (domyslnie INPUT/)")
    ap.add_argument("--bez-okna", action="store_true", help="wsadowo, bez okna")
    ap.add_argument("--out", default=os.path.join(APP_DIR, "OUTPUT"))
    ap.add_argument("--prog", type=int, default=PROG, help="ostrzezenie ponizej N dni (domyslnie %d)" % PROG)
    ap.add_argument("--timeout", type=float, default=TIMEOUT)
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--gui", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        selftest()
        if a.gui:
            gui()
    elif a.wejscie or a.bez_okna:
        try:
            run(tekst_z_wejscia(a.wejscie or os.path.join(APP_DIR, "INPUT")), a.out, a.prog, a.timeout)
        except (ValueError, OSError) as e:
            sys.exit("BLAD: %s" % e)
    else:
        gui()


if __name__ == "__main__":
    main()
