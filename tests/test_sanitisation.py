# tests/test_sanitisation.py
"""Tests pour les fonctions de validation des entrées utilisateur."""

import pytest
from pathlib import Path
from main import valider_port, valider_cible, valider_fichier_sortie, parse_ports


# ── valider_port ─────────────────────────────────────────────────────────────

def test_valider_port_valide():
    assert valider_port(1) == 1
    assert valider_port(80) == 80
    assert valider_port(65535) == 65535

def test_valider_port_zero():
    with pytest.raises(ValueError):
        valider_port(0)

def test_valider_port_trop_grand():
    with pytest.raises(ValueError):
        valider_port(65536)

def test_valider_port_negatif():
    with pytest.raises(ValueError):
        valider_port(-1)


# ── valider_cible ─────────────────────────────────────────────────────────────

def test_valider_cible_ip():
    assert valider_cible("192.168.1.1") == "192.168.1.1"

def test_valider_cible_cidr():
    assert valider_cible("192.168.1.0/24") == "192.168.1.0/24"

def test_valider_cible_hostname():
    assert valider_cible("mon-serveur.local") == "mon-serveur.local"

def test_valider_cible_localhost():
    assert valider_cible("127.0.0.1") == "127.0.0.1"

def test_valider_cible_vide():
    with pytest.raises(ValueError):
        valider_cible("")

def test_valider_cible_caracteres_interdits():
    with pytest.raises(ValueError):
        valider_cible("192.168.1.1; rm -rf /")

def test_valider_cible_trop_long():
    with pytest.raises(ValueError):
        valider_cible("a" * 254)


# ── valider_fichier_sortie ────────────────────────────────────────────────────

def test_valider_fichier_sortie_txt():
    p = valider_fichier_sortie("scan.txt")
    assert isinstance(p, Path)

def test_valider_fichier_sortie_json():
    assert valider_fichier_sortie("resultats.json").suffix == ".json"

def test_valider_fichier_sortie_csv():
    assert valider_fichier_sortie("scan.csv").suffix == ".csv"

def test_valider_fichier_sortie_html():
    assert valider_fichier_sortie("rapport.html").suffix == ".html"

def test_valider_fichier_sortie_extension_invalide():
    with pytest.raises(ValueError):
        valider_fichier_sortie("scan.exe")

def test_valider_fichier_sortie_vide():
    with pytest.raises(ValueError):
        valider_fichier_sortie("")

def test_valider_fichier_sortie_traversal_relatif():
    with pytest.raises(ValueError):
        valider_fichier_sortie("../../etc/passwd.txt")

def test_valider_fichier_sortie_absolu_autorise(tmp_path):
    # Les chemins absolus hors cwd sont autorisés (ex. /tmp/scan.json)
    p = valider_fichier_sortie(str(tmp_path / "scan.json"))
    assert p.suffix == ".json"


# ── parse_ports ───────────────────────────────────────────────────────────────

def test_parse_ports_simple():
    assert parse_ports("80") == [80]

def test_parse_ports_plage():
    assert parse_ports("20-22") == [20, 21, 22]

def test_parse_ports_liste():
    assert parse_ports("22,80,443") == [22, 80, 443]

def test_parse_ports_combinaison():
    assert parse_ports("22,80-82,443") == [22, 80, 81, 82, 443]

def test_parse_ports_dedoublonne():
    assert parse_ports("80,80,80") == [80]

def test_parse_ports_plage_inversee():
    # L'ordre inversé est corrigé silencieusement
    assert parse_ports("85-80") == [80, 81, 82, 83, 84, 85]

def test_parse_ports_port_zero():
    with pytest.raises(ValueError):
        parse_ports("0")

def test_parse_ports_port_trop_grand():
    with pytest.raises(ValueError):
        parse_ports("65536")

def test_parse_ports_vide():
    with pytest.raises(ValueError):
        parse_ports("")

def test_parse_ports_invalide():
    with pytest.raises(ValueError):
        parse_ports("abc")


# ── threads validation ────────────────────────────────────────────────────────

def test_threads_zero_retourne_erreur():
    from main import main
    result = main(["--target", "127.0.0.1", "--ports", "80", "--threads", "0"])
    assert result == 1

def test_threads_negatif_retourne_erreur():
    from main import main
    result = main(["--target", "127.0.0.1", "--ports", "80", "--threads", "-1"])
    assert result == 1
