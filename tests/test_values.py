import random
import re

from masquer.synth.values import Faker, iban_check, luhn_digit


def fake(seed=7):
    return Faker(random.Random(seed))


def test_personnummer_luhn():
    f = fake()
    for _ in range(200):
        p = f.personnummer_se()
        digits = p.replace("-", "")
        assert re.fullmatch(r"\d{6}-\d{4}", p)
        assert luhn_digit(digits[:9]) == int(digits[9])


def test_orgnr_luhn():
    f = fake()
    for _ in range(100):
        d = f.orgnr_se().replace("-", "")
        assert int(d[2]) >= 2 and luhn_digit(d[:9]) == int(d[9])


def test_fodselsnummer_mod11():
    f = fake()
    w1, w2 = [3, 7, 6, 1, 8, 9, 4, 5, 2, 1], [5, 4, 3, 2, 7, 6, 5, 4, 3, 2, 1]
    for _ in range(100):
        n = f.fodselsnummer_no()
        assert sum(int(a) * b for a, b in zip(n, w1)) % 11 == 0
        assert sum(int(a) * b for a, b in zip(n, w2)) % 11 == 0


def test_cpr_mod11():
    f = fake()
    w = [4, 3, 2, 7, 6, 5, 4, 3, 2, 1]
    for _ in range(100):
        n = f.cpr_dk().replace("-", "")
        assert sum(int(a) * b for a, b in zip(n, w)) % 11 == 0


def test_hetu_check():
    f = fake()
    for _ in range(100):
        h = f.hetu_fi()
        assert "0123456789ABCDEFHJKLMNPRSTUVWXY"[int(h[:6] + h[7:10]) % 31] == h[10]


def test_iban_mod97():
    f = fake()
    for _ in range(100):
        i = f.iban()
        r = i[4:] + i[:4]
        assert int("".join(str(int(c, 36)) for c in r)) % 97 == 1
    assert iban_check("GB", "WEST12345698765432") == "82"  # ECBS example


def test_reserved_ranges():
    f = fake()
    for _ in range(300):
        d = f.domain()
        assert d.endswith(".example")
        ip = f.customer_public_ip()
        assert ip.startswith("203.0.113.")


def test_canaries_recorded():
    f = fake()
    v = f.upn()
    assert v in f.canaries["upn"]


def test_ascii_name():
    from masquer.synth.values import ascii_name
    assert ascii_name("Åsa") == "asa"
    assert ascii_name("Øberg") == "oberg"
    assert ascii_name("Schröder") == "schroder"
    assert ascii_name("O'Brien") == "obrien"
    assert ascii_name("Sigurðsson") == "sigurdsson"
