"""Kalkan simgelerini çizer.

    ../../venv/bin/python ikonlar.py

kaynak-ikon.png (1024px, uygulama simgesi; `npx tauri icon` bundan tüm boyutları üretir)
src-tauri/icons/tepsi.png        menü çubuğu, şablon (macOS açık/koyu temaya göre boyar)
src-tauri/icons/tepsi-uyari.png  menü çubuğu, uyarı varken (kırmızı)
"""

from pathlib import Path

from PIL import Image, ImageDraw, ImageFilter

BURADA = Path(__file__).parent
IKONLAR = BURADA / "src-tauri" / "icons"


def kalkan_sekli(cx, ust, gen, yuk):
    """Kalkan çokgeni: düz üst kenar, yuvarlak omuzlar, sivri alt uç."""
    import math

    yari = gen / 2
    noktalar = []
    # üst kenar hafif içe kavisli
    for i in range(21):
        t = i / 20
        x = cx - yari + gen * t
        y = ust + yuk * 0.06 * math.sin(math.pi * t)
        noktalar.append((x, y))
    # sağ kenar: dik iner, sonra uca doğru kavis
    for i in range(1, 41):
        t = i / 40
        x = cx + yari * (1 - t**2.2)
        y = ust + yuk * (0.08 + 0.92 * t)
        noktalar.append((x, y))
    # sol kenar (ayna)
    for i in range(39, 0, -1):
        t = i / 40
        x = cx - yari * (1 - t**2.2)
        y = ust + yuk * (0.08 + 0.92 * t)
        noktalar.append((x, y))
    return noktalar


def uygulama_ikonu():
    n = 1024
    olcek = 4  # pürüzsüz kenar için büyük çiz, sonra küçült
    N = n * olcek
    img = Image.new("RGBA", (N, N), (0, 0, 0, 0))

    # macOS tarzı yuvarlak kare, koyu lacivertten turkuaza dikey geçiş
    zemin = Image.new("RGBA", (N, N))
    zd = ImageDraw.Draw(zemin)
    for y in range(N):
        t = y / N
        r = int(14 + (16 - 14) * t)
        g = int(30 + (120 - 30) * t)
        b = int(60 + (130 - 60) * t)
        zd.line([(0, y), (N, y)], fill=(r, g, b, 255))
    maske = Image.new("L", (N, N), 0)
    kenar = int(N * 0.1)
    ImageDraw.Draw(maske).rounded_rectangle(
        [kenar, kenar, N - kenar, N - kenar], radius=int(N * 0.18), fill=255
    )
    img.paste(zemin, (0, 0), maske)

    # kalkan: hafif gölge + beyaz gövde
    sekil = kalkan_sekli(N / 2, N * 0.24, N * 0.46, N * 0.54)
    golge = Image.new("RGBA", (N, N), (0, 0, 0, 0))
    ImageDraw.Draw(golge).polygon([(x, y + N * 0.012) for x, y in sekil], fill=(0, 0, 0, 90))
    golge = golge.filter(ImageFilter.GaussianBlur(N * 0.012))
    img = Image.alpha_composite(img, golge)
    d = ImageDraw.Draw(img)
    d.polygon(sekil, fill=(245, 250, 252, 255))

    # içte nabız çizgisi (ağ izleme)
    w = N * 0.024
    cizgi = [
        (N * 0.36, N * 0.50), (N * 0.44, N * 0.50), (N * 0.48, N * 0.41),
        (N * 0.53, N * 0.60), (N * 0.57, N * 0.50), (N * 0.64, N * 0.50),
    ]
    d.line(cizgi, fill=(16, 110, 125, 255), width=int(w), joint="curve")
    for x, y in (cizgi[0], cizgi[-1]):
        d.ellipse([x - w / 2, y - w / 2, x + w / 2, y + w / 2], fill=(16, 110, 125, 255))

    img = img.resize((n, n), Image.LANCZOS)
    img.save(BURADA / "kaynak-ikon.png")


def tepsi_ikonu(dosya, renk, unlem):
    """Menü çubuğu simgesi: 44x44 (Retina'da 22pt)."""
    n, olcek = 44, 8
    N = n * olcek
    img = Image.new("RGBA", (N, N), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    sekil = kalkan_sekli(N / 2, N * 0.1, N * 0.66, N * 0.8)
    d.polygon(sekil, fill=renk)
    # içi oyuk: biraz küçük kalkanı sil
    ic = kalkan_sekli(N / 2, N * 0.19, N * 0.48, N * 0.6)
    oyuk = Image.new("L", (N, N), 0)
    ImageDraw.Draw(oyuk).polygon(ic, fill=255)
    img.putalpha(Image.eval(img.getchannel("A"), lambda a: a).point(lambda a: a))
    alfa = img.getchannel("A")
    alfa.paste(0, (0, 0), oyuk)
    img.putalpha(alfa)
    d = ImageDraw.Draw(img)
    if unlem:
        cx = N / 2
        d.rounded_rectangle([cx - N * 0.045, N * 0.30, cx + N * 0.045, N * 0.55], radius=N * 0.04, fill=renk)
        d.ellipse([cx - N * 0.05, N * 0.60, cx + N * 0.05, N * 0.70], fill=renk)
    else:
        w = N * 0.07
        d.line(
            [(N * 0.38, N * 0.46), (N * 0.47, N * 0.56), (N * 0.63, N * 0.36)],
            fill=renk, width=int(w), joint="curve",
        )
    img.resize((n, n), Image.LANCZOS).save(IKONLAR / dosya)


if __name__ == "__main__":
    IKONLAR.mkdir(parents=True, exist_ok=True)
    uygulama_ikonu()
    tepsi_ikonu("tepsi.png", (0, 0, 0, 255), unlem=False)
    tepsi_ikonu("tepsi-uyari.png", (235, 70, 60, 255), unlem=True)
    print("Simgeler hazır.")
