//! Čistenie metadát obrázkov pred uložením (B8/MYHSN-22, návrh doc 24 §2
//! krok 3). Dôvod: `GET /media/{id}` je **bez autentizácie** — GPS súradnice
//! v EXIF alebo IPTC popis v obálke kanála by ktokoľvek mohol čítať (GDPR).
//!
//! Pravidlá (presne podľa návrhu):
//! - **JPEG:** zahodiť APP1 s XMP a APP13 (IPTC); v EXIF APP1 **vynulovať
//!   GPS IFD** (tag `0x8825`); **orientation, ICC (APP2) a APP0 nechať** —
//!   inak by sa fotky z telefónu zobrazovali otočené.
//! - **PNG:** zahodiť chunky `eXIf`, `tEXt`, `iTXt`, `zTXt`; ostatné
//!   (IHDR/PLTE/IDAT/IEND/gAMA/…) nechať.
//!
//! Je to čisté parsovanie bajtov **bez knižnice na dekódovanie obrázkov**
//! (žiadna nová závislosť). Kritické je nepoškodiť pixelové dáta: segmenty
//! a chunky sa len vyberajú, neprepisujú sa okrem 4 bajtov GPS ukazovateľa
//! v EXIF. CRC PNG chunkov sa nemení (data chunkov ostávajú), takže sa
//! nedosadzujú.
//!
//! Best-effort správanie: nezaparsovateľné EXIF → APP1 sa zahodí (bez
//! platného TIFF headeru aj tak neexistuje orientation, ktorý by stálo za
//! to zachovať); skrátený/poškodený stream → zvyšok sa ponechá ako bol.

/// Magic bytes JPEG: `FF D8 FF` (SOI + prvý marker).
pub const JPEG_MAGIC: &[u8] = &[0xFF, 0xD8, 0xFF];
/// Magic bytes PNG: 8-bajtová signatúra štandardu.
pub const PNG_MAGIC: &[u8] = &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];

/// Rozlíši podporovaný typ podľa magic bytes. `None` = nepodporovaný formát
/// (WebP, GIF, SVG, …) → API vráti 415.
pub fn detect_mime(bytes: &[u8]) -> Option<&'static str> {
    if bytes.starts_with(JPEG_MAGIC) {
        Some("image/jpeg")
    } else if bytes.starts_with(PNG_MAGIC) {
        Some("image/png")
    } else {
        None
    }
}

/// Vyčisti metadata podľa typu. `None` = bajty nezodpovedajú typu (napr.
/// `image/jpeg` bez magic) — volajúci to rieši ako 415.
pub fn clean(bytes: &[u8], mime: &str) -> Option<Vec<u8>> {
    match mime {
        "image/jpeg" if bytes.starts_with(&[0xFF, 0xD8]) => Some(clean_jpeg(bytes)),
        "image/png" if bytes.starts_with(PNG_MAGIC) => Some(clean_png(bytes)),
        _ => None,
    }
}

// --- JPEG ------------------------------------------------------------------

/// EXIF IFD tag: ukazovateľ na GPS IFD. Jeho 4-bajtová hodnota sa nuluje.
const TAG_GPS_IFD: u16 = 0x8825;
/// EXIF IFD tag: ukazovateľ na Exif sub-IFD (prejdeme aj ním — GPSInfo sa
/// v divných súboroch občas objaví aj tam).
const TAG_EXIF_IFD: u16 = 0x8769;

/// Vyber nepotrebné APP segmenty a vynuluj GPS IFD v EXIF. SOI, EOI a
/// entropy-coded data ostávajú bez zmeny. Prechádza segmenty za SOI:
/// každá `FF nn` (nn ≠ 00) je podľa špecifikácie marker (v dátach sa FF
/// vyskytuje len ako `FF 00` stuffing), takže po prvom ne-FF bajte za SOS
/// sa zvyšok streamu ponechá ako celok — všetky APP segmenty predchádzajú
/// prvému SOS aj v progresívnych JPEG-och.
fn clean_jpeg(bytes: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    out.extend_from_slice(&bytes[..2.min(bytes.len())]); // SOI
    let mut i = 2usize;
    while i + 1 < bytes.len() {
        if bytes[i] != 0xFF {
            // mimo segmentovej štruktúry (entropy data) — zvyšok ponechaj
            out.extend_from_slice(&bytes[i..]);
            return out;
        }
        let marker = bytes[i + 1];
        if marker == 0xFF {
            // FF fill pred markerom — preskoč jeden bajt
            i += 1;
            continue;
        }
        if marker == 0x00 {
            // FF00 stuffing — ponechaj a pokračuj
            out.extend_from_slice(&[0xFF, 0x00]);
            i += 2;
            continue;
        }
        if marker == 0x01 || (0xD0..=0xD7).contains(&marker) {
            // TEM / RSTn — samostatné markery bez dĺžky
            out.extend_from_slice(&bytes[i..i + 2]);
            i += 2;
            continue;
        }
        if marker == 0xD9 {
            // EOI — ponechaj seba aj zvyšok streamu
            out.extend_from_slice(&bytes[i..]);
            return out;
        }
        if i + 4 > bytes.len() {
            // neúplný header segmentu — zvyšok ponechaj
            out.extend_from_slice(&bytes[i..]);
            return out;
        }
        let seg_len = u16::from_be_bytes([bytes[i + 2], bytes[i + 3]]) as usize;
        if seg_len < 2 || i + 2 + seg_len > bytes.len() {
            // neplatná dĺžka (poškodený súbor) — zvyšok bez úprav
            out.extend_from_slice(&bytes[i..]);
            return out;
        }
        let payload = &bytes[i + 4..i + 2 + seg_len];
        let kept: Option<Vec<u8>> = match marker {
            0xE1 => {
                // APP1: EXIF alebo XMP
                if payload.starts_with(b"Exif\0\0") {
                    let mut p = payload.to_vec();
                    if sanitize_exif(&mut p[6..]) {
                        Some(p) // EXIF po vynulovaní GPS
                    } else {
                        None // neplatný TIFF — bez orientation aj tak
                    }
                } else if payload.starts_with(b"http://ns.adobe.com/xap/1.0/") {
                    None // XMP preč
                } else {
                    Some(payload.to_vec())
                }
            }
            0xED => None, // APP13 = IPTC preč
            _ => Some(payload.to_vec()),
        };
        if let Some(p) = kept {
            // dĺžka segmentu sa nemení (EXIF sanitize len nuluje 4 bajty,
            // ostatné ponechané segmenty idú bez zmeny bajtov)
            out.extend_from_slice(&bytes[i..i + 4]);
            out.extend_from_slice(&p);
        }
        i += 2 + seg_len;
    }
    if i < bytes.len() {
        out.extend_from_slice(&bytes[i..]);
    }
    out
}

/// Vynuluje GPS IFD ukazovatele v TIFF štruktúre (payload EXIF APP1 bez
/// prefixu `Exif\0\0`). Vráti `false`, ak TIFF header nie je platný.
fn sanitize_exif(tiff: &mut [u8]) -> bool {
    if tiff.len() < 8 {
        return false;
    }
    let little = match &tiff[0..2] {
        b"II" => true,
        b"MM" => false,
        _ => return false,
    };
    if rd_u16(tiff, 2, little) != Some(0x002A) {
        return false;
    }
    let ifd0 = match rd_u32(tiff, 4, little) {
        Some(v) => v as usize,
        None => return false,
    };
    walk_ifd(tiff, ifd0, little, 0);
    true
}

/// Prejde IFD reťazec + Exif sub-IFD a vynuluje hodnoty tagu `0x8825`.
/// Hĺbka 4 stačí (IFD0 → Exif sub-IFD; IFD0 → IFD1 → IFD2) a bráni cyklu
/// v poškodených súboroch.
fn walk_ifd(tiff: &mut [u8], ifd_off: usize, little: bool, depth: u32) {
    if depth > 4 {
        return;
    }
    let count = match rd_u16(tiff, ifd_off, little) {
        Some(c) => c as usize,
        None => return,
    };
    let entries_start = ifd_off + 2;
    for n in 0..count {
        let e = entries_start + n * 12;
        let tag = match rd_u16(tiff, e, little) {
            Some(t) => t,
            None => return,
        };
        match tag {
            TAG_GPS_IFD => {
                // vynuluj 4-bajtovú hodnotu ukazovateľa (e+8..e+12)
                if e + 12 <= tiff.len() {
                    tiff[e + 8..e + 12].copy_from_slice(&[0u8; 4]);
                }
            }
            TAG_EXIF_IFD => {
                if let Some(off) = rd_u32(tiff, e + 8, little) {
                    walk_ifd(tiff, off as usize, little, depth + 1);
                }
            }
            _ => {}
        }
    }
    // ďalší IFD (IFD1 — náhľad, občas s vlastným GPSInfo)
    let next_off = entries_start + count * 12;
    if let Some(next) = rd_u32(tiff, next_off, little) {
        if next != 0 {
            walk_ifd(tiff, next as usize, little, depth + 1);
        }
    }
}

fn rd_u16(b: &[u8], off: usize, little: bool) -> Option<u16> {
    let s: [u8; 2] = b.get(off..off + 2)?.try_into().ok()?;
    Some(if little {
        u16::from_le_bytes(s)
    } else {
        u16::from_be_bytes(s)
    })
}

fn rd_u32(b: &[u8], off: usize, little: bool) -> Option<u32> {
    let s: [u8; 4] = b.get(off..off + 4)?.try_into().ok()?;
    Some(if little {
        u32::from_le_bytes(s)
    } else {
        u32::from_be_bytes(s)
    })
}

// --- PNG -------------------------------------------------------------------

/// Chunky, ktoré obsahujú metadáta (popisy, EXIF, XMP) a zahadzujeme ich.
const PNG_DROP_CHUNKS: [&[u8; 4]; 4] = [b"eXIf", b"tEXt", b"iTXt", b"zTXt"];

/// Obalí PNG znova bez metadata chunkov. Neúplný stream sa ponechá ako bol.
fn clean_png(bytes: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    out.extend_from_slice(&bytes[..8]);
    let mut i = 8usize;
    while i + 8 <= bytes.len() {
        let len = u32::from_be_bytes([bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3]]) as usize;
        let typ: [u8; 4] = bytes[i + 4..i + 8].try_into().unwrap();
        // data + CRC4 musia obojstranne sediet do streamu
        if i + 8 + len + 4 > bytes.len() {
            break; // neúplný chunk — zvyšok ponechaj bez úprav
        }
        if !PNG_DROP_CHUNKS.contains(&&typ) {
            out.extend_from_slice(&bytes[i..i + 8 + len + 4]);
        }
        i += 8 + len + 4;
        if typ == *b"IEND" {
            break; // za IEND nič relevantné nie je
        }
    }
    if i < bytes.len() {
        out.extend_from_slice(&bytes[i..]);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pomocník: zostav JPEG segment (marker + 2B dĺžka + payload).
    fn seg(marker: u8, payload: &[u8]) -> Vec<u8> {
        let len = (payload.len() + 2) as u16;
        let mut v = vec![0xFF, marker];
        v.extend_from_slice(&len.to_be_bytes());
        v.extend_from_slice(payload);
        v
    }

    fn put16(v: &mut Vec<u8>, x: u16, le: bool) {
        let b = if le { x.to_le_bytes() } else { x.to_be_bytes() };
        v.extend_from_slice(&b);
    }
    fn put32(v: &mut Vec<u8>, x: u32, le: bool) {
        let b = if le { x.to_le_bytes() } else { x.to_be_bytes() };
        v.extend_from_slice(&b);
    }

    /// Zostaví EXIF APP1 payload: TIFF header + IFD0 (orientation, ExifIFD
    /// pointer, GPSInfo pointer) + Exif sub-IFD + GPS IFD. Obe byte orders.
    fn exif_payload(little: bool) -> Vec<u8> {
        let mut tiff: Vec<u8> = Vec::new();
        tiff.extend_from_slice(if little { b"II" } else { b"MM" });
        put16(&mut tiff, 0x002A, little);
        put32(&mut tiff, 8, little); // IFD0 hneď za headerom
        // IFD0 na offsete 8: 3 entries
        put16(&mut tiff, 3, little);
        // orientation (0x0112, SHORT, count 1): hodnota SHORT je v 4B poli
        // ľavostranne zarovnaná podľa endianu — big: [0,6,0,0], little: [6,0,0,0]
        put16(&mut tiff, 0x0112, little);
        put16(&mut tiff, 3, little);
        put32(&mut tiff, 1, little);
        tiff.extend_from_slice(if little { &[6u8, 0, 0, 0] } else { &[0u8, 6, 0, 0] });
        // ExifIFD pointer (LONG): sub-IFD na offsete 50
        put16(&mut tiff, TAG_EXIF_IFD, little);
        put16(&mut tiff, 4, little);
        put32(&mut tiff, 1, little);
        put32(&mut tiff, 50, little);
        // GPSInfo pointer (LONG): GPS IFD na offsete 68
        put16(&mut tiff, TAG_GPS_IFD, little);
        put16(&mut tiff, 4, little);
        put32(&mut tiff, 1, little);
        put32(&mut tiff, 68, little);
        put32(&mut tiff, 0, little); // ďalší IFD nie je
        // Exif sub-IFD na 50: 1 entry (0x9000 version) + next = 0
        put16(&mut tiff, 1, little);
        put16(&mut tiff, 0x9000, little);
        put16(&mut tiff, 1, little);
        put32(&mut tiff, 4, little);
        put32(&mut tiff, 0, little); // hodnota
        put32(&mut tiff, 0, little); // next
        // GPS IFD na 68: 1 entry (0x0001 lat ref ASCII "N\0") + next = 0
        put16(&mut tiff, 1, little);
        put16(&mut tiff, 0x0001, little);
        put16(&mut tiff, 2, little);
        put32(&mut tiff, 2, little);
        tiff.extend_from_slice(b"N\0\0\0"); // 4B inline hodnota
        put32(&mut tiff, 0, little); // next
        let mut p = b"Exif\0\0".to_vec();
        p.extend_from_slice(&tiff);
        p
    }

    fn sample_jpeg(little: bool) -> Vec<u8> {
        let mut v = vec![0xFF, 0xD8];
        v.extend_from_slice(&seg(0xE0, b"JFIF\0\x01\x01")); // APP0 JFIF
        v.extend_from_slice(&seg(0xE1, &exif_payload(little))); // APP1 EXIF s GPS
        v.extend_from_slice(&seg(0xE1, b"http://ns.adobe.com/xap/1.0/\0<xmp/>")); // APP1 XMP
        v.extend_from_slice(&seg(0xE2, b"ICC-profile-bytes")); // APP2 ICC
        v.extend_from_slice(&seg(0xED, b"IPTC\0\x1c\x02\x00popis")); // APP13 IPTC
        v.extend_from_slice(&seg(0xDB, &[0x00; 4])); // DQT (marker < 0xE0 — test, že nepretrhame prechod)
        v.extend_from_slice(&seg(0xC4, &[0x00; 4])); // DHT
        v.extend_from_slice(&seg(0xDA, &[0x00, 0x08])); // SOS
        v.extend_from_slice(&[0x11, 0x22, 0xFF, 0x00, 0x33]); // entropy data (FF00 stuffing)
        v.extend_from_slice(&[0xFF, 0xD9]); // EOI
        v
    }

    /// GPS IFD sa vynuluje, orientation + ICC + APP0 + dáta ostanú; XMP a
    /// IPTC zmiznú. Obe byte orders.
    #[test]
    fn jpeg_gps_zeroed_orientation_and_icc_kept() {
        for little in [false, true] {
            let src = sample_jpeg(little);
            let out = clean(&src, "image/jpeg").unwrap();
            assert!(out.starts_with(&[0xFF, 0xD8, 0xFF]), "SOI+marker sedí");
            // XMP a IPTC sú preč
            assert!(
                !out.windows(20).any(|w| w.starts_with(b"http://ns.adobe.com")),
                "XMP zmizol"
            );
            assert!(!out.windows(4).any(|w| w == b"IPTC"), "IPTC zmizol");
            // ICC a JFIF ostali
            assert!(
                out.windows(16).any(|w| w.starts_with(b"ICC-profile-byte")),
                "ICC ostal"
            );
            assert!(out.windows(5).any(|w| w.starts_with(b"JFIF\0")), "APP0 ostal");
            // DQT/DHT segmenty ostali (marker < 0xE0 nepretrhne prechod)
            assert!(
                out.windows(6).any(|w| w.starts_with(&[0xFF, 0xDB])) && out.windows(6).any(|w| w.starts_with(&[0xFF, 0xC4])),
                "DQT/DHT ostali"
            );
            // entropy data + EOI nepoškodené
            assert!(
                out.ends_with(&[0x11, 0x22, 0xFF, 0x00, 0x33, 0xFF, 0xD9]),
                "data+EOI bez zmeny"
            );
            // EXIF APP1 stále prítomný a orientation (6) v ňom je
            let exif_at = out
                .windows(6)
                .position(|w| w == b"Exif\0\0")
                .expect("EXIF APP1 zostal");
            let tiff = &out[exif_at + 6..];
            let le = tiff.starts_with(b"II");
            let mut found_orient = false;
            let mut found_gps_zero = false;
            let count = rd_u16(tiff, 8, le).unwrap() as usize;
            for n in 0..count {
                let e = 10 + n * 12;
                let tag = rd_u16(tiff, e, le).unwrap();
                if tag == 0x0112 {
                    let expect: [u8; 2] = if le { [6, 0] } else { [0, 6] };
                    assert_eq!(&tiff[e + 8..e + 10], &expect[..], "orientation zachované");
                    found_orient = true;
                }
                if tag == TAG_GPS_IFD {
                    assert_eq!(&tiff[e + 8..e + 12], &[0u8; 4], "GPS IFD vynulovaný");
                    found_gps_zero = true;
                }
            }
            assert!(found_orient && found_gps_zero, "orientation + nulovaný GPS tag prítomné");
        }
    }

    /// JPEG bez EXIF segmentu sa spracuje bez chyby (nič sa neodstráni).
    #[test]
    fn jpeg_without_exif_survives() {
        let mut v = vec![0xFF, 0xD8];
        v.extend_from_slice(&seg(0xE0, b"JFIF\0"));
        v.extend_from_slice(&seg(0xDA, &[0x00, 0x08]));
        v.extend_from_slice(&[0xAA, 0xBB, 0xFF, 0xD9]);
        let out = clean(&v, "image/jpeg").unwrap();
        assert!(out.windows(5).any(|w| w.starts_with(b"JFIF\0")));
        assert!(out.ends_with(&[0xAA, 0xBB, 0xFF, 0xD9]));
    }

    /// Skrátený (poškodený) stream nespadne — zvyšok sa ponechá.
    #[test]
    fn truncated_jpeg_does_not_panic() {
        let mut v = vec![0xFF, 0xD8];
        v.extend_from_slice(&seg(0xE1, &exif_payload(false)));
        v.push(0xFF); // utatý začiatok ďalšieho segmentu
        let out = clean(&v, "image/jpeg").unwrap();
        assert!(out.windows(6).any(|w| w == b"Exif\0\0"));
    }

    fn png_chunk(typ: &[u8; 4], data: &[u8]) -> Vec<u8> {
        let mut v = (data.len() as u32).to_be_bytes().to_vec();
        v.extend_from_slice(typ);
        v.extend_from_slice(data);
        v.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]); // CRC (nad bytmi netestujeme)
        v
    }

    /// PNG: eXIf/tEXt/iTXt/zTXt preč, IHDR/gAMA/IDAT/IEND ostanú bez zmeny.
    #[test]
    fn png_metadata_chunks_dropped() {
        let ihdr = png_chunk(b"IHDR", &[0u8; 13]);
        let gama = png_chunk(b"gAMA", &[0u8; 4]);
        let idat = png_chunk(b"IDAT", &[1, 2, 3]);
        let iend = png_chunk(b"IEND", b"");
        let mut v = PNG_MAGIC.to_vec();
        v.extend_from_slice(&ihdr);
        v.extend_from_slice(&gama);
        v.extend_from_slice(&png_chunk(b"tEXt", b"Comment\0sukromny popis"));
        v.extend_from_slice(&png_chunk(b"zTXt", b"Comment\0\x00komprimovany"));
        v.extend_from_slice(&png_chunk(b"iTXt", b"cc\0\0\0\0xmp"));
        v.extend_from_slice(&png_chunk(b"eXIf", b"exif-bytes"));
        v.extend_from_slice(&idat);
        v.extend_from_slice(&iend);
        let out = clean(&v, "image/png").unwrap();
        assert!(out.starts_with(PNG_MAGIC));
        assert!(!out.windows(4).any(|w| w == b"tEXt" || w == b"zTXt" || w == b"iTXt" || w == b"eXIf"), "metadata chunky preč");
        // ponechané chunky presne bez zmeny bajtov
        for chunk in [&ihdr, &gama, &idat, &iend] {
            assert!(
                out.windows(chunk.len()).any(|w| w == &chunk[..]),
                "chunk {} ostal bez zmeny",
                std::str::from_utf8(&chunk[4..8]).unwrap_or("?")
            );
        }
        assert!(out.ends_with(&iend), "IEND na konci");
    }

    /// detekcia: WebP/GIF/SVG → None (415), JPEG/PNG → správny typ.
    #[test]
    fn detect_rejects_other_formats() {
        assert_eq!(detect_mime(&[0xFF, 0xD8, 0xFF, 0xE0]), Some("image/jpeg"));
        assert_eq!(detect_mime(PNG_MAGIC), Some("image/png"));
        assert_eq!(detect_mime(b"RIFF....WEBPVP8 "), None);
        assert_eq!(detect_mime(b"GIF89a"), None);
        assert_eq!(detect_mime(b"<svg/>"), None);
        // image/jpeg s nesprávnymi magic → clean vráti None
        assert!(clean(b"GIF89a", "image/jpeg").is_none());
        assert!(clean(b"GIF89a", "image/png").is_none());
    }
}
