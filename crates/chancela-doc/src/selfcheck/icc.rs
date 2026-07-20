//! ICC profile validation for the OutputIntent's `/DestOutputProfile`.
//!
//! ISO 19005-2 §6.2.2 requires the output intent to carry a **valid** ICC profile whose colour
//! space agrees with the stream's `/N`. Checking `/N == 3` — all the write-time gate used to do —
//! proves nothing about the bytes: an empty stream, a truncated profile, or a CMYK profile
//! mislabelled `/N 3` all pass it.
//!
//! Two independent assertions run here:
//!
//! 1. **The profile parses and is internally consistent** (ICC.1:2010 §7): magic, declared size,
//!    version, device class, data colour space ↔ `/N` agreement, PCS, rendering intent, and a tag
//!    table whose every entry lies inside the profile. This is a real check against arbitrary
//!    bytes.
//! 2. **The embedded bytes are the shipped bytes.** Chancela ships exactly one profile
//!    (`assets/icc/sRGB-v2-micro.icc`) and embeds it verbatim, so byte identity is available to us
//!    and is strictly stronger than any structural check — it removes the failure mode instead of
//!    detecting it. It is also what narrows the claim: this module certifies *our* profile, not
//!    every conformant profile.

/// The bundled sRGB OutputIntent profile, as `pdfa::write` embeds it (CC0; see
/// `assets/icc/PROVENANCE.md`).
pub(super) const SRGB_ICC: &[u8] = include_bytes!("../../assets/icc/sRGB-v2-micro.icc");

/// Tags an RGB matrix/TRC display profile must carry (ICC.1:2010 §8.3).
const REQUIRED_RGB_TAGS: [&[u8; 4]; 9] = [
    b"desc", b"cprt", b"wtpt", b"rXYZ", b"gXYZ", b"bXYZ", b"rTRC", b"gTRC", b"bTRC",
];

fn be32(bytes: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

fn sig(bytes: &[u8], at: usize) -> [u8; 4] {
    [bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]]
}

fn show(signature: [u8; 4]) -> String {
    String::from_utf8_lossy(&signature).to_string()
}

/// Assert `profile` is a structurally valid ICC profile whose colour space has `declared_n`
/// components, and that it is the profile this writer ships.
pub(super) fn verify(profile: &[u8], declared_n: i64) -> Result<(), String> {
    verify_structure(profile, declared_n)?;
    if profile != SRGB_ICC {
        return Err(format!(
            "embedded ICC profile ({} bytes) is not the shipped sRGB profile ({} bytes)",
            profile.len(),
            SRGB_ICC.len()
        ));
    }
    Ok(())
}

/// The profile-format half of [`verify`], independent of which profile we ship.
pub(super) fn verify_structure(profile: &[u8], declared_n: i64) -> Result<(), String> {
    if profile.len() < 132 {
        return Err(format!(
            "ICC profile is {} bytes; an ICC header plus tag count needs 132",
            profile.len()
        ));
    }
    if sig(profile, 36) != *b"acsp" {
        return Err(format!(
            "ICC profile lacks the `acsp` signature at offset 36 (found {:?})",
            show(sig(profile, 36))
        ));
    }
    let declared_size = be32(profile, 0) as usize;
    if declared_size != profile.len() {
        return Err(format!(
            "ICC profile header declares {declared_size} bytes but the stream holds {}",
            profile.len()
        ));
    }

    let major_version = profile[8];
    if !matches!(major_version, 2 | 4) {
        return Err(format!(
            "ICC profile major version is {major_version}; PDF/A output intents use v2 or v4"
        ));
    }

    let class = sig(profile, 12);
    if !matches!(&class, b"mntr" | b"prtr" | b"scnr" | b"spac") {
        return Err(format!(
            "ICC profile device class /{} is not an output-intent class",
            show(class)
        ));
    }

    let space = sig(profile, 16);
    let components = match &space {
        b"GRAY" => 1,
        b"RGB " => 3,
        b"Lab " => 3,
        b"CMYK" => 4,
        other => {
            return Err(format!(
                "ICC profile data colour space {} is outside the PDF/A output-intent set",
                show(*other)
            ));
        }
    };
    if components != declared_n {
        return Err(format!(
            "ICC profile colour space {} has {components} components but the stream declares /N {declared_n}",
            show(space)
        ));
    }

    let pcs = sig(profile, 20);
    if !matches!(&pcs, b"XYZ " | b"Lab ") {
        return Err(format!(
            "ICC profile connection space {} is neither XYZ nor Lab",
            show(pcs)
        ));
    }

    let intent = be32(profile, 64);
    if intent > 3 {
        return Err(format!(
            "ICC profile rendering intent {intent} is outside the defined range 0..=3"
        ));
    }

    // Tag table: count, then `count` 12-byte (signature, offset, size) entries.
    let tag_count = be32(profile, 128) as usize;
    let table_end = 132usize
        .checked_add(tag_count.checked_mul(12).ok_or("ICC tag count overflows")?)
        .ok_or("ICC tag table overflows")?;
    if tag_count == 0 || table_end > profile.len() {
        return Err(format!(
            "ICC profile declares {tag_count} tags, which does not fit in {} bytes",
            profile.len()
        ));
    }

    let mut present = Vec::with_capacity(tag_count);
    for index in 0..tag_count {
        let entry = 132 + index * 12;
        let signature = sig(profile, entry);
        let offset = be32(profile, entry + 4) as usize;
        let size = be32(profile, entry + 8) as usize;
        let end = offset
            .checked_add(size)
            .ok_or_else(|| format!("ICC tag {} has an overflowing extent", show(signature)))?;
        if offset < table_end || end > profile.len() {
            return Err(format!(
                "ICC tag {} spans {offset}..{end}, outside the profile body {table_end}..{}",
                show(signature),
                profile.len()
            ));
        }
        present.push(signature);
    }

    if space == *b"RGB " {
        for required in REQUIRED_RGB_TAGS {
            if !present.contains(required) {
                return Err(format!(
                    "ICC RGB profile is missing the mandatory {} tag",
                    show(*required)
                ));
            }
        }
    }

    Ok(())
}
