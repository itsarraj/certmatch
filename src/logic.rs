//! Pure comparison/parsing logic. The real `openssl` invocations that
//! produce the text this operates on live in `main.rs` — this module
//! never touches a file or a subprocess.

/// Two PEM public-key blocks (as printed by `openssl x509 -pubkey` /
/// `openssl pkey -pubout`) represent the same key if their content is
/// identical once whitespace differences are normalized away — PEM is
/// base64 wrapped at a fixed line width, and two independently-produced
/// PEMs of the same underlying DER bytes are byte-identical modulo that
/// wrapping.
pub fn keys_match(pubkey_a: &str, pubkey_b: &str) -> bool {
    normalize(pubkey_a) == normalize(pubkey_b)
}

fn normalize(pem: &str) -> String {
    pem.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect::<Vec<_>>()
        .join("\n")
}

/// Splits a multi-certificate PEM bundle into its individual
/// `-----BEGIN CERTIFICATE-----`...`-----END CERTIFICATE-----` blocks,
/// in file order — the order a real chain file is meant to be read in
/// (leaf first, then each intermediate, root last or omitted).
pub fn split_cert_bundle(pem: &str) -> Vec<String> {
    let mut certs = Vec::new();
    let mut current = String::new();
    let mut in_cert = false;
    for line in pem.lines() {
        if line.starts_with("-----BEGIN CERTIFICATE-----") {
            in_cert = true;
            current.clear();
        }
        if in_cert {
            current.push_str(line);
            current.push('\n');
        }
        if line.starts_with("-----END CERTIFICATE-----") {
            in_cert = false;
            certs.push(current.clone());
        }
    }
    certs
}

/// Given each certificate's real `(subject, issuer)` pair in file
/// order, checks that the chain is correctly ordered: each cert's
/// issuer matches the *next* cert's subject (leaf → intermediate →
/// root). Returns the index of the first break, if any.
pub fn chain_order_valid(subjects_and_issuers: &[(String, String)]) -> Result<(), usize> {
    for i in 0..subjects_and_issuers.len().saturating_sub(1) {
        let (_, issuer) = &subjects_and_issuers[i];
        let (next_subject, _) = &subjects_and_issuers[i + 1];
        if issuer != next_subject {
            return Err(i);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identical_pem_text_matches() {
        let pem = "-----BEGIN PUBLIC KEY-----\nABC\nDEF\n-----END PUBLIC KEY-----\n";
        assert!(keys_match(pem, pem));
    }

    #[test]
    fn different_line_wrapping_still_matches() {
        let a = "-----BEGIN PUBLIC KEY-----\nABCDEF\n-----END PUBLIC KEY-----\n";
        let b = "-----BEGIN PUBLIC KEY-----\r\nABCDEF\r\n-----END PUBLIC KEY-----\r\n";
        assert!(keys_match(a, b));
    }

    #[test]
    fn genuinely_different_keys_do_not_match() {
        let a = "-----BEGIN PUBLIC KEY-----\nABC\n-----END PUBLIC KEY-----\n";
        let b = "-----BEGIN PUBLIC KEY-----\nXYZ\n-----END PUBLIC KEY-----\n";
        assert!(!keys_match(a, b));
    }

    #[test]
    fn splits_a_two_certificate_bundle_into_two_blocks() {
        let bundle = "-----BEGIN CERTIFICATE-----\nLEAF\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nINTERMEDIATE\n-----END CERTIFICATE-----\n";
        let certs = split_cert_bundle(bundle);
        assert_eq!(certs.len(), 2);
        assert!(certs[0].contains("LEAF"));
        assert!(certs[1].contains("INTERMEDIATE"));
    }

    #[test]
    fn single_certificate_bundle_splits_into_one_block() {
        let bundle = "-----BEGIN CERTIFICATE-----\nONLY\n-----END CERTIFICATE-----\n";
        assert_eq!(split_cert_bundle(bundle).len(), 1);
    }

    #[test]
    fn empty_bundle_splits_into_zero_blocks() {
        assert!(split_cert_bundle("").is_empty());
    }

    #[test]
    fn correctly_ordered_chain_is_valid() {
        let chain = vec![
            (
                "leaf.example.com".to_string(),
                "Intermediate CA".to_string(),
            ),
            ("Intermediate CA".to_string(), "Root CA".to_string()),
        ];
        assert_eq!(chain_order_valid(&chain), Ok(()));
    }

    #[test]
    fn misordered_chain_reports_the_break_index() {
        let chain = vec![
            ("leaf.example.com".to_string(), "Root CA".to_string()), // wrong: skips the intermediate
            ("Intermediate CA".to_string(), "Root CA".to_string()),
        ];
        assert_eq!(chain_order_valid(&chain), Err(0));
    }

    #[test]
    fn a_single_certificate_chain_is_trivially_valid() {
        let chain = vec![("only.example.com".to_string(), "Some CA".to_string())];
        assert_eq!(chain_order_valid(&chain), Ok(()));
    }

    #[test]
    fn empty_chain_is_trivially_valid() {
        assert_eq!(chain_order_valid(&[]), Ok(()));
    }
}
