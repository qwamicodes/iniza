use argon2::{Algorithm, Argon2, AssociatedData, ParamsBuilder, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use sha2::Sha256;

#[test]
fn xchacha20_poly1305_matches_the_published_internet_draft_vector() {
    let key = decode_hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
    let nonce: [u8; 24] = decode_hex("404142434445464748494a4b4c4d4e4f5051525354555657")
        .try_into()
        .expect("vector nonce should contain 24 bytes");
    let associated_data = decode_hex("50515253c0c1c2c3c4c5c6c7");
    let plaintext = decode_hex(concat!(
        "4c616469657320616e642047656e746c656d656e206f662074686520636c6173",
        "73206f66202739393a204966204920636f756c64206f6666657220796f75206f",
        "6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73",
        "637265656e20776f756c642062652069742e"
    ));
    let expected_ciphertext_and_tag = decode_hex(concat!(
        "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb",
        "731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452",
        "2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9",
        "21f9664c97637da9768812f615c68b13b52e",
        "c0875924c1c7987947deafd8780acf49"
    ));

    let cipher = XChaCha20Poly1305::new_from_slice(&key).expect("vector key should be valid");
    let actual = cipher
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: &plaintext,
                aad: &associated_data,
            },
        )
        .expect("published vector should encrypt");

    assert_eq!(actual, expected_ciphertext_and_tag);
}

#[test]
fn hkdf_sha256_matches_rfc_5869_test_case_one() {
    let input_key_material = vec![0x0b; 22];
    let salt = decode_hex("000102030405060708090a0b0c");
    let info = decode_hex("f0f1f2f3f4f5f6f7f8f9");
    let expected_output = decode_hex(concat!(
        "3cb25f25faacd57a90434f64d0362f2a",
        "2d2d0a90cf1a5a4c5db02d56ecc4c5bf",
        "34007208d5b887185865"
    ));
    let mut actual = vec![0_u8; 42];

    Hkdf::<Sha256>::new(Some(&salt), &input_key_material)
        .expand(&info, &mut actual)
        .expect("RFC output length should be valid");

    assert_eq!(actual, expected_output);
}

#[test]
fn argon2id_matches_rfc_9106_version_19_test_vector() {
    let params = ParamsBuilder::new()
        .m_cost(32)
        .t_cost(3)
        .p_cost(4)
        .data(AssociatedData::new(&[0x04; 12]).expect("RFC associated data should be valid"))
        .build()
        .expect("RFC parameters should be valid");
    let argon2 = Argon2::new_with_secret(&[0x03; 8], Algorithm::Argon2id, Version::V0x13, params)
        .expect("RFC secret should be valid");
    let mut actual = [0_u8; 32];

    argon2
        .hash_password_into(&[0x01; 32], &[0x02; 16], &mut actual)
        .expect("RFC vector should hash");

    assert_eq!(
        actual.as_slice(),
        decode_hex("0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659")
    );
}

#[test]
fn blake3_matches_the_official_empty_input_vector() {
    assert_eq!(
        blake3::hash(b"").to_hex().as_str(),
        "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
    );
}

fn decode_hex(input: &str) -> Vec<u8> {
    assert!(
        input.len().is_multiple_of(2),
        "hex input should contain complete bytes"
    );
    input
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).expect("hex input should be UTF-8");
            u8::from_str_radix(text, 16).expect("hex input should contain hexadecimal digits")
        })
        .collect()
}
