#![cfg(target_os = "linux")]

//! Conformance proof for the isolated hostile-image normalization boundary.

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use image::{DynamicImage, ImageBuffer, ImageFormat, Rgb};
use mealy_infrastructure::{LinuxBubblewrapMediaNormalizer, MediaNormalizerError};
use std::{fs, io::Cursor, path::Path};

const ONE_PIXEL_PNG: &str =
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAIAAACQd1PeAAAADElEQVR4nGP4z8AAAAMBAQDJ/pLvAAAAAElFTkSuQmCC";

fn normalizer() -> LinuxBubblewrapMediaNormalizer {
    let worker = fs::canonicalize(env!("CARGO_BIN_EXE_mealy-media-worker"))
        .expect("media worker path is canonical");
    LinuxBubblewrapMediaNormalizer::load(Path::new("/usr/bin/bwrap"), &worker)
        .expect("isolated media normalizer loads")
}

#[test]
fn real_namespace_normalizes_and_rejects_hostile_inputs_without_daemon_decode() {
    let normalizer = normalizer();
    let source = BASE64_STANDARD
        .decode(ONE_PIXEL_PNG)
        .expect("fixture base64 decodes");
    let canonical = normalizer
        .normalize("image/png", &source)
        .expect("valid PNG normalizes");
    assert_eq!((canonical.width(), canonical.height()), (1, 1));
    assert_eq!(canonical.media_type(), "image/jpeg");
    assert_eq!(canonical.bytes()[..2], [0xff, 0xd8]);
    assert_eq!(canonical.sha256_digest().len(), 64);

    assert_eq!(
        normalizer.normalize("image/jpeg", &source),
        Err(MediaNormalizerError::InvalidInput)
    );
    assert_eq!(
        normalizer.normalize("image/png", b"not-an-image"),
        Err(MediaNormalizerError::InvalidInput)
    );
    assert_eq!(
        normalizer.normalize("image/png", &vec![0_u8; 2 * 1024 * 1024 + 1]),
        Err(MediaNormalizerError::ResourceLimitExceeded)
    );

    let maximum_image =
        DynamicImage::ImageRgb8(ImageBuffer::from_pixel(4_096, 4_096, Rgb([12, 34, 56])));
    let mut maximum_png = Vec::new();
    maximum_image
        .write_to(&mut Cursor::new(&mut maximum_png), ImageFormat::Png)
        .expect("maximum-size PNG encodes");
    assert!(maximum_png.len() < 2 * 1024 * 1024);
    let canonical = normalizer
        .normalize("image/png", &maximum_png)
        .expect("maximum decoded dimensions normalize inside worker limits");
    assert_eq!((canonical.width(), canonical.height()), (2_048, 2_048));
}
