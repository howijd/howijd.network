/// Current version of the Cryptdatum format
///
/// This constant defines the current version of the Cryptdatum format.
/// Implementations of the Cryptdatum library should set this value to 1
/// to indicate support for the current version of the format.
pub const VERSION: u16 = 1;


/// Minimum version of the Cryptdatum format
///
/// This constant defines the minimum version of the Cryptdatum format
/// what is supported by this library.
pub const MIN_VERSION: u16 = 1;

/// Size of a Cryptdatum header in bytes
///
/// This constant defines the size of a Cryptdatum header in bytes. It can be
/// used by implementations of the Cryptdatum library to allocate sufficient
/// memory for a Cryptdatum header, or to check the size of a Cryptdatum header
/// that has been read from a stream.
pub const HEADER_SIZE: usize = 64;

/// Magic number for Cryptdatum headers
///
/// This constant defines the magic number that is used to identify Cryptdatum
/// headers. If the magic number field in a Cryptdatum header does not match
/// this value, the header should be considered invalid.
pub const MAGIC: [u8; 8] = [0xA7, 0xF6, 0xE5, 0xD4, 0xC3, 0xB2, 0xA1, 0xE1];

/// Delimiter for Cryptdatum headers
///
/// This constant defines the delimiter that is used to mark the end of a
/// Cryptdatum header. If the delimiter field in a Cryptdatum header does not
/// match this value, the header should be considered invalid.
pub const DELIMITER: [u8; 8] = [0xC8, 0xB7, 0xA6, 0xE5, 0xD4, 0xC3, 0xB2, 0xF1];

/// Structure representing a Cryptdatum header
///
/// This structure represents a Cryptdatum header, which contains metadata about
/// the data payload of a Cryptdatum datum. It is used to identify the data as
/// a Cryptdatum datum, as well as to indicate the features that are used by
/// the datum.
#[repr(C)]
pub struct CryptdatumHeader {
  pub magic: [u8; 8], // CRYPTDATUM_MAGIC
  pub version: u16, // Indicates the version of the Cryptdatum
  pub timestamp: u64, // Unix timestamp in nanoseconds
  pub opc: u16, // Unique operation ID
  pub checksum: u64, // CRC64 checksum
  pub flags: u32, // Cryptdatum features enabled
  pub size: u64, // Total size of the data, incl. header and optional signature
  pub signature_size: u32, // signature size
  pub compression_algorithm: u8, // compression algorithm
  pub encryption_algorithm: u8, // encryption algorithm
  pub signature_type: u8, // signature type
  reserved: [u8; 5], // Reserved for future use
  pub delimiter:[u8; 8], // CRYPTDATUM_DELIMITER
}

/// Verify a Cryptdatum header
///
/// This function verifies a Cryptdatum header to ensure that it is valid.
/// It checks the magic number, delimiter, and other fields in the header
/// to ensure that they match the expected values.
///
/// # Parameters
///
/// * `data`: A slice containing the Cryptdatum header to verify
///
/// # Returns
///
/// `true` if the header is valid, `false` if it is invalid
pub fn verify_header(data: &[u8]) -> bool {
  // Verify that the data is at least the size of the header
  if data.len() < HEADER_SIZE {
      return false;
  }

  // Verify that the magic number and delimiter match the expected values
  if &data[0..8] != MAGIC {
      return false;
  }
  if &data[56..64] != DELIMITER {
      return false;
  }

  // Verify that the version number matches the expected value
  let version = u16::from_le_bytes([data[8], data[9]]);
  if version != VERSION {
      return false;
  }

  // If all checks pass, return true
  true
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  // Test too small data
  fn verify_header_too_small_data() {
    let data = [0; HEADER_SIZE - 1];
    assert!(!verify_header(&data));
  }

  #[test]
  fn verify_header_magic() {
    // Test valid magic
    let mut data = [0; HEADER_SIZE];
    data[0..8].copy_from_slice(&MAGIC);
    data[8] = VERSION as u8;
    data[9] = (VERSION >> 8) as u8;
    data[56..64].copy_from_slice(&DELIMITER);
    assert!(verify_header(&data));

    // Test invalid magic
    let mut data = [0; HEADER_SIZE];
    data[0] = 0x00;
    data[8] = VERSION as u8;
    data[9] = (VERSION >> 8) as u8;
    data[56..64].copy_from_slice(&DELIMITER);
    assert!(!verify_header(&data));
  }

  #[test]
  // Test invalid delimiter
  fn verify_header_delimiter() {
    let mut data = [0; HEADER_SIZE];
    data[0..8].copy_from_slice(&MAGIC);
    data[8] = VERSION as u8;
    data[9] = (VERSION >> 8) as u8;
    data[56] = 0x00;
    assert!(!verify_header(&data));
  }
}
