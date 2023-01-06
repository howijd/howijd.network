use std::ops::BitAnd;

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
pub const HEADER_SIZE: usize = 80;

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
pub struct Header {
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

#[derive(Copy, Clone, Debug, PartialEq)]
#[repr(u64)]
pub enum DatumFlag {
  DatumInvalid = 1 << 0,
  DatumDraft = 1 << 1,
  DatumEmpty = 1 << 2,
  DatumChecksum = 1 << 3,
  DatumOPC = 1 << 4,
  DatumCompressed = 1 << 5,
  DatumEncrypted = 1 << 6,
  DatumExtractable = 1 << 7,
  DatumSigned = 1 << 8,
  DatumStreamable = 1 << 9,
  DatumCustom = 1 << 10,
  DatumCompromised = 1 << 11,
}

impl BitAnd<DatumFlag> for DatumFlag {
  type Output = bool;

  fn bitand(self, rhs: DatumFlag) -> bool {
      (self as u64) & (rhs as u64) != 0
  }
}

impl BitAnd<u64> for DatumFlag {
  type Output = bool;

  fn bitand(self, rhs: u64) -> bool {
      (self as u64) & rhs != 0
  }

}

impl BitAnd<DatumFlag> for u64 {
  type Output = bool;

  fn bitand(self, rhs: DatumFlag) -> bool {
      self & (rhs as u64) != 0
  }
}



const EMPTY: [u8; 8] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
const MAGIC_DATE: u64 = 1652155382000000001;

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
  // check magic and delimiter
  if !data[..8].eq(&MAGIC) || !data[72..80].eq(&DELIMITER) {
    return false;
  }

  // check version is >= 1
  let version = u16::from_le_bytes([data[8], data[9]]);
  if version < VERSION {
      return true;
  }

  // break here if DatumDraft is set
  let flags = u64::from_le_bytes([
    data[10], data[11], data[12], data[13], data[14], data[15], data[16], data[17],
  ]);

  if flags & DatumFlag::DatumDraft  || flags & DatumFlag::DatumCompromised  {
    return true;
  }

  // It it was not a draft it must have timestamp
  let timestamp = u64::from_le_bytes([
    data[18], data[19], data[20], data[21], data[22], data[23], data[24], data[25],
  ]);
  if timestamp < MAGIC_DATE {
      return false;
  }

  // DatumOPC is set then counter value must be gte 1
  if flags & DatumFlag::DatumOPC {
    let counter = u32::from_le_bytes([data[26], data[27], data[28], data[29]]);
    if counter < 1 {
      return false;
    }
  }

  // DatumChecksum Checksum must be set
  if flags & DatumFlag::DatumChecksum  && data[30..38].eq(&EMPTY) {
    return false;
  }

  // Not DatumEmpty or DatumDraft
  if flags & DatumFlag::DatumEmpty  {
    // Size field must be set
    let size = u64::from_le_bytes([
      data[38], data[39], data[40], data[41], data[42], data[43], data[44], data[45],
    ]);
    if size < 1 {
      return false;
    }

    // DatumCompressed compression algorithm must be set
    if flags & DatumFlag::DatumCompressed {
      let algorithm = u16::from_le_bytes([data[46], data[47]]);
      if algorithm < 1 {
          return false;
      }
    }
    // DatumEncrypted encryption algorithm must be set
    if flags & DatumFlag::DatumEncrypted {
      let algorithm = u16::from_le_bytes([data[48], data[49]]);
      if algorithm < 1 {
          return false;
      }
    }

    // DatumExtractable payl;oad can be extracted then filename must be set
    if flags & DatumFlag::DatumExtractable && data[50..58].eq(&EMPTY) {
      return false;
    }
  }

  // DatumSigned then Signature Type must be also set
  // however value of the signature Size may depend on Signature Type
  if flags & DatumFlag::DatumSigned {
    let signature_type = u16::from_le_bytes([data[58], data[59]]);
    if signature_type < 1 {
      return false;
    }
  }

  // If all checks pass, return true
  true
}

fn set_header_version(slice: &mut [u8], version: u16) {
  if slice.len() < 10 {
    return;
  }
  slice[8] = version as u8;
  slice[9] = (version >> 8) as u8;
}

fn set_header_date(slice: &mut [u8], nsec: u64) {
  if slice.len() < 25 {
    return;
  }
  slice[18] = nsec as u8;
  slice[19] = (nsec >> 8) as u8;
  slice[20] = (nsec >> 16) as u8;
  slice[21] = (nsec >> 24) as u8;
  slice[22] = (nsec >> 32) as u8;
  slice[23] = (nsec >> 40) as u8;
  slice[24] = (nsec >> 48) as u8;
  slice[25] = (nsec >> 56) as u8;
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
    set_header_version(&mut data, VERSION);
    set_header_date(&mut data, MAGIC_DATE);


    data[72..80].copy_from_slice(&DELIMITER);
    assert!(verify_header(&data));

    // Test invalid magic
    let mut data = [0; HEADER_SIZE];
    data[0] = 0x00;
    set_header_version(&mut data, VERSION);
    data[72..80].copy_from_slice(&DELIMITER);
    assert!(!verify_header(&data));
  }

  #[test]
  // Test invalid delimiter
  fn verify_header_delimiter() {
    let mut data = [0; HEADER_SIZE];
    data[0..8].copy_from_slice(&MAGIC);
    set_header_version(&mut data, VERSION);
    data[72] = 0x00;
    assert!(!verify_header(&data));
  }
}
