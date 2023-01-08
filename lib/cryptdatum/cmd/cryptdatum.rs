// Copyright 2022 The howijd.network Authors
// Licensed under the Apache License, Version 2.0.
// See the LICENSE file.
use std::env;
use std::fs::File;
use std::io::Read;
use std::process::exit;
use cryptdatum::*;

fn main() -> Result<()> {
  let args: Vec<String> = env::args().collect();

  if args.len() < 2 {
      println!("error: no subcommand provided.");
      exit(1);
  }

  let command = &args[1];
  let filepath = &args[2];

  match command.as_str() {
      "file-has-header" => cmd_file_has_header(filepath)?,
      "file-has-valid-header" => cmd_file_has_valid_header(filepath)?,
      "file-info" => cmd_file_info(filepath)?,
      // "file-info" => cmd_file_info(filepath)?,
      _ => {
          println!("invalid command");
          exit(1);
      }
  }

  Ok(())
}

fn cmd_file_has_header(filepath: &str) -> Result<()> {
  let mut ctd = File::open(filepath)?;
  let mut headb = [0; cryptdatum::HEADER_SIZE];

  ctd.read_exact(&mut headb)?;

  if !has_header(&headb) {
      exit(1);
  }

  Ok(())
}

fn cmd_file_has_valid_header(filepath: &str) -> Result<()> {
  let mut ctd = File::open(filepath)?;
  let mut headb = [0; cryptdatum::HEADER_SIZE];

  ctd.read_exact(&mut headb)?;

  if !has_valid_header(&headb) {
      exit(1);
  }

  Ok(())
}

fn cmd_file_info(filepath: &str) -> Result<()> {
  let mut ctd = File::open(filepath)?;
  let header = decode_header(&mut ctd)?;
  print_header(header);
  Ok(())
}

fn pretty_size(size: u64) -> String {
  let units = ["B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB"];
  let mut i = 0;
  let mut ss = size;
  while ss >= 1024 && i < 8 {
      ss /= 1024;
      i += 1;
  }
  format!("{} {}", ss, units[i])
}

fn bool_str(value: bool) -> &'static str {
  if value {
      "true"
  } else {
      "false"
  }
}

fn print_header(header: Header) {

  let created = timestamp::format("%Y-%m-%dT%H:%M:%S%nZ", header.timestamp);
  let datumsize = pretty_size(header.size);

  println!("+--------------+------------+-----------------------------+-------------------+---------------------------------+");
  println!("| CRYPTDATUM   | SIZE: {:>34} | CREATED:{:>43} |", datumsize, created);
  println!("+--------------+------------+-----------------------------+-------------------+---------------------------------+");
  println!("| Version      | 2          | Version number              | uint16            | {:<31} |", header.version);
  println!("| Flags        | 8          | Flags                       | uint64            | {:<31} |", header.flags);
  println!("| Timestamp    | 8          | Timestamp                   | uint64            | {:<31} |", header.timestamp);
  println!("| OPC          | 4          | Operation Counter           | uint32            | {:<31} |", header.opc);
  println!("| Checksum     | 8          | Checksum                    | uint64            | {:<31} |", header.checksum);
  println!("| Size         | 8          | Total size                  | uint64            | {:<31} |", header.size);
  println!("| Comp. Alg.   | 2          | Compression algorithm       | uint16            | {:<31} |", header.compression_alg);
  println!("| Encrypt. Alg | 2          | Encryption algorithm        | uint16            | {:<31} |", header.encryption_alg);
  println!("| Sign. Type   | 2          | Signature type              | uint16            | {:<31} |", header.signature_type);
  println!("| Sign. Size   | 4          | Signature size              | uint32            | {:<31} |", header.signature_size);
  println!("| File Ext.    | 8          | File extension              | char[8]           | {:<31} |", header.file_ext);
  println!("| Custom       | 8          | Custom                      | uint8[8]          | {:03} {:03} {:03} {:03} {:03} {:03} {:03} {:03} |",
    header.custom[0], header.custom[1], header.custom[2], header.custom[3],
    header.custom[4], header.custom[5], header.custom[6], header.custom[7]);
  println!("+--------------+------------+----------------------------+--------------------+---------------------------------+");
  println!("| FLAGS                                                                                                         |");
  println!("+------------+--------+-------------+--------+--------------+--------+------------------------------------------+");
  println!("| Invalid    | {:<6} | OPC         | {:<6} | Signed       | {:<6} |                                          |",
    bool_str(header.flags & DatumFlag::DatumInvalid), bool_str(header.flags & DatumFlag::DatumOPC), bool_str(header.flags & DatumFlag::DatumSigned));
  println!("| Draft      | {:<6} | Compressed  | {:<6} | Streamable   | {:<6} |                                          |",
    bool_str(header.flags & DatumFlag::DatumDraft), bool_str(header.flags & DatumFlag::DatumCompressed), bool_str(header.flags & DatumFlag::DatumStreamable));
  println!("| Empty      | {:<6} | Encrypted   | {:<6} | Custom       | {:<6} |                                          |",
    bool_str(header.flags & DatumFlag::DatumEmpty), bool_str(header.flags & DatumFlag::DatumEncrypted), bool_str(header.flags & DatumFlag::DatumCustom));
  println!("| Checksum   | {:<6} | Extractable | {:<6} | Compromised  | {:<6} |                                          |",
    bool_str(header.flags & DatumFlag::DatumChecksum), bool_str(header.flags & DatumFlag::DatumExtractable), bool_str(header.flags & DatumFlag::DatumCompromised));
  println!("+------------+--------+-------------+--------+--------------+--------+------------------------------------------+");
}
