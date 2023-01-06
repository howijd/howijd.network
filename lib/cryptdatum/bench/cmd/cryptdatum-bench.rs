use std::env;
use std::error::Error;
use std::fs::File;
use std::io::Read;
use std::process::exit;

use cryptdatum::verify_header;

fn main() -> Result<(), Box<dyn Error>> {
  let args: Vec<String> = env::args().collect();

  if args.len() < 2 {
      println!("error: no subcommand provided.");
      exit(1);
  }

  let command = &args[1];
  let file = &args[2];

  match command.as_str() {
      "verify" => cmd_verify(file)?,
      _ => {
          println!("invalid command");
          exit(1);
      }
  }

  Ok(())
}

fn cmd_verify(file: &str) -> Result<(), Box<dyn Error>> {
  let mut ctd = File::open(file)?;
  let mut headb = [0; cryptdatum::HEADER_SIZE];

  ctd.read_exact(&mut headb)?;

  if !verify_header(&headb) {
      exit(1);
  }

  Ok(())
}
