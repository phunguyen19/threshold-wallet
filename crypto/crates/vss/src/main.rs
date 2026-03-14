use std::str::FromStr;

use clap::{ColorChoice, Parser, Subcommand, ValueEnum};
use num_bigint::{BigUint, RandBigInt};

// Curve25519 prime: 2^255 - 19
const PRIME_25519_STR: &str =
    "57896044618658097711785492504343953926634992332820282019728792003956564819949";

#[derive(Parser, Debug)]
#[command(name="vss", version, about, long_about=None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    #[arg(long, global = true, value_enum, default_value_t = NumberFormat::Hex)]
    number_format: NumberFormat,

    #[arg(long, global = true)]
    verbose: bool,
}

#[derive(Debug, Clone, ValueEnum)]
#[clap(rename_all = "lower")]
enum NumberFormat {
    Hex,
    Dec,
}

impl NumberFormat {
    fn format(&self, n: &BigUint) -> String {
        match self {
            Self::Hex => format!("{:#x}", n),
            Self::Dec => format!("{}", n),
        }
    }
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Generate shares for a secret
    Deal {
        /// How many participants
        #[arg(long)]
        players: usize,

        /// Minimal number of shares needed to reconstruct the secret
        #[arg(long)]
        threshold: usize,

        /// List params prime:order:g:h
        #[arg(long, value_parser=parse_pogh_param)]
        pogh: Option<CliPogh>,

        /// Debug coefficient. F_j:G_j
        #[arg(long, value_parser=parse_debug_coeffs)]
        debug_coeffs: Option<(Vec<BigUint>, Vec<BigUint>)>,
    },
    Verify {
        /// List params prime:order:g:h
        #[arg(long, value_parser=parse_pogh_param)]
        pogh: Option<CliPogh>,

        /// VSS commitment values
        #[arg(long, value_delimiter = ':', value_parser = BigUint::from_str)]
        commitments: Vec<BigUint>,

        /// Share
        #[arg(long, value_parser = parse_share_param)]
        share: (usize, BigUint, BigUint),
    },
    Reconstruct,
}

fn parse_share_param(input: &str) -> Result<(usize, BigUint, BigUint), String> {
    // split by :
    let vals: Vec<&str> = input.split(":").collect();
    if vals.len() != 3 {
        return Err(format!(
            "share value must be in format index:s:t, receive: {:?}",
            input
        ));
    }

    // parse each value and return proper error
    let index = match vals[0].parse::<usize>() {
        Ok(v) => v,
        Err(e) => {
            return Err(format!(
                "cannot parse index value {}, error: {:?}",
                vals[0], e,
            ));
        }
    };

    let s = match BigUint::from_str(vals[0]) {
        Ok(v) => v,
        Err(e) => {
            return Err(format!(
                "cannot parse s={} of share={:?} error: {:?}",
                vals[0], input, e
            ));
        }
    };

    let t = match BigUint::from_str(vals[1]) {
        Ok(v) => v,
        Err(e) => {
            return Err(format!(
                "cannot parse t={} of share={:?} error: {:?}",
                vals[1], input, e
            ));
        }
    };

    return Ok((index, s, t));
}

#[derive(Debug, Clone)]
struct CliPogh {
    prime: BigUint,
    order: BigUint,
    generator_g: BigUint,
    generator_h: BigUint,
}

// Parsing string input "prime:order:g:h"
fn parse_pogh_param(input: &str) -> Result<CliPogh, String> {
    let vals: Vec<&str> = input.split(":").collect();
    if vals.len() != 4 {
        return Err(format!("params values is invalid: {:?}", input));
    }

    let prime = match BigUint::from_str(vals[0]) {
        Ok(v) => v,
        Err(e) => {
            return Err(format!(
                "cannot parse prime {:?} in value {:?}, error: {:?}",
                vals[0], input, e
            ));
        }
    };

    let order = match BigUint::from_str(vals[1]) {
        Ok(v) => v,
        Err(e) => {
            return Err(format!(
                "cannot parse order {:?} in value {:?}, error: {:?}",
                vals[1], input, e
            ));
        }
    };

    let generator_g = match BigUint::from_str(vals[2]) {
        Ok(v) => v,
        Err(e) => {
            return Err(format!(
                "cannot parse generator G {:?} in value {:?}, error: {:?}",
                vals[2], input, e
            ));
        }
    };

    let generator_h = match BigUint::from_str(vals[3]) {
        Ok(v) => v,
        Err(e) => {
            return Err(format!(
                "cannot parse generator h {:?} in value {:?}, error: {:?}",
                vals[3], input, e
            ));
        }
    };

    Ok(CliPogh {
        prime,
        order,
        generator_g,
        generator_h,
    })
}

fn parse_debug_coeffs(input: &str) -> Result<(Vec<BigUint>, Vec<BigUint>), String> {
    let vals: Vec<&str> = input.split("/").collect();
    if vals.len() != 2 {
        return Err(format!("value is not valid: {:?}", input));
    }

    let vals_coeffs_f: Vec<&str> = vals[0].split(":").collect();
    let vals_coeffs_g: Vec<&str> = vals[1].split(":").collect();

    let mut coeffs_f: Vec<BigUint> = vec![];
    for s in vals_coeffs_f {
        match BigUint::from_str(s) {
            Ok(v) => coeffs_f.push(v),
            Err(e) => {
                return Err(format!(
                    "cannot parse value {:?} of input {:?}, error {:?}",
                    s, input, e
                ));
            }
        };
    }

    let mut coeffs_g: Vec<BigUint> = vec![];
    for s in vals_coeffs_g {
        match BigUint::from_str(s) {
            Ok(v) => coeffs_g.push(v),
            Err(e) => {
                return Err(format!(
                    "cannot parse value {:?} of input {:?}, error {:?}",
                    s, input, e
                ));
            }
        };
    }

    Ok((coeffs_f, coeffs_g))
}

#[derive(Debug)]
struct DealParams {
    players: usize,
    threshold: usize,
    prime: BigUint,
    order: BigUint,
    generator_g: BigUint,
    generator_h: BigUint,
    coeffs_f: Vec<BigUint>,
    coeffs_g: Vec<BigUint>,
}

#[derive(Debug)]
struct DealResult {
    // E_i
    commitments: Vec<BigUint>,
    // (i, s_i, t_i)
    shares: Vec<(usize, BigUint, BigUint)>,
}

fn deal(params: DealParams) -> Result<DealResult, String> {
    println!("{:?}", params);

    // validate players is valid
    // validate threshold is valid and smaller than players
    if params.threshold < 2 || params.threshold > params.players {
        return Err(format!(
            "threshold must be greater than 1 and smaller than number of players {}, receive {}",
            &params.players, &params.threshold
        ));
    }
    // validate prime valid
    if !is_prime(&params.prime) {
        return Err(format!("prime value {} is not valid", params.prime));
    }
    // validate order valid
    if !is_prime(&params.order)
        || &params.prime % &params.order != 1_u8.into()
        || params.order >= params.prime
    {
        return Err(format!(
            "order value {} is not valid for prime {}",
            params.order, params.prime
        ));
    }
    // validate g valid
    if params.generator_g.modpow(&params.order, &params.prime) != 1_u8.into() {
        return Err(format!("generator g {} is not valid", params.generator_g));
    }
    // validate h valid
    if params.generator_h.modpow(&params.order, &params.prime) != 1_u8.into() {
        return Err(format!("generator h {} is not valid", params.generator_h));
    }
    // validate coeffs f and g equal len
    if params.coeffs_f.len() != params.coeffs_g.len() || params.coeffs_f.len() != params.threshold {
        return Err(format!(
            "F and G must have the number of coeffcients equal threshold. Receives F coeffs {} G coeffs {}",
            params.coeffs_f.len(),
            params.coeffs_g.len(),
        ));
    }
    // validate coeffs f and g valid
    for coeff in [params.coeffs_f.clone(), params.coeffs_g.clone()].concat() {
        if coeff < 1_u8.into() || coeff > params.order {
            return Err(format!(
                "coefficients must not smaller than 1 and greater than order {}, receive {}",
                params.order, coeff
            ));
        }
    }

    // Generate commitments
    let mut commitments: Vec<BigUint> = vec![];
    for i in 0..params.threshold {
        let c = &params
            .generator_g
            .modpow(&params.coeffs_f[i], &params.prime)
            * &params
                .generator_h
                .modpow(&params.coeffs_g[i], &params.prime);
        commitments.push(c % &params.prime);
    }

    // Generate share pairs
    let polynomial = |x: &BigUint, coeffs: &Vec<BigUint>, modulus: &BigUint| -> BigUint {
        let mut ret: BigUint = 0_u64.into();
        for (degree, value) in coeffs.iter().enumerate() {
            ret += (value * x.modpow(&degree.into(), modulus)) % modulus;
        }
        (ret) % modulus
    };

    let mut shares: Vec<(usize, BigUint, BigUint)> = vec![];
    for i in 1..=params.players {
        let s = polynomial(&i.into(), &params.coeffs_f, &params.order);
        let t = polynomial(&i.into(), &params.coeffs_g, &params.order);
        shares.push((i, s, t));
    }

    return Ok(DealResult {
        commitments,
        shares,
    });
}

struct VerifyParams {}

fn main() {
    let args = Cli::parse();
    println!("{:?}", args);
    match args.command {
        Commands::Deal {
            players,
            threshold,
            pogh,
            debug_coeffs,
        } => {
            if let Some(poghv) = pogh {
                if let Some(debug_coeffs_v) = debug_coeffs {
                    let r = deal(DealParams {
                        players,
                        threshold,
                        prime: poghv.prime,
                        order: poghv.order,
                        generator_g: poghv.generator_g,
                        generator_h: poghv.generator_h,
                        coeffs_f: debug_coeffs_v.0,
                        coeffs_g: debug_coeffs_v.1,
                    });
                    println!("{:?}", r);
                }
            }
        }
        Commands::Verify {
            pogh,
            commitments,
            share,
        } => {
            println!("pass")
        }
        _ => {}
    }
}

fn is_prime(n: &BigUint) -> bool {
    let two: BigUint = 2_u8.into();

    if n < &two {
        return false;
    }
    if n == &two {
        return true;
    }
    if n % &two == BigUint::ZERO {
        return false;
    }

    let mut i: BigUint = 3_u8.into();
    while &(&i * &i) <= n {
        if n % &i == BigUint::ZERO {
            return false;
        }
        i += &two;
    }
    true
}
