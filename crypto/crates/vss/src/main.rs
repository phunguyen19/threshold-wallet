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
        #[arg(long, value_parser = parse_verify_share_param)]
        share: (usize, BigUint, BigUint),
    },
    Reconstruct {
        /// List of shares for reconstruct the secret
        #[arg(long, short, value_parser = parse_reconstruct_shares_param)]
        shares: Vec<(BigUint, BigUint)>,

        /// Optional prime value
        #[arg(long, short, value_parser = BigUint::from_str, default_value = PRIME_25519_STR)]
        prime: BigUint,
    },
}

fn parse_verify_share_param(input: &str) -> Result<(usize, BigUint, BigUint), String> {
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

    let s = match BigUint::from_str(vals[1]) {
        Ok(v) => v,
        Err(e) => {
            return Err(format!(
                "cannot parse s={} of share={:?} error: {:?}",
                vals[1], input, e
            ));
        }
    };

    let t = match BigUint::from_str(vals[2]) {
        Ok(v) => v,
        Err(e) => {
            return Err(format!(
                "cannot parse t={} of share={:?} error: {:?}",
                vals[2], input, e
            ));
        }
    };

    return Ok((index, s, t));
}

fn parse_reconstruct_shares_param(val: &str) -> Result<(BigUint, BigUint), String> {
    let s: Vec<&str> = val.split(":").collect();
    if s.len() != 2 {
        return Err(format!("cannot parse share param: {:?}", val));
    }

    let x = match BigUint::from_str(s[0]) {
        Ok(v) => v,
        Err(e) => {
            return Err(format!(
                "cannot parse x={} of share={:?} error: {:?}",
                s[0], val, e
            ));
        }
    };

    let y = match BigUint::from_str(s[1]) {
        Ok(v) => v,
        Err(e) => {
            return Err(format!(
                "cannot parse y={} of share={:?} error: {:?}",
                s[1], val, e
            ));
        }
    };

    Ok((x, y))
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

#[derive(Debug)]
struct VerifyParams {
    generator_g: BigUint,
    generator_h: BigUint,
    commitments: Vec<BigUint>,
    share: (usize, BigUint, BigUint),
    modulus: BigUint,
}

#[derive(Debug)]
struct VerifyResult {
    result: bool,
    verify_share_value: BigUint,
    verify_commitment_value: BigUint,
}

fn verify(params: VerifyParams) -> Result<VerifyResult, String> {
    println!("{:?}", params);

    let verify_share_value = (params.generator_g.modpow(&params.share.1, &params.modulus)
        * params.generator_h.modpow(&params.share.2, &params.modulus))
        % &params.modulus;

    let mut verify_commitment_value: BigUint = 1_u8.into();
    let idegree: BigUint = params.share.0.into();
    for i in 0..params.commitments.len() {
        let edegree = idegree.pow(i as u32);
        verify_commitment_value *= params.commitments[i].modpow(&edegree, &params.modulus)
    }
    verify_commitment_value %= &params.modulus;

    return Ok(VerifyResult {
        result: verify_share_value == verify_commitment_value,
        verify_share_value,
        verify_commitment_value,
    });
}

struct ReconstructParams {
    shares: Vec<(BigUint, BigUint)>,
    prime: BigUint,
}

struct ReconstructResult {
    secret: BigUint,
    prime: BigUint,
    basis_l_vals: Vec<BigUint>,
}

fn reconstruct(params: ReconstructParams) -> Result<ReconstructResult, String> {
    if params.shares.len() < 2 {
        return Err("there must be more than 1 share".into());
    }

    if params.prime <= params.shares.len().into() {
        return Err("shares count must be smaller than prime".into());
    }

    for (x, _) in &params.shares {
        if *x >= params.prime {
            return Err("x value must be smaller than prime".into());
        }
        if *x == BigUint::ZERO {
            return Err("x value must be greater than 0".into());
        }
    }

    // Validation duplication x
    for (i, el_i) in params.shares.iter().enumerate() {
        for (j, el_j) in params.shares.iter().enumerate() {
            if i != j && el_i.0 == el_j.0 {
                return Err(format!(
                    "shares must be unique, found duplicate x-coordinates: {:?}",
                    el_i.0
                ));
            }
        }
    }

    // For each key point:
    // Calculate: Li(0) mod p
    // Lᵢ(x) = ∏(j≠i) [(x - xⱼ) / (xᵢ - xⱼ)]
    let mut l_vec: Vec<BigUint> = Vec::new();

    // Σ Lᵢ = 1 mod p
    let mut verify: BigUint = 0u32.into();

    // Compute q(0) = D mod p
    // q(x) = Σ yᵢ × Lᵢ(x)
    let mut sec: BigUint = 0u32.into();

    for s_i in &params.shares {
        let x_i = &s_i.0;
        let y_i = &s_i.1;
        let mut numerator: BigUint = 1_usize.into();
        let mut denominator: BigUint = 1_usize.into();
        for s_j in &params.shares {
            let x_j = &s_j.0;

            if x_i == x_j {
                continue;
            }

            if x_i < x_j {
                numerator *= x_j;
                denominator *= x_j - x_i;
            } else {
                numerator *= &params.prime - x_j;
                denominator *= x_i - x_j;
            }
        }

        let denominator_inv_mod = match denominator.modinv(&params.prime) {
            Some(v) => v,
            None => return Err(format!("cannot calculate inverse mod for share={:?}", s_i)),
        };

        let numerator_mod = numerator % &params.prime;

        let l = (numerator_mod * denominator_inv_mod) % &params.prime;

        verify += &l;

        sec = (sec + (y_i * &l)) % &params.prime;

        l_vec.push(l);
    }

    // Verify: Sum(Li) = 1 mod p
    if verify % &params.prime != 1_usize.into() {
        return Err("shares are not in the same polynomial".into());
    }

    Ok(ReconstructResult {
        secret: sec,
        prime: params.prime,
        basis_l_vals: l_vec,
    })
}

fn main() -> Result<(), String> {
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
            Ok(())
        }
        Commands::Verify {
            pogh,
            commitments,
            share,
        } => {
            if let Some(pogh) = pogh {
                let r = verify(VerifyParams {
                    generator_g: pogh.generator_g,
                    generator_h: pogh.generator_h,
                    commitments,
                    share,
                    modulus: pogh.prime,
                });
                println!("{:?}", r);
            }
            Ok(())
        }
        Commands::Reconstruct { shares, prime } => {
            let result = reconstruct(ReconstructParams {
                shares: shares.clone(),
                prime: prime.clone(),
            })?;

            let number_format = &args.number_format;

            if args.verbose {
                println!("Input: {:?} {:?}", shares, prime);
                println!("share_points: {:?}", shares);
                println!("l_vec: {:?}", result.basis_l_vals);
            }

            println!();
            println!("Shamir's Secret Reconstruction ");
            println!("───────────────────────────────");
            println!("Prime: {}", number_format.format(&result.prime));
            println!("Shares: {} provided", shares.len());
            println!("───────────────────────────────");
            println!();
            println!("Input Shares:");
            for s in &shares {
                println!("  {}: {}", &s.0, number_format.format(&s.1));
            }
            println!();
            println!("✓ Reconstructed Secret");
            println!("──────────────────────");
            println!("Secret: {}", number_format.format(&result.secret));
            println!("──────────────────────");

            Ok(())
        }
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
