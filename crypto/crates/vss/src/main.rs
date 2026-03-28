use clap::{Parser, Subcommand, ValueEnum};
use curve25519_dalek::{
    RistrettoPoint, Scalar, constants::RISTRETTO_BASEPOINT_POINT, ristretto::CompressedRistretto,
    traits::Identity,
};
use num_bigint::BigUint;
use num_traits::Num;
use sha2::Sha512;

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
        /// Secret
        #[arg(long, value_parser = parse_biguint)]
        secret: BigUint,

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
        #[arg(long, value_delimiter = ':', value_parser = parse_biguint)]
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
        #[arg(long, short, value_parser = parse_biguint)]
        prime: Option<BigUint>,
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

    let s = match parse_biguint(vals[1]) {
        Ok(v) => v,
        Err(e) => {
            return Err(format!(
                "cannot parse s={} of share={:?} error: {:?}",
                vals[1], input, e
            ));
        }
    };

    let t = match parse_biguint(vals[2]) {
        Ok(v) => v,
        Err(e) => {
            return Err(format!(
                "cannot parse t={} of share={:?} error: {:?}",
                vals[2], input, e
            ));
        }
    };

    Ok((index, s, t))
}

fn parse_reconstruct_shares_param(val: &str) -> Result<(BigUint, BigUint), String> {
    let s: Vec<&str> = val.split(":").collect();
    if s.len() != 2 {
        return Err(format!("cannot parse share param: {:?}", val));
    }

    let x = match parse_biguint(s[0]) {
        Ok(v) => v,
        Err(e) => {
            return Err(format!(
                "cannot parse x={} of share={:?} error: {:?}",
                s[0], val, e
            ));
        }
    };

    let y = match parse_biguint(s[1]) {
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

    let prime = match parse_biguint(vals[0]) {
        Ok(v) => v,
        Err(e) => {
            return Err(format!(
                "cannot parse prime {:?} in value {:?}, error: {:?}",
                vals[0], input, e
            ));
        }
    };

    let order = match parse_biguint(vals[1]) {
        Ok(v) => v,
        Err(e) => {
            return Err(format!(
                "cannot parse order {:?} in value {:?}, error: {:?}",
                vals[1], input, e
            ));
        }
    };

    let generator_g = match parse_biguint(vals[2]) {
        Ok(v) => v,
        Err(e) => {
            return Err(format!(
                "cannot parse generator G {:?} in value {:?}, error: {:?}",
                vals[2], input, e
            ));
        }
    };

    let generator_h = match parse_biguint(vals[3]) {
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
        match parse_biguint(s) {
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
        match parse_biguint(s) {
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

fn parse_biguint(s: &str) -> Result<BigUint, String> {
    if let Some(x) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        BigUint::from_str_radix(x, 16).map_err(|e| e.to_string())
    } else {
        BigUint::from_str_radix(s, 10).map_err(|e| e.to_string())
    }
}

#[derive(Debug)]
struct DealParams {
    secret: BigUint,
    players: usize,
    threshold: usize,
    prime: BigUint,
    order: BigUint,
    generator_g: BigUint,
    generator_h: BigUint,
    coeffs_a: Vec<BigUint>,
    coeffs_b: Vec<BigUint>,
}

#[derive(Debug)]
struct DealResult {
    // E_i
    commitments: Vec<BigUint>,
    // (i, s_i, t_i)
    shares: Vec<(usize, BigUint, BigUint)>,
}

#[derive(Debug)]
struct DealCurveParams {
    secret: BigUint,
    players: usize,
    threshold: usize,
}

#[derive(Debug)]
struct DealCurveResult {
    // E_i
    commitments: Vec<BigUint>,
    // (i, s_i, t_i)
    shares: Vec<(usize, BigUint, BigUint)>,
}

fn generate_g() -> RistrettoPoint {
    RISTRETTO_BASEPOINT_POINT
}

fn generate_h() -> RistrettoPoint {
    let msg = "VSS_pedersen_h_generator_v1";
    RistrettoPoint::hash_from_bytes::<Sha512>(msg.as_bytes())
}

fn commit_custom(a: &BigUint, b: &BigUint, g: &BigUint, h: &BigUint, modulus: &BigUint) -> BigUint {
    (g.modpow(a, modulus) * h.modpow(b, modulus)) % modulus
}

// Commitment: E_j = g^a_j * h^b_j  (in EC: a_j*G + b_j*H)
fn commit_ec(a: &Scalar, b: &Scalar, g: &RistrettoPoint, h: &RistrettoPoint) -> RistrettoPoint {
    g * a + h * b
}

fn gen_share_custom(x: &BigUint, coeffs: &[BigUint], modulus: &BigUint) -> BigUint {
    coeffs
        .iter()
        .rev()
        .fold(BigUint::ZERO, |acc, c| (acc * x + c) % modulus)
        % modulus
}

fn gen_share_ec(x: &Scalar, coeffs: &Vec<Scalar>) -> Scalar {
    coeffs.iter().rev().fold(Scalar::ZERO, |acc, c| acc * x + c)
}

fn deal_custom(params: DealParams) -> Result<DealResult, String> {
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
    if params.coeffs_a.len() != params.coeffs_b.len() || params.coeffs_a.len() != params.threshold {
        return Err(format!(
            "F and G must have the number of coeffcients equal threshold. Receives F coeffs {} G coeffs {}",
            params.coeffs_a.len(),
            params.coeffs_b.len(),
        ));
    }
    // validate debug first free coeff
    if params.coeffs_a[0] != params.secret {
        return Err(format!(
            "debug coeffs first free coeff must equal secret {}, found {}",
            params.secret, params.coeffs_a[0]
        ));
    }
    // validate coeffs f and g valid
    for coeff in [params.coeffs_a.clone(), params.coeffs_b.clone()].concat() {
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
        let c = commit_custom(
            &params.coeffs_a[i],
            &params.coeffs_b[i],
            &params.generator_g,
            &params.generator_h,
            &params.prime,
        );
        commitments.push(c % &params.prime);
    }

    let mut shares: Vec<(usize, BigUint, BigUint)> = vec![];
    for i in 1..=params.players {
        let s = gen_share_custom(&i.into(), &params.coeffs_a, &params.order);
        let t = gen_share_custom(&i.into(), &params.coeffs_b, &params.order);
        shares.push((i, s, t));
    }

    Ok(DealResult {
        commitments,
        shares,
    })
}

fn deal_ec(params: DealCurveParams) -> Result<DealCurveResult, String> {
    // validate players is valid
    // validate threshold is valid and smaller than players
    if params.threshold < 2 || params.threshold > params.players {
        return Err(format!(
            "threshold must be greater than 1 and smaller than number of players {}, receive {}",
            &params.players, &params.threshold
        ));
    }

    let k: Scalar = biguint_to_scalar(&params.secret).map_err(|e| {
        format!(
            "cannot convert {:?} to scalar, error: {:?}",
            params.secret, e
        )
    })?;

    let mut csprng = rand::rngs::OsRng;
    let t: Scalar = Scalar::random(&mut csprng);

    let mut coeffs_a: Vec<Scalar> = vec![k];
    let mut coeffs_b: Vec<Scalar> = vec![t];
    for _ in 1_usize..params.threshold {
        coeffs_a.push(Scalar::random(&mut csprng));
        coeffs_b.push(Scalar::random(&mut csprng));
    }

    // Generate commitments
    let mut commitments: Vec<BigUint> = vec![];
    for i in 0..params.threshold {
        commitments.push(ristretto_point_to_biguint(&commit_ec(
            &coeffs_a[i],
            &coeffs_b[i],
            &generate_g(),
            &generate_h(),
        )));
    }

    let mut shares: Vec<(usize, BigUint, BigUint)> = vec![];
    for i in 1..=params.players {
        let s = scalar_to_biguint(&gen_share_ec(&Scalar::from(i as u8), &coeffs_a));
        let t = scalar_to_biguint(&gen_share_ec(&Scalar::from(i as u8), &coeffs_b));
        shares.push((i, s, t));
    }

    Ok(DealCurveResult {
        commitments,
        shares,
    })
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
    verify_commitment_value: BigUint,
    verify_share_value: BigUint,
}

fn verify_custom(params: VerifyParams) -> Result<VerifyResult, String> {
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

    Ok(VerifyResult {
        result: verify_share_value == verify_commitment_value,
        verify_share_value,
        verify_commitment_value,
    })
}

#[derive(Debug)]
struct VerifyECParams {
    commitments: Vec<BigUint>,
    share: (usize, BigUint, BigUint),
}

// Verify share EC
// E(s_i, t_i) = g*s + h*t = \sum_{j=0}^{k-1}{E_j*i^j}
fn verify_ec(params: VerifyECParams) -> Result<VerifyResult, String> {
    let g = generate_g();
    let h = generate_h();

    let si: Scalar = biguint_to_scalar(&params.share.1)?;
    let ti: Scalar = biguint_to_scalar(&params.share.2)?;

    let lhs = g * si + h * ti;

    // rhs sum(ej * i^j)
    let mut rhs = RistrettoPoint::identity(); // (0,0)
    let i = Scalar::from(params.share.0 as u64);
    let mut ipowj = Scalar::ONE; // start with i^0 = 1
    for ej in &params.commitments {
        let ejscalar = biguint_to_ristretto_point(ej)?;
        rhs += ejscalar * ipowj;
        ipowj *= i;
    }

    Ok(VerifyResult {
        result: lhs == rhs,
        verify_commitment_value: ristretto_point_to_biguint(&lhs),
        verify_share_value: ristretto_point_to_biguint(&rhs),
    })
}

struct ReconstructParams {
    shares: Vec<(BigUint, BigUint)>,
    prime: BigUint,
}

fn reconstruct_custom(params: ReconstructParams) -> Result<BigUint, String> {
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

    Ok(sec)
}

struct ReconstructEcParams {
    shares: Vec<(BigUint, BigUint)>,
}

fn reconstruct_ec(params: ReconstructEcParams) -> Result<BigUint, String> {
    let mut shares: Vec<(Scalar, Scalar)> = vec![];
    for s in params.shares {
        let i = biguint_to_scalar(&s.0)?;
        let v = biguint_to_scalar(&s.1)?;
        shares.push((i, v));
    }

    // for each (xi, yi):
    //   li = product over (xj, _) where xj ≠ xi: (-xj) / (xi - xj)
    //   sum += yi * li
    Ok(scalar_to_biguint(&shares.iter().fold(
        Scalar::ZERO,
        |sum, (xi, yi)| {
            let li = shares
                .iter()
                .filter(|(xj, _)| xj != xi)
                .fold(Scalar::ONE, |prod, (xj, _)| {
                    prod * (-xj) * (xi - xj).invert()
                });

            sum + li * yi
        },
    )))
}

fn main() -> Result<(), String> {
    let args = Cli::parse();
    let fmt = &args.number_format;
    let verbose = args.verbose;

    match args.command {
        Commands::Deal {
            secret,
            players,
            threshold,
            pogh,
            debug_coeffs,
        } => {
            let (commitments, shares) = if let Some(poghv) = pogh {
                if let Some(debug_coeffs_v) = debug_coeffs {
                    if verbose {
                        println!("secret:    {}", fmt.format(&secret));
                        println!("players:   {}", players);
                        println!("threshold: {}", threshold);
                        println!("prime:     {}", fmt.format(&poghv.prime));
                        println!("order:     {}", fmt.format(&poghv.order));
                        println!("g:         {}", fmt.format(&poghv.generator_g));
                        println!("h:         {}", fmt.format(&poghv.generator_h));
                        for (i, c) in debug_coeffs_v.0.iter().enumerate() {
                            println!("a[{}]: {}", i, fmt.format(c));
                        }
                        for (i, c) in debug_coeffs_v.1.iter().enumerate() {
                            println!("b[{}]: {}", i, fmt.format(c));
                        }
                    }
                    let r = deal_custom(DealParams {
                        secret,
                        players,
                        threshold,
                        prime: poghv.prime,
                        order: poghv.order,
                        generator_g: poghv.generator_g,
                        generator_h: poghv.generator_h,
                        coeffs_a: debug_coeffs_v.0,
                        coeffs_b: debug_coeffs_v.1,
                    })?;
                    (r.commitments, r.shares)
                } else {
                    return Err("--debug-coeffs required when --pogh is set".into());
                }
            } else {
                if verbose {
                    println!("secret:    {}", fmt.format(&secret));
                    println!("players:   {}", players);
                    println!("threshold: {}", threshold);
                    println!("curve:     ristretto255");
                }
                let r = deal_ec(DealCurveParams {
                    secret,
                    players,
                    threshold,
                })?;
                (r.commitments, r.shares)
            };

            println!();
            println!("✓ Deal Complete");
            println!("────────────────────────────────────────");
            println!("Commitments ({}):", commitments.len());
            for (i, c) in commitments.iter().enumerate() {
                println!("  E[{}] = {}", i, fmt.format(c));
            }
            println!();
            println!("Shares ({}):", shares.len());
            for (i, s, t) in &shares {
                println!("  [{}]  s = {}  t = {}", i, fmt.format(s), fmt.format(t));
            }
            println!("────────────────────────────────────────");

            Ok(())
        }
        Commands::Verify {
            pogh,
            commitments,
            share,
        } => {
            if verbose {
                println!("share index: {}", share.0);
                println!("s:           {}", fmt.format(&share.1));
                println!("t:           {}", fmt.format(&share.2));
                println!("commitments ({}):", commitments.len());
                for (i, c) in commitments.iter().enumerate() {
                    println!("  E[{}] = {}", i, fmt.format(c));
                }
            }

            let r = if let Some(pogh) = pogh {
                verify_custom(VerifyParams {
                    generator_g: pogh.generator_g,
                    generator_h: pogh.generator_h,
                    commitments,
                    share,
                    modulus: pogh.prime,
                })?
            } else {
                verify_ec(VerifyECParams { commitments, share })?
            };

            println!();
            if r.result {
                println!("✓ Verification Passed");
            } else {
                println!("✗ Verification Failed");
            }
            println!("────────────────────────────────────────");
            if verbose {
                println!(
                    "  lhs (g·s + h·t):          {}",
                    fmt.format(&r.verify_commitment_value)
                );
                println!(
                    "  rhs (Σ Eⱼ·iʲ):            {}",
                    fmt.format(&r.verify_share_value)
                );
            }
            println!("  Result: {}", if r.result { "VALID" } else { "INVALID" });
            println!("────────────────────────────────────────");

            Ok(())
        }
        Commands::Reconstruct { shares, prime } => {
            if verbose {
                println!("shares ({}):", shares.len());
                for (x, y) in &shares {
                    println!("  x = {}  y = {}", fmt.format(x), fmt.format(y));
                }
            }

            let result = if let Some(prime) = prime {
                reconstruct_custom(ReconstructParams {
                    shares: shares.clone(),
                    prime: prime.clone(),
                })?
            } else {
                reconstruct_ec(ReconstructEcParams { shares })?
            };

            println!();
            println!("✓ Reconstructed Secret");
            println!("────────────────────────────────────────");
            println!("  Secret: {}", fmt.format(&result));
            println!("────────────────────────────────────────");

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

fn biguint_to_scalar(n: &BigUint) -> Result<Scalar, String> {
    let mut b = n.to_bytes_le();
    b.resize(64, 0u8);

    // Defensive conversion to make sure
    // it works regardless the size
    let r: [u8; 64] = b[..64]
        .try_into()
        .map_err(|e| format!("cannot convert value {:?} to be scalar, error: {:?}", n, e))?;

    Ok(Scalar::from_bytes_mod_order_wide(&r))
}

fn scalar_to_biguint(n: &Scalar) -> BigUint {
    BigUint::from_bytes_le(n.as_bytes())
}

fn biguint_to_ristretto_point(n: &BigUint) -> Result<RistrettoPoint, String> {
    let bytes = n.to_bytes_le();
    let mut buf = [0u8; 32];
    if bytes.len() > 32 {
        return Err("commitment too large for 32-byte point".into());
    }
    buf[..bytes.len()].copy_from_slice(&bytes);
    CompressedRistretto(buf)
        .decompress()
        .ok_or_else(|| format!("invalid compressed point for value {}", n))
}

fn ristretto_point_to_biguint(n: &RistrettoPoint) -> BigUint {
    BigUint::from_bytes_le(n.compress().as_bytes())
}

#[cfg(test)]
mod tests {
    use num_bigint::RandBigInt;
    use rand::thread_rng;

    use super::*;

    fn build_subsets<T: Clone>(
        items: &[T],
        k: usize,
        start: usize,
        current: &mut Vec<T>,
        result: &mut Vec<Vec<T>>,
    ) {
        if current.len() == k {
            result.push(current.clone());
            return;
        }
        for i in start..items.len() {
            current.push(items[i].clone());
            build_subsets(items, k, i + 1, current, result);
            current.pop();
        }
    }

    /// Generate all k-sized subsets of a slice
    fn subsets<T: Clone>(items: &[T], k: usize) -> Vec<Vec<T>> {
        let mut result = Vec::new();
        let mut current = Vec::with_capacity(k);
        build_subsets(items, k, 0, &mut current, &mut result);
        result
    }

    fn gen_rand_biguint() -> BigUint {
        let mut rng = thread_rng();
        // RistrettoPoint work under q ~ 2^252
        rng.gen_biguint(252)
    }

    #[test]
    fn test_full_flow_preset() {
        let test_cases: Vec<BigUint> = vec![25_u32.into(), gen_rand_biguint()];

        for secret in test_cases {
            // test deal
            let deal_result = deal_ec(DealCurveParams {
                secret: secret.clone(),
                players: 5,
                threshold: 3,
            })
            .unwrap();

            // Test verify
            for share in &deal_result.shares {
                let verify_result = verify_ec(VerifyECParams {
                    commitments: deal_result.commitments.clone(),
                    share: share.clone(),
                })
                .unwrap();
                assert_eq!(verify_result.result, true);
            }

            // Test reconstruct
            for subset in subsets(&deal_result.shares, 3) {
                let reconstruct_result = reconstruct_ec(ReconstructEcParams {
                    shares: subset.iter().map(|s| (s.0.into(), s.1.clone())).collect(),
                });
                assert_eq!(reconstruct_result.unwrap(), secret);
            }
        }
    }
}
