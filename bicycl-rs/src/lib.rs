//! Safe Rust bindings for the [BICYCL] cryptographic library.
//!
//! BICYCL implements class-group-based cryptographic schemes including:
//! - **Paillier** homomorphic encryption
//! - **Joye-Libert** homomorphic encryption
//! - **CL_HSMqk / CL_HSM2k** class-group encryption with homomorphic properties
//! - **ECDSA** signatures
//! - **Two-party ECDSA** threshold signing (2-of-2)
//! - **Threshold ECDSA** (t-of-n)
//! - **CL DLog proofs**
//!
//! # Build
//!
//! Requires CMake, GMP, and OpenSSL development headers at build time.
//!
//! # Thread safety
//!
//! The underlying C library is **not** thread-safe.  All wrapper types are
//! `!Send + !Sync` and must be used from a single thread.
//!
//! # License
//!
//! This crate is licensed under **GPL-3.0-or-later**.  Any crate or binary
//! that depends on it inherits the GPL-3.0 copyleft obligation.
//!
//! # Quick start
//!
//! ```no_run
//! use bicycl_rs::{Context, Error};
//!
//! fn main() -> Result<(), Error> {
//!     let ctx = Context::new()?;
//!     let mut rng = ctx.randgen_from_seed_decimal("12345")?;
//!     let paillier = ctx.paillier(512)?;
//!     let (sk, pk) = paillier.keygen(&ctx, &mut rng)?;
//!     let ct = paillier.encrypt_decimal(&ctx, &pk, &mut rng, "42")?;
//!     let plain = paillier.decrypt_decimal(&ctx, &pk, &sk, &ct)?;
//!     assert_eq!(plain, "42");
//!     Ok(())
//! }
//! ```
//!
//! [BICYCL]: https://gite.lirmm.fr/crypto/bicycl
#![deny(unsafe_op_in_unsafe_fn)]

mod error;

use core::ffi::{c_char, c_int, c_void};
use std::ffi::{CStr, CString};
use std::marker::PhantomData;
use std::ptr::NonNull;

pub use error::{Error, Result};

fn status_to_result(status: bicycl_rs_sys::bicycl_status_t) -> Result<()> {
    if status == bicycl_rs_sys::bicycl_status_t::BICYCL_OK {
        Ok(())
    } else {
        Err(Error::from_status(status))
    }
}

fn ffi_string_from_len<F>(mut f: F) -> Result<String>
where
    F: FnMut(*mut c_char, *mut usize) -> bicycl_rs_sys::bicycl_status_t,
{
    let buf = ffi_bytes_from_len(|buf, len| f(buf.cast::<c_char>(), len))?;
    let cstr = CStr::from_bytes_with_nul(&buf).map_err(|_| Error::Internal)?;
    Ok(cstr.to_str()?.to_owned())
}

fn ffi_bytes_from_len<F>(mut f: F) -> Result<Vec<u8>>
where
    F: FnMut(*mut u8, *mut usize) -> bicycl_rs_sys::bicycl_status_t,
{
    let mut len: usize = 0;
    let first = f(std::ptr::null_mut(), &mut len as *mut usize);
    if first != bicycl_rs_sys::bicycl_status_t::BICYCL_ERR_BUFFER_TOO_SMALL
        && first != bicycl_rs_sys::bicycl_status_t::BICYCL_OK
    {
        return Err(Error::from_status(first));
    }

    let mut buf = vec![0_u8; len];
    if len == 0 {
        return Ok(buf);
    }

    let second = f(buf.as_mut_ptr(), &mut len as *mut usize);
    status_to_result(second)?;
    buf.truncate(len);
    Ok(buf)
}

/// Returns the ABI version of the linked `bicycl_capi` C library.
///
/// Compare against [`bicycl_rs_sys::BICYCL_CAPI_VERSION`] to verify
/// the runtime library matches the headers this crate was compiled against.
pub fn abi_version() -> u32 {
    unsafe { bicycl_rs_sys::bicycl_get_abi_version() }
}

/// Returns the human-readable version string of the linked `bicycl_capi` library.
///
/// Returns an empty string if the library returns a null pointer.
pub fn version() -> &'static str {
    unsafe {
        let p = bicycl_rs_sys::bicycl_get_version();
        if p.is_null() {
            return "";
        }
        CStr::from_ptr(p).to_str().unwrap_or("")
    }
}

/// Overwrites the given byte buffer with zeros using a memory-safe barrier.
///
/// Unlike a plain `buf.fill(0)`, this call is guaranteed not to be optimised
/// away by the compiler, making it suitable for clearing sensitive key material.
pub fn zeroize(buf: &mut [u8]) {
    unsafe {
        bicycl_rs_sys::bicycl_zeroize(buf.as_mut_ptr().cast::<c_void>(), buf.len());
    }
}

/// The central BICYCL library context.
///
/// All cryptographic objects and operations require a reference to a `Context`.
/// The context acts as an error sink: it stores the last error message produced
/// by the C library and is passed to every operation so the library has
/// somewhere to record diagnostic information.
///
/// All derived objects (`RandGen`, scheme instances, keys, ciphertexts, etc.)
/// own their data independently and do **not** hold pointers into the context's
/// memory, so their drop order relative to `Context` does not affect memory
/// safety.  `Context` is `!Send + !Sync` because the underlying C library is
/// not thread-safe; all objects must be used from a single thread.
#[derive(Debug)]
pub struct Context {
    raw: NonNull<bicycl_rs_sys::bicycl_context_t>,
    _marker: PhantomData<*mut ()>,
}

impl Context {
    /// Creates a new library context.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying C allocation fails.
    pub fn new() -> Result<Self> {
        let mut raw = std::ptr::null_mut();
        let status = unsafe { bicycl_rs_sys::bicycl_context_new(&mut raw as *mut _) };
        status_to_result(status)?;
        let raw = NonNull::new(raw).expect("bicycl_context_new returned null");
        Ok(Self {
            raw,
            _marker: PhantomData,
        })
    }

    /// Returns the last error message stored by the C library, or `""` if none.
    pub fn last_error(&self) -> &str {
        unsafe {
            let p = bicycl_rs_sys::bicycl_context_last_error(self.raw.as_ptr());
            if p.is_null() {
                return "";
            }
            CStr::from_ptr(p).to_str().unwrap_or("")
        }
    }

    /// Clears the last error message stored in the context.
    pub fn clear_error(&self) {
        unsafe { bicycl_rs_sys::bicycl_context_clear_error(self.raw.as_ptr()) }
    }

    /// Creates a deterministic random number generator seeded from a decimal string.
    ///
    /// `seed_decimal` must be a valid decimal integer (e.g., `"12345"`).
    /// The same seed always produces the same sequence, which is useful for
    /// reproducible tests but **must not be used with a fixed seed in production**.
    pub fn randgen_from_seed_decimal(&self, seed_decimal: &str) -> Result<RandGen> {
        let seed_c = CString::new(seed_decimal)?;
        let mut raw = std::ptr::null_mut();
        let status = unsafe {
            bicycl_rs_sys::bicycl_randgen_new_from_seed_decimal(
                self.raw.as_ptr(),
                seed_c.as_ptr(),
                &mut raw as *mut _,
            )
        };
        status_to_result(status)?;
        let raw = NonNull::new(raw).expect("bicycl_randgen_new_from_seed_decimal returned null");
        Ok(RandGen {
            raw,
            _marker: PhantomData,
        })
    }

    /// Creates a class group from a negative fundamental discriminant given as a decimal string.
    ///
    /// `discriminant_decimal` must be a negative integer (e.g., `"-23"`).
    pub fn classgroup_from_discriminant_decimal(
        &self,
        discriminant_decimal: &str,
    ) -> Result<ClassGroup> {
        let disc_c = CString::new(discriminant_decimal)?;
        let mut raw = std::ptr::null_mut();
        let status = unsafe {
            bicycl_rs_sys::bicycl_classgroup_new_from_discriminant_decimal(
                self.raw.as_ptr(),
                disc_c.as_ptr(),
                &mut raw as *mut _,
            )
        };
        status_to_result(status)?;
        let raw = NonNull::new(raw)
            .expect("bicycl_classgroup_new_from_discriminant_decimal returned null");
        Ok(ClassGroup {
            raw,
            _marker: PhantomData,
        })
    }

    /// Creates a Paillier cryptosystem instance with the given RSA modulus bit length.
    ///
    /// Typical values for `modulus_bits`: 512 (testing), 1024, 2048.
    pub fn paillier(&self, modulus_bits: u32) -> Result<Paillier> {
        let mut raw = std::ptr::null_mut();
        let status = unsafe {
            bicycl_rs_sys::bicycl_paillier_new(self.raw.as_ptr(), modulus_bits, &mut raw as *mut _)
        };
        status_to_result(status)?;
        let raw = NonNull::new(raw).expect("bicycl_paillier_new returned null");
        Ok(Paillier {
            raw,
            _marker: PhantomData,
        })
    }

    /// Creates a Joye-Libert cryptosystem instance.
    ///
    /// - `modulus_bits`: RSA modulus bit length (e.g., 1024, 2048).
    /// - `k`: plaintext bit length (must be ≤ `modulus_bits / 2`).
    pub fn joye_libert(&self, modulus_bits: u32, k: u32) -> Result<JoyeLibert> {
        let mut raw = std::ptr::null_mut();
        let status = unsafe {
            bicycl_rs_sys::bicycl_joye_libert_new(
                self.raw.as_ptr(),
                modulus_bits,
                k,
                &mut raw as *mut _,
            )
        };
        status_to_result(status)?;
        let raw = NonNull::new(raw).expect("bicycl_joye_libert_new returned null");
        Ok(JoyeLibert {
            raw,
            _marker: PhantomData,
        })
    }

    /// Creates a CL_HSMqk instance.
    ///
    /// - `q_decimal`: the prime order `q` of the subgroup (decimal string).
    /// - `k`: the bit-size parameter `k` (plaintext space is `Z/q^k`).
    /// - `p_decimal`: the class-group prime `p` (decimal string).
    pub fn cl_hsmqk(&self, q_decimal: &str, k: u32, p_decimal: &str) -> Result<ClHsmqk> {
        let q_c = CString::new(q_decimal)?;
        let p_c = CString::new(p_decimal)?;
        let mut raw = std::ptr::null_mut();
        let status = unsafe {
            bicycl_rs_sys::bicycl_cl_hsmqk_new(
                self.raw.as_ptr(),
                q_c.as_ptr(),
                k,
                p_c.as_ptr(),
                &mut raw as *mut _,
            )
        };
        status_to_result(status)?;
        let raw = NonNull::new(raw).expect("bicycl_cl_hsmqk_new returned null");
        Ok(ClHsmqk {
            raw,
            _marker: PhantomData,
        })
    }

    /// Creates a CL_HSM2k instance.
    ///
    /// - `n_decimal`: the RSA-like composite modulus `n` (decimal string).
    /// - `k`: the bit-size parameter `k` (plaintext space is `Z/2^k`).
    pub fn cl_hsm2k(&self, n_decimal: &str, k: u32) -> Result<ClHsm2k> {
        let n_c = CString::new(n_decimal)?;
        let mut raw = std::ptr::null_mut();
        let status = unsafe {
            bicycl_rs_sys::bicycl_cl_hsm2k_new(
                self.raw.as_ptr(),
                n_c.as_ptr(),
                k,
                &mut raw as *mut _,
            )
        };
        status_to_result(status)?;
        let raw = NonNull::new(raw).expect("bicycl_cl_hsm2k_new returned null");
        Ok(ClHsm2k {
            raw,
            _marker: PhantomData,
        })
    }

    /// Creates an ECDSA instance at the given security level.
    ///
    /// `seclevel_bits` selects the elliptic curve (e.g., 112 → P-224, 128 → P-256).
    pub fn ecdsa(&self, seclevel_bits: u32) -> Result<Ecdsa> {
        let mut raw = std::ptr::null_mut();
        let status = unsafe {
            bicycl_rs_sys::bicycl_ecdsa_new(self.raw.as_ptr(), seclevel_bits, &mut raw as *mut _)
        };
        status_to_result(status)?;
        let raw = NonNull::new(raw).expect("bicycl_ecdsa_new returned null");
        Ok(Ecdsa {
            raw,
            _marker: PhantomData,
        })
    }

    /// Creates a new two-party ECDSA session at the given security level.
    ///
    /// Drive the session through the required keygen and sign rounds; see
    /// [`TwoPartyEcdsaSession`] for method details.
    pub fn two_party_ecdsa_session(
        &self,
        rng: &mut RandGen,
        seclevel_bits: u32,
    ) -> Result<TwoPartyEcdsaSession> {
        let mut raw = std::ptr::null_mut();
        let status = unsafe {
            bicycl_rs_sys::bicycl_two_party_ecdsa_session_new(
                self.raw.as_ptr(),
                rng.raw.as_ptr(),
                seclevel_bits,
                &mut raw as *mut _,
            )
        };
        status_to_result(status)?;
        let raw = NonNull::new(raw).expect("bicycl_two_party_ecdsa_session_new returned null");
        Ok(TwoPartyEcdsaSession {
            raw,
            _state: PhantomData,
            _marker: PhantomData,
        })
    }

    /// Creates a new CL DLog proof session at the given security level.
    ///
    /// Use this for non-interactive zero-knowledge proofs of discrete
    /// logarithm in the class group.  See [`ClDlogSession`] for the
    /// prove/verify round methods.
    pub fn cl_dlog_session(&self, rng: &mut RandGen, seclevel_bits: u32) -> Result<ClDlogSession> {
        let mut raw = std::ptr::null_mut();
        let status = unsafe {
            bicycl_rs_sys::bicycl_cl_dlog_session_new(
                self.raw.as_ptr(),
                rng.raw.as_ptr(),
                seclevel_bits,
                &mut raw as *mut _,
            )
        };
        status_to_result(status)?;
        let raw = NonNull::new(raw).expect("bicycl_cl_dlog_session_new returned null");
        Ok(ClDlogSession {
            raw,
            _state: PhantomData,
            _marker: PhantomData,
        })
    }

    /// Creates a new threshold ECDSA session.
    ///
    /// - `n_players`: total number of participants.
    /// - `threshold_t`: minimum number of participants required to sign
    ///   (must satisfy `threshold_t < n_players`).
    pub fn threshold_ecdsa_session(
        &self,
        rng: &mut RandGen,
        seclevel_bits: u32,
        n_players: u32,
        threshold_t: u32,
    ) -> Result<ThresholdEcdsaSession> {
        let mut raw = std::ptr::null_mut();
        let status = unsafe {
            bicycl_rs_sys::bicycl_threshold_ecdsa_session_new(
                self.raw.as_ptr(),
                rng.raw.as_ptr(),
                seclevel_bits,
                n_players,
                threshold_t,
                &mut raw as *mut _,
            )
        };
        status_to_result(status)?;
        let raw = NonNull::new(raw).expect("bicycl_threshold_ecdsa_session_new returned null");
        Ok(ThresholdEcdsaSession {
            raw,
            _state: PhantomData,
            _marker: PhantomData,
        })
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        unsafe { bicycl_rs_sys::bicycl_context_free(self.raw.as_ptr()) }
    }
}

/// A deterministic pseudo-random number generator seeded from a decimal value.
///
/// Create via [`Context::randgen_from_seed_decimal`].
#[derive(Debug)]
pub struct RandGen {
    raw: NonNull<bicycl_rs_sys::bicycl_randgen_t>,
    _marker: PhantomData<*mut ()>,
}

impl Drop for RandGen {
    fn drop(&mut self) {
        unsafe { bicycl_rs_sys::bicycl_randgen_free(self.raw.as_ptr()) }
    }
}

/// An imaginary quadratic class group defined by its discriminant.
///
/// Create via [`Context::classgroup_from_discriminant_decimal`].
#[derive(Debug)]
pub struct ClassGroup {
    raw: NonNull<bicycl_rs_sys::bicycl_classgroup_t>,
    _marker: PhantomData<*mut ()>,
}

impl ClassGroup {
    /// Returns the identity element (principal form) of this class group.
    pub fn one(&self, ctx: &Context) -> Result<Qfi> {
        let mut raw = std::ptr::null_mut();
        let status = unsafe {
            bicycl_rs_sys::bicycl_classgroup_one(
                ctx.raw.as_ptr(),
                self.raw.as_ptr(),
                &mut raw as *mut _,
            )
        };
        status_to_result(status)?;
        let raw = NonNull::new(raw).expect("bicycl_classgroup_one returned null");
        Ok(Qfi {
            raw,
            _marker: PhantomData,
        })
    }

    /// Computes the NUDUPL squaring of a QFI element (i.e., `input² = input ∘ input`).
    pub fn nudupl(&self, ctx: &Context, input: &Qfi) -> Result<Qfi> {
        let mut raw = std::ptr::null_mut();
        let status = unsafe {
            bicycl_rs_sys::bicycl_classgroup_nudupl(
                ctx.raw.as_ptr(),
                self.raw.as_ptr(),
                input.raw.as_ptr(),
                &mut raw as *mut _,
            )
        };
        status_to_result(status)?;
        let raw = NonNull::new(raw).expect("bicycl_classgroup_nudupl returned null");
        Ok(Qfi {
            raw,
            _marker: PhantomData,
        })
    }
}

impl Drop for ClassGroup {
    fn drop(&mut self) {
        unsafe { bicycl_rs_sys::bicycl_classgroup_free(self.raw.as_ptr()) }
    }
}

/// A Quadratic Form element in a class group.
///
/// Obtained from [`ClassGroup::one`] or [`ClassGroup::nudupl`].
#[derive(Debug)]
pub struct Qfi {
    raw: NonNull<bicycl_rs_sys::bicycl_qfi_t>,
    _marker: PhantomData<*mut ()>,
}

impl Qfi {
    /// Returns `true` if this element is the identity element of the class group.
    pub fn is_one(&self, ctx: &Context) -> Result<bool> {
        let mut out: c_int = 0;
        let status = unsafe {
            bicycl_rs_sys::bicycl_qfi_is_one(
                ctx.raw.as_ptr(),
                self.raw.as_ptr(),
                &mut out as *mut _,
            )
        };
        status_to_result(status)?;
        Ok(out != 0)
    }

    /// Returns the discriminant of the class group this element belongs to, as a decimal string.
    pub fn discriminant_decimal(&self, ctx: &Context) -> Result<String> {
        ffi_string_from_len(|buf, len| unsafe {
            bicycl_rs_sys::bicycl_qfi_discriminant_decimal(
                ctx.raw.as_ptr(),
                self.raw.as_ptr(),
                buf,
                len,
            )
        })
    }
}

impl Drop for Qfi {
    fn drop(&mut self) {
        unsafe { bicycl_rs_sys::bicycl_qfi_free(self.raw.as_ptr()) }
    }
}

/// A Paillier homomorphic encryption scheme instance.
///
/// Create via [`Context::paillier`].
#[derive(Debug)]
pub struct Paillier {
    raw: NonNull<bicycl_rs_sys::bicycl_paillier_t>,
    _marker: PhantomData<*mut ()>,
}

/// A Paillier secret key.  Keep this private.
#[derive(Debug)]
pub struct PaillierSecretKey {
    raw: NonNull<bicycl_rs_sys::bicycl_paillier_sk_t>,
    _marker: PhantomData<*mut ()>,
}

/// A Paillier public key.  Safe to share.
#[derive(Debug)]
pub struct PaillierPublicKey {
    raw: NonNull<bicycl_rs_sys::bicycl_paillier_pk_t>,
    _marker: PhantomData<*mut ()>,
}

/// A Paillier ciphertext.
#[derive(Debug)]
pub struct PaillierCiphertext {
    raw: NonNull<bicycl_rs_sys::bicycl_paillier_ct_t>,
    _marker: PhantomData<*mut ()>,
}

impl Paillier {
    /// Generates a fresh Paillier key pair.
    ///
    /// Returns `(secret_key, public_key)`.
    pub fn keygen(
        &self,
        ctx: &Context,
        rng: &mut RandGen,
    ) -> Result<(PaillierSecretKey, PaillierPublicKey)> {
        let mut sk_raw = std::ptr::null_mut();
        let mut pk_raw = std::ptr::null_mut();
        let status = unsafe {
            bicycl_rs_sys::bicycl_paillier_keygen(
                ctx.raw.as_ptr(),
                self.raw.as_ptr(),
                rng.raw.as_ptr(),
                &mut sk_raw as *mut _,
                &mut pk_raw as *mut _,
            )
        };
        status_to_result(status)?;

        let sk = PaillierSecretKey {
            raw: NonNull::new(sk_raw).expect("bicycl_paillier_keygen/sk returned null"),
            _marker: PhantomData,
        };
        let pk = PaillierPublicKey {
            raw: NonNull::new(pk_raw).expect("bicycl_paillier_keygen/pk returned null"),
            _marker: PhantomData,
        };
        Ok((sk, pk))
    }

    /// Encrypts a plaintext given as a decimal string.
    ///
    /// The plaintext must lie in `[0, N)` where `N` is the Paillier modulus.
    pub fn encrypt_decimal(
        &self,
        ctx: &Context,
        pk: &PaillierPublicKey,
        rng: &mut RandGen,
        message_decimal: &str,
    ) -> Result<PaillierCiphertext> {
        let message_c = CString::new(message_decimal)?;
        let mut ct_raw = std::ptr::null_mut();
        let status = unsafe {
            bicycl_rs_sys::bicycl_paillier_encrypt_decimal(
                ctx.raw.as_ptr(),
                self.raw.as_ptr(),
                pk.raw.as_ptr(),
                rng.raw.as_ptr(),
                message_c.as_ptr(),
                &mut ct_raw as *mut _,
            )
        };
        status_to_result(status)?;
        let raw = NonNull::new(ct_raw).expect("bicycl_paillier_encrypt_decimal returned null");
        Ok(PaillierCiphertext {
            raw,
            _marker: PhantomData,
        })
    }

    /// Decrypts a ciphertext, returning the plaintext as a decimal string.
    ///
    /// Unlike the Joye-Libert and CL variants, Paillier decryption requires both
    /// `pk` and `sk` because the underlying C API uses the public key's modulus
    /// during the decryption computation.
    pub fn decrypt_decimal(
        &self,
        ctx: &Context,
        pk: &PaillierPublicKey,
        sk: &PaillierSecretKey,
        ct: &PaillierCiphertext,
    ) -> Result<String> {
        ffi_string_from_len(|buf, len| unsafe {
            bicycl_rs_sys::bicycl_paillier_decrypt_decimal(
                ctx.raw.as_ptr(),
                self.raw.as_ptr(),
                pk.raw.as_ptr(),
                sk.raw.as_ptr(),
                ct.raw.as_ptr(),
                buf,
                len,
            )
        })
    }
}

impl Drop for Paillier {
    fn drop(&mut self) {
        unsafe { bicycl_rs_sys::bicycl_paillier_free(self.raw.as_ptr()) }
    }
}

impl Drop for PaillierSecretKey {
    fn drop(&mut self) {
        unsafe { bicycl_rs_sys::bicycl_paillier_sk_free(self.raw.as_ptr()) }
    }
}

impl Drop for PaillierPublicKey {
    fn drop(&mut self) {
        unsafe { bicycl_rs_sys::bicycl_paillier_pk_free(self.raw.as_ptr()) }
    }
}

impl Drop for PaillierCiphertext {
    fn drop(&mut self) {
        unsafe { bicycl_rs_sys::bicycl_paillier_ct_free(self.raw.as_ptr()) }
    }
}

/// A Joye-Libert homomorphic encryption scheme instance.
///
/// Create via [`Context::joye_libert`].
#[derive(Debug)]
pub struct JoyeLibert {
    raw: NonNull<bicycl_rs_sys::bicycl_joye_libert_t>,
    _marker: PhantomData<*mut ()>,
}

/// A Joye-Libert secret key.  Keep this private.
#[derive(Debug)]
pub struct JoyeLibertSecretKey {
    raw: NonNull<bicycl_rs_sys::bicycl_joye_libert_sk_t>,
    _marker: PhantomData<*mut ()>,
}

/// A Joye-Libert public key.  Safe to share.
#[derive(Debug)]
pub struct JoyeLibertPublicKey {
    raw: NonNull<bicycl_rs_sys::bicycl_joye_libert_pk_t>,
    _marker: PhantomData<*mut ()>,
}

/// A Joye-Libert ciphertext.
#[derive(Debug)]
pub struct JoyeLibertCiphertext {
    raw: NonNull<bicycl_rs_sys::bicycl_joye_libert_ct_t>,
    _marker: PhantomData<*mut ()>,
}

impl JoyeLibert {
    /// Generates a fresh Joye-Libert key pair.  Returns `(secret_key, public_key)`.
    pub fn keygen(
        &self,
        ctx: &Context,
        rng: &mut RandGen,
    ) -> Result<(JoyeLibertSecretKey, JoyeLibertPublicKey)> {
        let mut sk_raw = std::ptr::null_mut();
        let mut pk_raw = std::ptr::null_mut();
        let status = unsafe {
            bicycl_rs_sys::bicycl_joye_libert_keygen(
                ctx.raw.as_ptr(),
                self.raw.as_ptr(),
                rng.raw.as_ptr(),
                &mut sk_raw as *mut _,
                &mut pk_raw as *mut _,
            )
        };
        status_to_result(status)?;

        let sk = JoyeLibertSecretKey {
            raw: NonNull::new(sk_raw).expect("bicycl_joye_libert_keygen/sk returned null"),
            _marker: PhantomData,
        };
        let pk = JoyeLibertPublicKey {
            raw: NonNull::new(pk_raw).expect("bicycl_joye_libert_keygen/pk returned null"),
            _marker: PhantomData,
        };
        Ok((sk, pk))
    }

    /// Encrypts a plaintext given as a decimal string.
    ///
    /// The plaintext must be a non-negative integer less than `2^k`.
    pub fn encrypt_decimal(
        &self,
        ctx: &Context,
        pk: &JoyeLibertPublicKey,
        rng: &mut RandGen,
        message_decimal: &str,
    ) -> Result<JoyeLibertCiphertext> {
        let message_c = CString::new(message_decimal)?;
        let mut ct_raw = std::ptr::null_mut();
        let status = unsafe {
            bicycl_rs_sys::bicycl_joye_libert_encrypt_decimal(
                ctx.raw.as_ptr(),
                self.raw.as_ptr(),
                pk.raw.as_ptr(),
                rng.raw.as_ptr(),
                message_c.as_ptr(),
                &mut ct_raw as *mut _,
            )
        };
        status_to_result(status)?;
        let raw = NonNull::new(ct_raw).expect("bicycl_joye_libert_encrypt_decimal returned null");
        Ok(JoyeLibertCiphertext {
            raw,
            _marker: PhantomData,
        })
    }

    /// Decrypts a ciphertext, returning the plaintext as a decimal string.
    pub fn decrypt_decimal(
        &self,
        ctx: &Context,
        sk: &JoyeLibertSecretKey,
        ct: &JoyeLibertCiphertext,
    ) -> Result<String> {
        ffi_string_from_len(|buf, len| unsafe {
            bicycl_rs_sys::bicycl_joye_libert_decrypt_decimal(
                ctx.raw.as_ptr(),
                self.raw.as_ptr(),
                sk.raw.as_ptr(),
                ct.raw.as_ptr(),
                buf,
                len,
            )
        })
    }
}

impl Drop for JoyeLibert {
    fn drop(&mut self) {
        unsafe { bicycl_rs_sys::bicycl_joye_libert_free(self.raw.as_ptr()) }
    }
}

impl Drop for JoyeLibertSecretKey {
    fn drop(&mut self) {
        unsafe { bicycl_rs_sys::bicycl_joye_libert_sk_free(self.raw.as_ptr()) }
    }
}

impl Drop for JoyeLibertPublicKey {
    fn drop(&mut self) {
        unsafe { bicycl_rs_sys::bicycl_joye_libert_pk_free(self.raw.as_ptr()) }
    }
}

impl Drop for JoyeLibertCiphertext {
    fn drop(&mut self) {
        unsafe { bicycl_rs_sys::bicycl_joye_libert_ct_free(self.raw.as_ptr()) }
    }
}

/// A CL_HSMqk class-group encryption scheme with additive homomorphism over `Z/q^k`.
///
/// Create via [`Context::cl_hsmqk`].
#[derive(Debug)]
pub struct ClHsmqk {
    raw: NonNull<bicycl_rs_sys::bicycl_cl_hsmqk_t>,
    _marker: PhantomData<*mut ()>,
}

/// A CL_HSMqk secret key.  Keep this private.
#[derive(Debug)]
pub struct ClHsmqkSecretKey {
    raw: NonNull<bicycl_rs_sys::bicycl_cl_hsmqk_sk_t>,
    _marker: PhantomData<*mut ()>,
}

/// A CL_HSMqk public key.  Safe to share.
#[derive(Debug)]
pub struct ClHsmqkPublicKey {
    raw: NonNull<bicycl_rs_sys::bicycl_cl_hsmqk_pk_t>,
    _marker: PhantomData<*mut ()>,
}

/// A CL_HSMqk ciphertext.
#[derive(Debug)]
pub struct ClHsmqkCiphertext {
    raw: NonNull<bicycl_rs_sys::bicycl_cl_hsmqk_ct_t>,
    _marker: PhantomData<*mut ()>,
}

impl ClHsmqk {
    /// Generates a fresh CL_HSMqk key pair.  Returns `(secret_key, public_key)`.
    pub fn keygen(
        &self,
        ctx: &Context,
        rng: &mut RandGen,
    ) -> Result<(ClHsmqkSecretKey, ClHsmqkPublicKey)> {
        let mut sk_raw = std::ptr::null_mut();
        let mut pk_raw = std::ptr::null_mut();
        let status = unsafe {
            bicycl_rs_sys::bicycl_cl_hsmqk_keygen(
                ctx.raw.as_ptr(),
                self.raw.as_ptr(),
                rng.raw.as_ptr(),
                &mut sk_raw as *mut _,
                &mut pk_raw as *mut _,
            )
        };
        status_to_result(status)?;

        let sk = ClHsmqkSecretKey {
            raw: NonNull::new(sk_raw).expect("bicycl_cl_hsmqk_keygen/sk returned null"),
            _marker: PhantomData,
        };
        let pk = ClHsmqkPublicKey {
            raw: NonNull::new(pk_raw).expect("bicycl_cl_hsmqk_keygen/pk returned null"),
            _marker: PhantomData,
        };
        Ok((sk, pk))
    }

    /// Encrypts a plaintext in `Z/q^k` given as a decimal string.
    pub fn encrypt_decimal(
        &self,
        ctx: &Context,
        pk: &ClHsmqkPublicKey,
        rng: &mut RandGen,
        message_decimal: &str,
    ) -> Result<ClHsmqkCiphertext> {
        let message_c = CString::new(message_decimal)?;
        let mut ct_raw = std::ptr::null_mut();
        let status = unsafe {
            bicycl_rs_sys::bicycl_cl_hsmqk_encrypt_decimal(
                ctx.raw.as_ptr(),
                self.raw.as_ptr(),
                pk.raw.as_ptr(),
                rng.raw.as_ptr(),
                message_c.as_ptr(),
                &mut ct_raw as *mut _,
            )
        };
        status_to_result(status)?;
        let raw = NonNull::new(ct_raw).expect("bicycl_cl_hsmqk_encrypt_decimal returned null");
        Ok(ClHsmqkCiphertext {
            raw,
            _marker: PhantomData,
        })
    }

    /// Decrypts a CL_HSMqk ciphertext, returning the plaintext as a decimal string.
    pub fn decrypt_decimal(
        &self,
        ctx: &Context,
        sk: &ClHsmqkSecretKey,
        ct: &ClHsmqkCiphertext,
    ) -> Result<String> {
        ffi_string_from_len(|buf, len| unsafe {
            bicycl_rs_sys::bicycl_cl_hsmqk_decrypt_decimal(
                ctx.raw.as_ptr(),
                self.raw.as_ptr(),
                sk.raw.as_ptr(),
                ct.raw.as_ptr(),
                buf,
                len,
            )
        })
    }

    /// Homomorphically adds two ciphertexts: `Enc(a) ⊕ Enc(b) = Enc(a+b mod q^k)`.
    pub fn add_ciphertexts(
        &self,
        ctx: &Context,
        pk: &ClHsmqkPublicKey,
        rng: &mut RandGen,
        ca: &ClHsmqkCiphertext,
        cb: &ClHsmqkCiphertext,
    ) -> Result<ClHsmqkCiphertext> {
        let mut ct_raw = std::ptr::null_mut();
        let status = unsafe {
            bicycl_rs_sys::bicycl_cl_hsmqk_add_ciphertexts(
                ctx.raw.as_ptr(),
                self.raw.as_ptr(),
                pk.raw.as_ptr(),
                rng.raw.as_ptr(),
                ca.raw.as_ptr(),
                cb.raw.as_ptr(),
                &mut ct_raw as *mut _,
            )
        };
        status_to_result(status)?;
        let raw = NonNull::new(ct_raw).expect("bicycl_cl_hsmqk_add_ciphertexts returned null");
        Ok(ClHsmqkCiphertext {
            raw,
            _marker: PhantomData,
        })
    }

    /// Homomorphically multiplies a ciphertext by a scalar: `Enc(m) * s = Enc(m*s mod q^k)`.
    ///
    /// `scalar_decimal` is the scalar as a decimal string.
    pub fn scal_ciphertext_decimal(
        &self,
        ctx: &Context,
        pk: &ClHsmqkPublicKey,
        rng: &mut RandGen,
        ct: &ClHsmqkCiphertext,
        scalar_decimal: &str,
    ) -> Result<ClHsmqkCiphertext> {
        let scalar_c = CString::new(scalar_decimal)?;
        let mut out_raw = std::ptr::null_mut();
        let status = unsafe {
            bicycl_rs_sys::bicycl_cl_hsmqk_scal_ciphertext_decimal(
                ctx.raw.as_ptr(),
                self.raw.as_ptr(),
                pk.raw.as_ptr(),
                rng.raw.as_ptr(),
                ct.raw.as_ptr(),
                scalar_c.as_ptr(),
                &mut out_raw as *mut _,
            )
        };
        status_to_result(status)?;
        let raw =
            NonNull::new(out_raw).expect("bicycl_cl_hsmqk_scal_ciphertext_decimal returned null");
        Ok(ClHsmqkCiphertext {
            raw,
            _marker: PhantomData,
        })
    }

    /// Computes `Enc(a + b*s mod q^k)`: adds ciphertext `ca` to a scalar multiple of `cb`.
    ///
    /// Specifically, multiplies `cb` by `scalar_decimal` and adds the result to `ca`,
    /// equivalent to `scal_ciphertext_decimal(cb, s)` then `add_ciphertexts(ca, scaled_cb)`
    /// but in a single C call.  `scalar_decimal` is the scalar as a decimal string.
    pub fn addscal_ciphertexts_decimal(
        &self,
        ctx: &Context,
        pk: &ClHsmqkPublicKey,
        rng: &mut RandGen,
        ca: &ClHsmqkCiphertext,
        cb: &ClHsmqkCiphertext,
        scalar_decimal: &str,
    ) -> Result<ClHsmqkCiphertext> {
        let scalar_c = CString::new(scalar_decimal)?;
        let mut out_raw = std::ptr::null_mut();
        let status = unsafe {
            bicycl_rs_sys::bicycl_cl_hsmqk_addscal_ciphertexts_decimal(
                ctx.raw.as_ptr(),
                self.raw.as_ptr(),
                pk.raw.as_ptr(),
                rng.raw.as_ptr(),
                ca.raw.as_ptr(),
                cb.raw.as_ptr(),
                scalar_c.as_ptr(),
                &mut out_raw as *mut _,
            )
        };
        status_to_result(status)?;
        let raw = NonNull::new(out_raw)
            .expect("bicycl_cl_hsmqk_addscal_ciphertexts_decimal returned null");
        Ok(ClHsmqkCiphertext {
            raw,
            _marker: PhantomData,
        })
    }
}

impl Drop for ClHsmqk {
    fn drop(&mut self) {
        unsafe { bicycl_rs_sys::bicycl_cl_hsmqk_free(self.raw.as_ptr()) }
    }
}

impl Drop for ClHsmqkSecretKey {
    fn drop(&mut self) {
        unsafe { bicycl_rs_sys::bicycl_cl_hsmqk_sk_free(self.raw.as_ptr()) }
    }
}

impl Drop for ClHsmqkPublicKey {
    fn drop(&mut self) {
        unsafe { bicycl_rs_sys::bicycl_cl_hsmqk_pk_free(self.raw.as_ptr()) }
    }
}

impl Drop for ClHsmqkCiphertext {
    fn drop(&mut self) {
        unsafe { bicycl_rs_sys::bicycl_cl_hsmqk_ct_free(self.raw.as_ptr()) }
    }
}

/// A CL_HSM2k class-group encryption scheme with additive homomorphism over `Z/2^k`.
///
/// Create via [`Context::cl_hsm2k`].
#[derive(Debug)]
pub struct ClHsm2k {
    raw: NonNull<bicycl_rs_sys::bicycl_cl_hsm2k_t>,
    _marker: PhantomData<*mut ()>,
}

/// A CL_HSM2k secret key.  Keep this private.
#[derive(Debug)]
pub struct ClHsm2kSecretKey {
    raw: NonNull<bicycl_rs_sys::bicycl_cl_hsm2k_sk_t>,
    _marker: PhantomData<*mut ()>,
}

/// A CL_HSM2k public key.  Safe to share.
#[derive(Debug)]
pub struct ClHsm2kPublicKey {
    raw: NonNull<bicycl_rs_sys::bicycl_cl_hsm2k_pk_t>,
    _marker: PhantomData<*mut ()>,
}

/// A CL_HSM2k ciphertext.
#[derive(Debug)]
pub struct ClHsm2kCiphertext {
    raw: NonNull<bicycl_rs_sys::bicycl_cl_hsm2k_ct_t>,
    _marker: PhantomData<*mut ()>,
}

impl ClHsm2k {
    /// Generates a fresh CL_HSM2k key pair.  Returns `(secret_key, public_key)`.
    pub fn keygen(
        &self,
        ctx: &Context,
        rng: &mut RandGen,
    ) -> Result<(ClHsm2kSecretKey, ClHsm2kPublicKey)> {
        let mut sk_raw = std::ptr::null_mut();
        let mut pk_raw = std::ptr::null_mut();
        let status = unsafe {
            bicycl_rs_sys::bicycl_cl_hsm2k_keygen(
                ctx.raw.as_ptr(),
                self.raw.as_ptr(),
                rng.raw.as_ptr(),
                &mut sk_raw as *mut _,
                &mut pk_raw as *mut _,
            )
        };
        status_to_result(status)?;

        let sk = ClHsm2kSecretKey {
            raw: NonNull::new(sk_raw).expect("bicycl_cl_hsm2k_keygen/sk returned null"),
            _marker: PhantomData,
        };
        let pk = ClHsm2kPublicKey {
            raw: NonNull::new(pk_raw).expect("bicycl_cl_hsm2k_keygen/pk returned null"),
            _marker: PhantomData,
        };
        Ok((sk, pk))
    }

    /// Encrypts a plaintext in `Z/2^k` given as a decimal string.
    pub fn encrypt_decimal(
        &self,
        ctx: &Context,
        pk: &ClHsm2kPublicKey,
        rng: &mut RandGen,
        message_decimal: &str,
    ) -> Result<ClHsm2kCiphertext> {
        let message_c = CString::new(message_decimal)?;
        let mut ct_raw = std::ptr::null_mut();
        let status = unsafe {
            bicycl_rs_sys::bicycl_cl_hsm2k_encrypt_decimal(
                ctx.raw.as_ptr(),
                self.raw.as_ptr(),
                pk.raw.as_ptr(),
                rng.raw.as_ptr(),
                message_c.as_ptr(),
                &mut ct_raw as *mut _,
            )
        };
        status_to_result(status)?;
        let raw = NonNull::new(ct_raw).expect("bicycl_cl_hsm2k_encrypt_decimal returned null");
        Ok(ClHsm2kCiphertext {
            raw,
            _marker: PhantomData,
        })
    }

    /// Decrypts a CL_HSM2k ciphertext, returning the plaintext as a decimal string.
    pub fn decrypt_decimal(
        &self,
        ctx: &Context,
        sk: &ClHsm2kSecretKey,
        ct: &ClHsm2kCiphertext,
    ) -> Result<String> {
        ffi_string_from_len(|buf, len| unsafe {
            bicycl_rs_sys::bicycl_cl_hsm2k_decrypt_decimal(
                ctx.raw.as_ptr(),
                self.raw.as_ptr(),
                sk.raw.as_ptr(),
                ct.raw.as_ptr(),
                buf,
                len,
            )
        })
    }

    /// Homomorphically adds two ciphertexts: `Enc(a) ⊕ Enc(b) = Enc(a+b mod 2^k)`.
    pub fn add_ciphertexts(
        &self,
        ctx: &Context,
        pk: &ClHsm2kPublicKey,
        rng: &mut RandGen,
        ca: &ClHsm2kCiphertext,
        cb: &ClHsm2kCiphertext,
    ) -> Result<ClHsm2kCiphertext> {
        let mut ct_raw = std::ptr::null_mut();
        let status = unsafe {
            bicycl_rs_sys::bicycl_cl_hsm2k_add_ciphertexts(
                ctx.raw.as_ptr(),
                self.raw.as_ptr(),
                pk.raw.as_ptr(),
                rng.raw.as_ptr(),
                ca.raw.as_ptr(),
                cb.raw.as_ptr(),
                &mut ct_raw as *mut _,
            )
        };
        status_to_result(status)?;
        let raw = NonNull::new(ct_raw).expect("bicycl_cl_hsm2k_add_ciphertexts returned null");
        Ok(ClHsm2kCiphertext {
            raw,
            _marker: PhantomData,
        })
    }

    /// Homomorphically multiplies a ciphertext by a scalar: `Enc(m) * s = Enc(m*s mod 2^k)`.
    pub fn scal_ciphertext_decimal(
        &self,
        ctx: &Context,
        pk: &ClHsm2kPublicKey,
        rng: &mut RandGen,
        ct: &ClHsm2kCiphertext,
        scalar_decimal: &str,
    ) -> Result<ClHsm2kCiphertext> {
        let scalar_c = CString::new(scalar_decimal)?;
        let mut out_raw = std::ptr::null_mut();
        let status = unsafe {
            bicycl_rs_sys::bicycl_cl_hsm2k_scal_ciphertext_decimal(
                ctx.raw.as_ptr(),
                self.raw.as_ptr(),
                pk.raw.as_ptr(),
                rng.raw.as_ptr(),
                ct.raw.as_ptr(),
                scalar_c.as_ptr(),
                &mut out_raw as *mut _,
            )
        };
        status_to_result(status)?;
        let raw =
            NonNull::new(out_raw).expect("bicycl_cl_hsm2k_scal_ciphertext_decimal returned null");
        Ok(ClHsm2kCiphertext {
            raw,
            _marker: PhantomData,
        })
    }

    /// Computes `Enc(a + b*s mod 2^k)`: adds ciphertext `ca` to a scalar multiple of `cb`.
    ///
    /// Specifically, multiplies `cb` by `scalar_decimal` and adds the result to `ca`,
    /// equivalent to `scal_ciphertext_decimal(cb, s)` then `add_ciphertexts(ca, scaled_cb)`
    /// but in a single C call.  `scalar_decimal` is the scalar as a decimal string.
    pub fn addscal_ciphertexts_decimal(
        &self,
        ctx: &Context,
        pk: &ClHsm2kPublicKey,
        rng: &mut RandGen,
        ca: &ClHsm2kCiphertext,
        cb: &ClHsm2kCiphertext,
        scalar_decimal: &str,
    ) -> Result<ClHsm2kCiphertext> {
        let scalar_c = CString::new(scalar_decimal)?;
        let mut out_raw = std::ptr::null_mut();
        let status = unsafe {
            bicycl_rs_sys::bicycl_cl_hsm2k_addscal_ciphertexts_decimal(
                ctx.raw.as_ptr(),
                self.raw.as_ptr(),
                pk.raw.as_ptr(),
                rng.raw.as_ptr(),
                ca.raw.as_ptr(),
                cb.raw.as_ptr(),
                scalar_c.as_ptr(),
                &mut out_raw as *mut _,
            )
        };
        status_to_result(status)?;
        let raw = NonNull::new(out_raw)
            .expect("bicycl_cl_hsm2k_addscal_ciphertexts_decimal returned null");
        Ok(ClHsm2kCiphertext {
            raw,
            _marker: PhantomData,
        })
    }
}

impl Drop for ClHsm2k {
    fn drop(&mut self) {
        unsafe { bicycl_rs_sys::bicycl_cl_hsm2k_free(self.raw.as_ptr()) }
    }
}

impl Drop for ClHsm2kSecretKey {
    fn drop(&mut self) {
        unsafe { bicycl_rs_sys::bicycl_cl_hsm2k_sk_free(self.raw.as_ptr()) }
    }
}

impl Drop for ClHsm2kPublicKey {
    fn drop(&mut self) {
        unsafe { bicycl_rs_sys::bicycl_cl_hsm2k_pk_free(self.raw.as_ptr()) }
    }
}

impl Drop for ClHsm2kCiphertext {
    fn drop(&mut self) {
        unsafe { bicycl_rs_sys::bicycl_cl_hsm2k_ct_free(self.raw.as_ptr()) }
    }
}

/// An ECDSA signature scheme instance.
///
/// Create via [`Context::ecdsa`].
#[derive(Debug)]
pub struct Ecdsa {
    raw: NonNull<bicycl_rs_sys::bicycl_ecdsa_t>,
    _marker: PhantomData<*mut ()>,
}

/// An ECDSA secret (signing) key.  Keep this private.
#[derive(Debug)]
pub struct EcdsaSecretKey {
    raw: NonNull<bicycl_rs_sys::bicycl_ecdsa_sk_t>,
    _marker: PhantomData<*mut ()>,
}

/// An ECDSA public (verification) key.  Safe to share.
#[derive(Debug)]
pub struct EcdsaPublicKey {
    raw: NonNull<bicycl_rs_sys::bicycl_ecdsa_pk_t>,
    _marker: PhantomData<*mut ()>,
}

/// An ECDSA signature `(r, s)`.
#[derive(Debug)]
pub struct EcdsaSignature {
    raw: NonNull<bicycl_rs_sys::bicycl_ecdsa_sig_t>,
    _marker: PhantomData<*mut ()>,
}

impl Ecdsa {
    /// Generates a fresh ECDSA key pair.  Returns `(secret_key, public_key)`.
    pub fn keygen(
        &self,
        ctx: &Context,
        rng: &mut RandGen,
    ) -> Result<(EcdsaSecretKey, EcdsaPublicKey)> {
        let mut sk_raw = std::ptr::null_mut();
        let mut pk_raw = std::ptr::null_mut();
        let status = unsafe {
            bicycl_rs_sys::bicycl_ecdsa_keygen(
                ctx.raw.as_ptr(),
                self.raw.as_ptr(),
                rng.raw.as_ptr(),
                &mut sk_raw as *mut _,
                &mut pk_raw as *mut _,
            )
        };
        status_to_result(status)?;
        let sk = EcdsaSecretKey {
            raw: NonNull::new(sk_raw).expect("bicycl_ecdsa_keygen/sk returned null"),
            _marker: PhantomData,
        };
        let pk = EcdsaPublicKey {
            raw: NonNull::new(pk_raw).expect("bicycl_ecdsa_keygen/pk returned null"),
            _marker: PhantomData,
        };
        Ok((sk, pk))
    }

    /// Signs a message with the given secret key.
    ///
    /// `msg` is the raw message bytes (not a hash).  The C library hashes it internally.
    pub fn sign_message(
        &self,
        ctx: &Context,
        rng: &mut RandGen,
        sk: &EcdsaSecretKey,
        msg: &[u8],
    ) -> Result<EcdsaSignature> {
        let mut sig_raw = std::ptr::null_mut();
        let status = unsafe {
            bicycl_rs_sys::bicycl_ecdsa_sign_message(
                ctx.raw.as_ptr(),
                self.raw.as_ptr(),
                rng.raw.as_ptr(),
                sk.raw.as_ptr(),
                msg.as_ptr(),
                msg.len(),
                &mut sig_raw as *mut _,
            )
        };
        status_to_result(status)?;
        let raw = NonNull::new(sig_raw).expect("bicycl_ecdsa_sign_message returned null");
        Ok(EcdsaSignature {
            raw,
            _marker: PhantomData,
        })
    }

    /// Verifies a signature against a message and public key.
    ///
    /// Returns `true` if the signature is valid, `false` otherwise.
    /// Does **not** return an error on invalid signatures — errors indicate
    /// an internal failure (e.g., allocation), not a cryptographic mismatch.
    pub fn verify_message(
        &self,
        ctx: &Context,
        pk: &EcdsaPublicKey,
        msg: &[u8],
        sig: &EcdsaSignature,
    ) -> Result<bool> {
        let mut out_valid: c_int = 0;
        let status = unsafe {
            bicycl_rs_sys::bicycl_ecdsa_verify_message(
                ctx.raw.as_ptr(),
                self.raw.as_ptr(),
                pk.raw.as_ptr(),
                msg.as_ptr(),
                msg.len(),
                sig.raw.as_ptr(),
                &mut out_valid as *mut _,
            )
        };
        status_to_result(status)?;
        Ok(out_valid != 0)
    }
}

impl EcdsaSignature {
    /// Returns the `r` component of the signature as a decimal string.
    pub fn r_decimal(&self, ctx: &Context) -> Result<String> {
        ffi_string_from_len(|buf, len| unsafe {
            bicycl_rs_sys::bicycl_ecdsa_sig_r_decimal(ctx.raw.as_ptr(), self.raw.as_ptr(), buf, len)
        })
    }

    /// Returns the `s` component of the signature as a decimal string.
    pub fn s_decimal(&self, ctx: &Context) -> Result<String> {
        ffi_string_from_len(|buf, len| unsafe {
            bicycl_rs_sys::bicycl_ecdsa_sig_s_decimal(ctx.raw.as_ptr(), self.raw.as_ptr(), buf, len)
        })
    }
}

// ── Two-party ECDSA session with typestate ──

/// State markers for [`TwoPartyEcdsaSession`].
pub mod two_party {
    pub struct New;
    pub struct Keygen1;
    pub struct Keygen2;
    pub struct Keygen3;
    pub struct KeygenDone;
    pub struct Sign1;
    pub struct Sign2;
    pub struct Sign3;
    pub struct Sign4;
    pub struct SignDone;
}

/// A stateful session for the interactive two-party (2-of-2) ECDSA signing protocol.
///
/// Create via [`Context::two_party_ecdsa_session`].  Each round method consumes
/// the session and returns the next state on success.  On error, the session is
/// dropped (the protocol is broken and must be restarted from scratch).
///
/// ```text
/// New → keygen_round1 → Keygen1 → keygen_round2 → Keygen2
///     → keygen_round3 → Keygen3 → keygen_round4 → KeygenDone
///     → sign_round1 → Sign1 → sign_round2 → Sign2
///     → sign_round3 → Sign3 → sign_round4 → Sign4
///     → sign_finalize → SignDone
/// ```
///
/// Calling a method from the wrong state is a compile-time error:
///
/// ```compile_fail
/// # fn main() -> Result<(), bicycl_rs::Error> {
/// let ctx = bicycl_rs::Context::new()?;
/// let mut rng = ctx.randgen_from_seed_decimal("1")?;
/// let session = ctx.two_party_ecdsa_session(&mut rng, 112)?;
/// // ERROR: New state has no sign_round1
/// session.sign_round1(&ctx, &mut rng, b"msg")?;
/// # Ok(()) }
/// ```
pub struct TwoPartyEcdsaSession<S = two_party::New> {
    raw: NonNull<bicycl_rs_sys::bicycl_two_party_ecdsa_session_t>,
    _state: PhantomData<S>,
    _marker: PhantomData<*mut ()>,
}

impl<S> std::fmt::Debug for TwoPartyEcdsaSession<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TwoPartyEcdsaSession")
            .field("raw", &self.raw)
            .finish()
    }
}

impl<S> TwoPartyEcdsaSession<S> {
    fn transition<T>(self) -> TwoPartyEcdsaSession<T> {
        let raw = self.raw;
        std::mem::forget(self);
        TwoPartyEcdsaSession {
            raw,
            _state: PhantomData,
            _marker: PhantomData,
        }
    }
}

impl<S> Drop for TwoPartyEcdsaSession<S> {
    fn drop(&mut self) {
        unsafe { bicycl_rs_sys::bicycl_two_party_ecdsa_session_free(self.raw.as_ptr()) }
    }
}

impl TwoPartyEcdsaSession<two_party::New> {
    pub fn keygen_round1(
        self,
        ctx: &Context,
        rng: &mut RandGen,
    ) -> Result<TwoPartyEcdsaSession<two_party::Keygen1>> {
        let status = unsafe {
            bicycl_rs_sys::bicycl_two_party_ecdsa_keygen_round1(
                ctx.raw.as_ptr(),
                self.raw.as_ptr(),
                rng.raw.as_ptr(),
            )
        };
        status_to_result(status)?;
        Ok(self.transition())
    }
}

impl TwoPartyEcdsaSession<two_party::Keygen1> {
    pub fn keygen_round2(
        self,
        ctx: &Context,
        rng: &mut RandGen,
    ) -> Result<TwoPartyEcdsaSession<two_party::Keygen2>> {
        let status = unsafe {
            bicycl_rs_sys::bicycl_two_party_ecdsa_keygen_round2(
                ctx.raw.as_ptr(),
                self.raw.as_ptr(),
                rng.raw.as_ptr(),
            )
        };
        status_to_result(status)?;
        Ok(self.transition())
    }
}

impl TwoPartyEcdsaSession<two_party::Keygen2> {
    pub fn keygen_round3(
        self,
        ctx: &Context,
        rng: &mut RandGen,
    ) -> Result<TwoPartyEcdsaSession<two_party::Keygen3>> {
        let status = unsafe {
            bicycl_rs_sys::bicycl_two_party_ecdsa_keygen_round3(
                ctx.raw.as_ptr(),
                self.raw.as_ptr(),
                rng.raw.as_ptr(),
            )
        };
        status_to_result(status)?;
        Ok(self.transition())
    }
}

impl TwoPartyEcdsaSession<two_party::Keygen3> {
    pub fn keygen_round4(
        self,
        ctx: &Context,
    ) -> Result<TwoPartyEcdsaSession<two_party::KeygenDone>> {
        let status = unsafe {
            bicycl_rs_sys::bicycl_two_party_ecdsa_keygen_round4(ctx.raw.as_ptr(), self.raw.as_ptr())
        };
        status_to_result(status)?;
        Ok(self.transition())
    }
}

impl TwoPartyEcdsaSession<two_party::KeygenDone> {
    pub fn sign_round1(
        self,
        ctx: &Context,
        rng: &mut RandGen,
        msg: &[u8],
    ) -> Result<TwoPartyEcdsaSession<two_party::Sign1>> {
        let status = unsafe {
            bicycl_rs_sys::bicycl_two_party_ecdsa_sign_round1(
                ctx.raw.as_ptr(),
                self.raw.as_ptr(),
                rng.raw.as_ptr(),
                msg.as_ptr(),
                msg.len(),
            )
        };
        status_to_result(status)?;
        Ok(self.transition())
    }
}

impl TwoPartyEcdsaSession<two_party::Sign1> {
    pub fn sign_round2(
        self,
        ctx: &Context,
        rng: &mut RandGen,
    ) -> Result<TwoPartyEcdsaSession<two_party::Sign2>> {
        let status = unsafe {
            bicycl_rs_sys::bicycl_two_party_ecdsa_sign_round2(
                ctx.raw.as_ptr(),
                self.raw.as_ptr(),
                rng.raw.as_ptr(),
            )
        };
        status_to_result(status)?;
        Ok(self.transition())
    }
}

impl TwoPartyEcdsaSession<two_party::Sign2> {
    pub fn sign_round3(self, ctx: &Context) -> Result<TwoPartyEcdsaSession<two_party::Sign3>> {
        let status = unsafe {
            bicycl_rs_sys::bicycl_two_party_ecdsa_sign_round3(ctx.raw.as_ptr(), self.raw.as_ptr())
        };
        status_to_result(status)?;
        Ok(self.transition())
    }
}

impl TwoPartyEcdsaSession<two_party::Sign3> {
    pub fn sign_round4(
        self,
        ctx: &Context,
        rng: &mut RandGen,
    ) -> Result<TwoPartyEcdsaSession<two_party::Sign4>> {
        let status = unsafe {
            bicycl_rs_sys::bicycl_two_party_ecdsa_sign_round4(
                ctx.raw.as_ptr(),
                self.raw.as_ptr(),
                rng.raw.as_ptr(),
            )
        };
        status_to_result(status)?;
        Ok(self.transition())
    }
}

impl TwoPartyEcdsaSession<two_party::Sign4> {
    /// Returns `true` if the produced signature is valid.
    pub fn sign_finalize(
        self,
        ctx: &Context,
    ) -> Result<(TwoPartyEcdsaSession<two_party::SignDone>, bool)> {
        let mut out_valid: c_int = 0;
        let status = unsafe {
            bicycl_rs_sys::bicycl_two_party_ecdsa_sign_finalize(
                ctx.raw.as_ptr(),
                self.raw.as_ptr(),
                &mut out_valid as *mut _,
            )
        };
        status_to_result(status)?;
        Ok((self.transition(), out_valid != 0))
    }
}

// ── CL DLog session with typestate ──

/// State markers for [`ClDlogSession`].
pub mod cl_dlog {
    pub struct New;
    pub struct Prepared;
    pub struct Proved;
    pub struct StatementImported;
    pub struct Ready;
}

/// A session for the interactive CL DLog (discrete logarithm) proof protocol.
///
/// Create via [`Context::cl_dlog_session`].
///
/// **Prover path:**
/// ```text
/// New → prepare_statement → Prepared → prove_round → Proved
/// ```
/// In the `Proved` state: `export_statement`, `export_proof`, `verify_round`.
///
/// **Verifier path:**
/// ```text
/// New → import_statement → StatementImported → import_proof → Ready
/// ```
/// In the `Ready` state: `verify_round`.
///
/// Calling a method from the wrong state is a compile-time error:
///
/// ```compile_fail
/// # fn main() -> Result<(), bicycl_rs::Error> {
/// let ctx = bicycl_rs::Context::new()?;
/// let mut rng = ctx.randgen_from_seed_decimal("1")?;
/// let session = ctx.cl_dlog_session(&mut rng, 112)?;
/// // ERROR: New state has no prove_round
/// session.prove_round(&ctx, &mut rng)?;
/// # Ok(()) }
/// ```
pub struct ClDlogSession<S = cl_dlog::New> {
    raw: NonNull<bicycl_rs_sys::bicycl_cl_dlog_session_t>,
    _state: PhantomData<S>,
    _marker: PhantomData<*mut ()>,
}

impl<S> std::fmt::Debug for ClDlogSession<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClDlogSession")
            .field("raw", &self.raw)
            .finish()
    }
}

impl<S> ClDlogSession<S> {
    fn transition<T>(self) -> ClDlogSession<T> {
        let raw = self.raw;
        std::mem::forget(self);
        ClDlogSession {
            raw,
            _state: PhantomData,
            _marker: PhantomData,
        }
    }
}

impl<S> Drop for ClDlogSession<S> {
    fn drop(&mut self) {
        unsafe { bicycl_rs_sys::bicycl_cl_dlog_session_free(self.raw.as_ptr()) }
    }
}

/// A serializable message container used to exchange statements and proofs
/// between prover and verifier in the CL DLog protocol.
///
/// Create with [`ClDlogMessage::new`] and serialise/deserialise with
/// [`to_bytes`][Self::to_bytes] / [`load_bytes`][Self::load_bytes].
#[derive(Debug)]
pub struct ClDlogMessage {
    raw: NonNull<bicycl_rs_sys::bicycl_cl_dlog_message_t>,
    _marker: PhantomData<*mut ()>,
}

impl ClDlogSession<cl_dlog::New> {
    /// Prepares the statement (prover path).
    pub fn prepare_statement(
        self,
        ctx: &Context,
        rng: &mut RandGen,
    ) -> Result<ClDlogSession<cl_dlog::Prepared>> {
        let status = unsafe {
            bicycl_rs_sys::bicycl_cl_dlog_session_prepare_statement(
                ctx.raw.as_ptr(),
                self.raw.as_ptr(),
                rng.raw.as_ptr(),
            )
        };
        status_to_result(status)?;
        Ok(self.transition())
    }

    /// Imports the prover's statement (verifier path).
    pub fn import_statement(
        self,
        ctx: &Context,
        msg: &ClDlogMessage,
    ) -> Result<ClDlogSession<cl_dlog::StatementImported>> {
        let status = unsafe {
            bicycl_rs_sys::bicycl_cl_dlog_session_import_statement(
                ctx.raw.as_ptr(),
                self.raw.as_ptr(),
                msg.raw.as_ptr(),
            )
        };
        status_to_result(status)?;
        Ok(self.transition())
    }
}

impl ClDlogSession<cl_dlog::Prepared> {
    /// Executes the prover's round (generates the DLog proof).
    pub fn prove_round(
        self,
        ctx: &Context,
        rng: &mut RandGen,
    ) -> Result<ClDlogSession<cl_dlog::Proved>> {
        let status = unsafe {
            bicycl_rs_sys::bicycl_cl_dlog_session_prove_round(
                ctx.raw.as_ptr(),
                self.raw.as_ptr(),
                rng.raw.as_ptr(),
            )
        };
        status_to_result(status)?;
        Ok(self.transition())
    }
}

impl ClDlogSession<cl_dlog::Proved> {
    /// Exports the statement into `out_msg` so it can be sent to the verifier.
    pub fn export_statement(&self, ctx: &Context, out_msg: &mut ClDlogMessage) -> Result<()> {
        let status = unsafe {
            bicycl_rs_sys::bicycl_cl_dlog_session_export_statement(
                ctx.raw.as_ptr(),
                self.raw.as_ptr(),
                out_msg.raw.as_ptr(),
            )
        };
        status_to_result(status)
    }

    /// Exports the proof into `out_msg` so it can be sent to the verifier.
    pub fn export_proof(&self, ctx: &Context, out_msg: &mut ClDlogMessage) -> Result<()> {
        let status = unsafe {
            bicycl_rs_sys::bicycl_cl_dlog_session_export_proof(
                ctx.raw.as_ptr(),
                self.raw.as_ptr(),
                out_msg.raw.as_ptr(),
            )
        };
        status_to_result(status)
    }

    /// Verifies the proof (self-check).  Returns `true` if valid.
    pub fn verify_round(&self, ctx: &Context) -> Result<bool> {
        let mut out_valid: c_int = 0;
        let status = unsafe {
            bicycl_rs_sys::bicycl_cl_dlog_session_verify_round(
                ctx.raw.as_ptr(),
                self.raw.as_ptr(),
                &mut out_valid as *mut _,
            )
        };
        status_to_result(status)?;
        Ok(out_valid != 0)
    }
}

impl ClDlogSession<cl_dlog::StatementImported> {
    /// Imports the proof (on the verifier side).
    pub fn import_proof(
        self,
        ctx: &Context,
        msg: &ClDlogMessage,
    ) -> Result<ClDlogSession<cl_dlog::Ready>> {
        let status = unsafe {
            bicycl_rs_sys::bicycl_cl_dlog_session_import_proof(
                ctx.raw.as_ptr(),
                self.raw.as_ptr(),
                msg.raw.as_ptr(),
            )
        };
        status_to_result(status)?;
        Ok(self.transition())
    }
}

impl ClDlogSession<cl_dlog::Ready> {
    /// Executes the verifier's round.  Returns `true` if the proof is valid.
    pub fn verify_round(&self, ctx: &Context) -> Result<bool> {
        let mut out_valid: c_int = 0;
        let status = unsafe {
            bicycl_rs_sys::bicycl_cl_dlog_session_verify_round(
                ctx.raw.as_ptr(),
                self.raw.as_ptr(),
                &mut out_valid as *mut _,
            )
        };
        status_to_result(status)?;
        Ok(out_valid != 0)
    }
}

impl ClDlogMessage {
    /// Creates an empty message container.
    pub fn new() -> Result<Self> {
        let mut raw = std::ptr::null_mut();
        let status = unsafe { bicycl_rs_sys::bicycl_cl_dlog_message_new(&mut raw as *mut _) };
        status_to_result(status)?;
        let raw = NonNull::new(raw).expect("bicycl_cl_dlog_message_new returned null");
        Ok(Self {
            raw,
            _marker: PhantomData,
        })
    }

    /// Serializes the message to bytes for transmission.
    pub fn to_bytes(&self, ctx: &Context) -> Result<Vec<u8>> {
        ffi_bytes_from_len(|buf, len| unsafe {
            bicycl_rs_sys::bicycl_cl_dlog_message_export_bytes(
                ctx.raw.as_ptr(),
                self.raw.as_ptr(),
                buf,
                len,
            )
        })
    }

    /// Deserializes bytes into this message container (overwrites any previous content).
    pub fn load_bytes(&mut self, ctx: &Context, bytes: &[u8]) -> Result<()> {
        let status = unsafe {
            bicycl_rs_sys::bicycl_cl_dlog_message_import_bytes(
                ctx.raw.as_ptr(),
                self.raw.as_ptr(),
                bytes.as_ptr(),
                bytes.len(),
            )
        };
        status_to_result(status)
    }
}

impl Drop for ClDlogMessage {
    fn drop(&mut self) {
        unsafe { bicycl_rs_sys::bicycl_cl_dlog_message_free(self.raw.as_ptr()) }
    }
}

// ── Threshold ECDSA session with typestate ──

/// State markers for [`ThresholdEcdsaSession`].
pub mod threshold {
    pub struct New;
    pub struct Keygen1;
    pub struct Keygen2;
    pub struct KeygenDone;
    pub struct Sign1;
    pub struct Sign2;
    pub struct Sign3;
    pub struct Sign4;
    pub struct Sign5;
    pub struct Sign6;
    pub struct Sign7;
    pub struct Sign8;
    pub struct SignDone;
}

/// A stateful session for the threshold (t-of-n) ECDSA signing protocol.
///
/// Create via [`Context::threshold_ecdsa_session`].
///
/// ```text
/// New → keygen_round1 → Keygen1 → keygen_round2 → Keygen2
///     → keygen_finalize → KeygenDone
///     → sign_round1 → Sign1 → ... → Sign8
///     → sign_finalize → SignDone (signature_valid)
/// ```
///
/// Calling a method from the wrong state is a compile-time error:
///
/// ```compile_fail
/// # fn main() -> Result<(), bicycl_rs::Error> {
/// let ctx = bicycl_rs::Context::new()?;
/// let mut rng = ctx.randgen_from_seed_decimal("1")?;
/// let session = ctx.threshold_ecdsa_session(&mut rng, 112, 2, 1)?;
/// // ERROR: New state has no sign_round1
/// session.sign_round1(&ctx, &mut rng, b"msg")?;
/// # Ok(()) }
/// ```
pub struct ThresholdEcdsaSession<S = threshold::New> {
    raw: NonNull<bicycl_rs_sys::bicycl_threshold_ecdsa_session_t>,
    _state: PhantomData<S>,
    _marker: PhantomData<*mut ()>,
}

impl<S> std::fmt::Debug for ThresholdEcdsaSession<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ThresholdEcdsaSession")
            .field("raw", &self.raw)
            .finish()
    }
}

impl<S> ThresholdEcdsaSession<S> {
    fn transition<T>(self) -> ThresholdEcdsaSession<T> {
        let raw = self.raw;
        std::mem::forget(self);
        ThresholdEcdsaSession {
            raw,
            _state: PhantomData,
            _marker: PhantomData,
        }
    }
}

impl<S> Drop for ThresholdEcdsaSession<S> {
    fn drop(&mut self) {
        unsafe { bicycl_rs_sys::bicycl_threshold_ecdsa_session_free(self.raw.as_ptr()) }
    }
}

impl ThresholdEcdsaSession<threshold::New> {
    pub fn keygen_round1(
        self,
        ctx: &Context,
        rng: &mut RandGen,
    ) -> Result<ThresholdEcdsaSession<threshold::Keygen1>> {
        let status = unsafe {
            bicycl_rs_sys::bicycl_threshold_ecdsa_keygen_round1(
                ctx.raw.as_ptr(),
                self.raw.as_ptr(),
                rng.raw.as_ptr(),
            )
        };
        status_to_result(status)?;
        Ok(self.transition())
    }
}

impl ThresholdEcdsaSession<threshold::Keygen1> {
    pub fn keygen_round2(
        self,
        ctx: &Context,
        rng: &mut RandGen,
    ) -> Result<ThresholdEcdsaSession<threshold::Keygen2>> {
        let status = unsafe {
            bicycl_rs_sys::bicycl_threshold_ecdsa_keygen_round2(
                ctx.raw.as_ptr(),
                self.raw.as_ptr(),
                rng.raw.as_ptr(),
            )
        };
        status_to_result(status)?;
        Ok(self.transition())
    }
}

impl ThresholdEcdsaSession<threshold::Keygen2> {
    pub fn keygen_finalize(
        self,
        ctx: &Context,
    ) -> Result<ThresholdEcdsaSession<threshold::KeygenDone>> {
        let status = unsafe {
            bicycl_rs_sys::bicycl_threshold_ecdsa_keygen_finalize(
                ctx.raw.as_ptr(),
                self.raw.as_ptr(),
            )
        };
        status_to_result(status)?;
        Ok(self.transition())
    }
}

impl ThresholdEcdsaSession<threshold::KeygenDone> {
    pub fn sign_round1(
        self,
        ctx: &Context,
        rng: &mut RandGen,
        msg: &[u8],
    ) -> Result<ThresholdEcdsaSession<threshold::Sign1>> {
        let status = unsafe {
            bicycl_rs_sys::bicycl_threshold_ecdsa_sign_round1(
                ctx.raw.as_ptr(),
                self.raw.as_ptr(),
                rng.raw.as_ptr(),
                msg.as_ptr(),
                msg.len(),
            )
        };
        status_to_result(status)?;
        Ok(self.transition())
    }
}

impl ThresholdEcdsaSession<threshold::Sign1> {
    pub fn sign_round2(
        self,
        ctx: &Context,
        rng: &mut RandGen,
    ) -> Result<ThresholdEcdsaSession<threshold::Sign2>> {
        let status = unsafe {
            bicycl_rs_sys::bicycl_threshold_ecdsa_sign_round2(
                ctx.raw.as_ptr(),
                self.raw.as_ptr(),
                rng.raw.as_ptr(),
            )
        };
        status_to_result(status)?;
        Ok(self.transition())
    }
}

impl ThresholdEcdsaSession<threshold::Sign2> {
    pub fn sign_round3(self, ctx: &Context) -> Result<ThresholdEcdsaSession<threshold::Sign3>> {
        let status = unsafe {
            bicycl_rs_sys::bicycl_threshold_ecdsa_sign_round3(ctx.raw.as_ptr(), self.raw.as_ptr())
        };
        status_to_result(status)?;
        Ok(self.transition())
    }
}

impl ThresholdEcdsaSession<threshold::Sign3> {
    pub fn sign_round4(self, ctx: &Context) -> Result<ThresholdEcdsaSession<threshold::Sign4>> {
        let status = unsafe {
            bicycl_rs_sys::bicycl_threshold_ecdsa_sign_round4(ctx.raw.as_ptr(), self.raw.as_ptr())
        };
        status_to_result(status)?;
        Ok(self.transition())
    }
}

impl ThresholdEcdsaSession<threshold::Sign4> {
    pub fn sign_round5(
        self,
        ctx: &Context,
        rng: &mut RandGen,
    ) -> Result<ThresholdEcdsaSession<threshold::Sign5>> {
        let status = unsafe {
            bicycl_rs_sys::bicycl_threshold_ecdsa_sign_round5(
                ctx.raw.as_ptr(),
                self.raw.as_ptr(),
                rng.raw.as_ptr(),
            )
        };
        status_to_result(status)?;
        Ok(self.transition())
    }
}

impl ThresholdEcdsaSession<threshold::Sign5> {
    pub fn sign_round6(
        self,
        ctx: &Context,
        rng: &mut RandGen,
    ) -> Result<ThresholdEcdsaSession<threshold::Sign6>> {
        let status = unsafe {
            bicycl_rs_sys::bicycl_threshold_ecdsa_sign_round6(
                ctx.raw.as_ptr(),
                self.raw.as_ptr(),
                rng.raw.as_ptr(),
            )
        };
        status_to_result(status)?;
        Ok(self.transition())
    }
}

impl ThresholdEcdsaSession<threshold::Sign6> {
    pub fn sign_round7(
        self,
        ctx: &Context,
        rng: &mut RandGen,
    ) -> Result<ThresholdEcdsaSession<threshold::Sign7>> {
        let status = unsafe {
            bicycl_rs_sys::bicycl_threshold_ecdsa_sign_round7(
                ctx.raw.as_ptr(),
                self.raw.as_ptr(),
                rng.raw.as_ptr(),
            )
        };
        status_to_result(status)?;
        Ok(self.transition())
    }
}

impl ThresholdEcdsaSession<threshold::Sign7> {
    pub fn sign_round8(self, ctx: &Context) -> Result<ThresholdEcdsaSession<threshold::Sign8>> {
        let status = unsafe {
            bicycl_rs_sys::bicycl_threshold_ecdsa_sign_round8(ctx.raw.as_ptr(), self.raw.as_ptr())
        };
        status_to_result(status)?;
        Ok(self.transition())
    }
}

impl ThresholdEcdsaSession<threshold::Sign8> {
    pub fn sign_finalize(
        self,
        ctx: &Context,
    ) -> Result<ThresholdEcdsaSession<threshold::SignDone>> {
        let status = unsafe {
            bicycl_rs_sys::bicycl_threshold_ecdsa_sign_finalize(ctx.raw.as_ptr(), self.raw.as_ptr())
        };
        status_to_result(status)?;
        Ok(self.transition())
    }
}

impl ThresholdEcdsaSession<threshold::SignDone> {
    /// Returns `true` if the threshold signature produced by this session is valid.
    pub fn signature_valid(&self, ctx: &Context) -> Result<bool> {
        let mut out_valid: c_int = 0;
        let status = unsafe {
            bicycl_rs_sys::bicycl_threshold_ecdsa_signature_valid(
                ctx.raw.as_ptr(),
                self.raw.as_ptr(),
                &mut out_valid as *mut _,
            )
        };
        status_to_result(status)?;
        Ok(out_valid != 0)
    }
}

impl Drop for Ecdsa {
    fn drop(&mut self) {
        unsafe { bicycl_rs_sys::bicycl_ecdsa_free(self.raw.as_ptr()) }
    }
}

impl Drop for EcdsaSecretKey {
    fn drop(&mut self) {
        unsafe { bicycl_rs_sys::bicycl_ecdsa_sk_free(self.raw.as_ptr()) }
    }
}

impl Drop for EcdsaPublicKey {
    fn drop(&mut self) {
        unsafe { bicycl_rs_sys::bicycl_ecdsa_pk_free(self.raw.as_ptr()) }
    }
}

impl Drop for EcdsaSignature {
    fn drop(&mut self) {
        unsafe { bicycl_rs_sys::bicycl_ecdsa_sig_free(self.raw.as_ptr()) }
    }
}
