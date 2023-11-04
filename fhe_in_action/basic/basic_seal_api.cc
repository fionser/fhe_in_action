#include "seal/seal.h"
#include <iostream>
#include <sstream>

template <class Obj> std::string EncodeSEALObject(const Obj &obj) {
  std::ostringstream str;
  obj.save(str);
  return str.str();
}

template <class Obj>
void DecodeSEALObject(const seal::SEALContext &context, std::string byte_stream,
                      Obj &obj) {
  std::istringstream str(byte_stream);
  obj.load(context, str);
}

template <class Obj> size_t GetSEALObjectSize(const Obj &obj) {
  return EncodeSEALObject(obj).length();
}

int main() {
  /// Parameters
  /// Define the polynomial ring Z_q[X] / X^N + 1
  size_t poly_deg_N = 4096; // Should be two power
  /// The ciphertext modulus q is defined as the product of 2 primes
  std::vector<int> modulus_q_bits = {30, 30, 30};
  /// modulus = [1073651713, 1073668097, 1073692673]
  std::vector<seal::Modulus> modulus =
      seal::CoeffModulus::Create(poly_deg_N, modulus_q_bits);

  /// All the primes used by SEAL should `p = 1 mod 2N`
  for (size_t i = 0; i < modulus.size(); ++i) {
    printf("Prime[%zd] %llu, = %llu mod 2N\n", i, modulus[i].value(),
           modulus[i].value() % (2 * poly_deg_N));
  }

  seal::EncryptionParameters parms(seal::scheme_type::bfv);
  parms.set_poly_modulus_degree(poly_deg_N);
  parms.set_coeff_modulus(modulus);
  /// BFV scheme needs plaintext modulus
  parms.set_plain_modulus(1024);

  /// SEAL's Context
  seal::SEALContext context(
      parms, /*expand modulus chain*/ true,
      /*at least security level */ seal::sec_level_type::tc128);
  /// First context points to all the ciphertext modulus
  /// Here is 1073651713 and 1073668097
  printf("Modulus Chain: first context index %zd => prime %llu\n",
         context.first_context_data()->chain_index(),
         context.first_context_data()->parms().coeff_modulus().back().value());

  /// Last context (index 0) points to the last prime in the chain
  /// Here is 1073651713
  printf("Modulus Chain: last context index %zd => prime %llu\n",
         context.last_context_data()->chain_index(),
         context.last_context_data()->parms().coeff_modulus().back().value());

  /// Q: where is the 3rd prime ?
  /// A: SEAL saves the last prime specially for keygen.
  /// To access that **special prime**, we need to call `key_context_data()`
  printf("Modulus Chain: key context index %zd => prime %llu\n",
         context.key_context_data()->chain_index(),
         context.key_context_data()->parms().coeff_modulus().back().value());

  /// KeyGeneration
  /// Create secret key and public key pair
  seal::KeyGenerator keygen(context);
  seal::SecretKey secret_key = keygen.secret_key();
  seal::PublicKey public_key;
  keygen.create_public_key(public_key);

  /// SEAL aslo provides API for `smaller` key size
  /// We can use it for network transfer.
  seal::Serializable<seal::PublicKey> ser_public_key =
      keygen.create_public_key();
  /// public key in bytes 108504 53053
  /// The serializable key is about 50% size
  printf("public key in bytes %zd %zd\n", GetSEALObjectSize(public_key),
         GetSEALObjectSize(ser_public_key));
  std::string bytes_stream_for_public_key = EncodeSEALObject(ser_public_key);

  seal::PublicKey public_key_recv;
  DecodeSEALObject(context, bytes_stream_for_public_key, public_key_recv);
  printf("Is recv public key valid %d\n",
         seal::is_data_valid_for(public_key_recv, context));

  /// Encryption & Decryption
  seal::Encryptor encryptor(context, public_key);
  seal::Decryptor decryptor(context, secret_key);

  seal::Plaintext plain;
  plain.resize(2);
  plain[0] = 10;
  plain[1] = 1000;

  seal::Ciphertext cipher;
  encryptor.encrypt(plain, cipher);

  seal::Plaintext decrypted;
  decryptor.decrypt(cipher, decrypted);
  printf("decrypted poly contains %zd coefficients\n", decrypted.coeff_count());
  /// 10
  printf("0-th is %llu\n", decrypted[0]);
  /// 1000
  printf("1-th is %llu\n", decrypted[1]);

  seal::Evaluator evaluator(context);
  seal::Ciphertext computed_cipher;
  evaluator.add(cipher, cipher, computed_cipher);
  decryptor.decrypt(computed_cipher, decrypted);
  printf("decrypted poly contains %zd coefficients\n", decrypted.coeff_count());
  /// 20
  printf("0-th is %llu\n", decrypted[0]);
  /// 976 that is because 1000 + 1000 = 976 mod 1024 where 1024 is our plaintext
  /// modulus
  printf("1-th is %llu\n", decrypted[1]);
  return 0;
}
