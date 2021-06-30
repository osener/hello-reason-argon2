open Argon2;

let () = {
  let message = fmt => Printf.ksprintf(Printf.printf("%s\n%!"), fmt);
  let hash_len = 32;
  let t_cost = 2;
  let m_cost = 65536;
  let parallelism = 1;
  let salt = "0000000000000000";
  let salt_len = String.length(salt);
  let pwd = "password";
  let encoded_len =
    encoded_len(
      ~t_cost,
      ~m_cost,
      ~parallelism,
      ~salt_len,
      ~hash_len,
      ~kind=D,
    );

  switch (I.hash_raw(~t_cost, ~m_cost, ~parallelism, ~pwd, ~salt, ~hash_len)) {
  | Result.Ok(hash) =>
    message("argon2i hash:");
    /* ec6891c09fc1461720e508485da42b2087ca9a708185d9dc890539a33cd2af6f */
    I.hash_to_string(hash)
    |> String.iter(c => Printf.printf("%02x", Char.code(c)));
    message("");
  | Result.Error(e) =>
    message(
      "Error while computing hash with argon2i_hash_raw: %s",
      ErrorCodes.message(e),
    )
  };
  switch (D.hash_raw(~t_cost, ~m_cost, ~parallelism, ~pwd, ~salt, ~hash_len)) {
  | Result.Ok(hash) =>
    message("argon2d hash:");
    /* 30f5e9f2584e962bba213cc256dcf9ccdce18d8f67a6cbf8e012e0619b6d52d2 */
    D.hash_to_string(hash)
    |> String.iter(c => Printf.printf("%02x", Char.code(c)));
    message("");
  | Result.Error(e) =>
    message(
      "Error while computing hash with argon2d_hash_raw: %s",
      ErrorCodes.message(e),
    )
  };
  switch (
    hash(
      ~t_cost,
      ~m_cost,
      ~parallelism,
      ~pwd,
      ~salt,
      ~kind=D,
      ~hash_len,
      ~encoded_len,
      ~version=VERSION_NUMBER,
    )
  ) {
  | Result.Ok((hash, encoded)) =>
    message("hash argon2d:");
    String.iter(c => Printf.printf("%02x", Char.code(c)), hash);
    message("\nencoded argon2d:%s", encoded);
    switch (verify(~encoded, ~pwd, ~kind=D)) {
    | Result.Ok(_) => message("verify OK")
    | Result.Error(e) =>
      message("Error while computing verify: %s", ErrorCodes.message(e))
    };
  | Result.Error(e) =>
    message("Error while computing hash: %s", ErrorCodes.message(e))
  };
};
