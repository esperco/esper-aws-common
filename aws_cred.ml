(*
   Utility to load AWS credentials from an arbitrary file.

   Format: compatible with ~/.aws/config

   aws_access_key_id = ...
   aws_secret_access_key = ...
*)

let parse_line s =
  try
    let a, b = BatString.split ~by:"=" s in
    Some (BatString.trim a, BatString.trim b)
  with Not_found ->
    None

let load_credentials fname =
  let lines = BatList.of_enum (BatFile.lines_of fname) in
  let kv_list = BatList.filter_map parse_line lines in
  try
    (
      List.assoc "aws_access_key_id" kv_list,
      List.assoc "aws_secret_access_key" kv_list
    )
  with Not_found ->
    failwith
      ("Missing aws_access_key_id or aws_secret_access_key in config file "
        ^ fname)
