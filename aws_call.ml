(*
   HTTP requests for all AWS APIs.

   http://docs.aws.amazon.com/general/latest/gr/signing_aws_api_requests.html
*)

open Printf
open Log

let json_content_type = "application/x-amz-json-1.1"

let hex_encode =
  let transform = Cryptokit.Hexa.encode () in
  fun s ->
    Cryptokit.transform_string transform s

let sha256 =
  let hash = Cryptokit.Hash.sha256 () in
  fun s ->
    Cryptokit.hash_string hash s

let test_sha256 () =
  hex_encode (sha256 "")
  = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

let hmac_sha256 signing_key =
  let hash = Cryptokit.MAC.hmac_sha256 signing_key in
  fun s ->
    Cryptokit.hash_string hash s

(*
   Percent-encode exactly how specified by the docs.
   For instance, ":" must be percent-encoded (Uri.pct_encode leaves it
   untouched).
*)
let percent_encode s =
  let buf = Buffer.create (2 * String.length s) in
  String.iter (function
    | 'A'..'Z'
    | 'a'..'z'
    | '0'..'9'
    | '-' | '_' | '~' as c ->
        Buffer.add_char buf c
    | c ->
        bprintf buf "%%%02X" (Char.code c)
  ) s;
  Buffer.contents buf

let make_canonical_query_string param_list =
  let l =
    List.stable_sort (fun (k1, _) (k2, _) -> String.compare k1 k2)
      param_list
  in
  String.concat "&" (
    BatList.map (fun (k, v) ->
      sprintf "%s=%s" k (percent_encode v)
    ) l
  )

(* "20160314" *)
let make_amz_dateonly t =
  let date = Nldate.create t in
  Nldate.format ~fmt:"%Y%m%d" date

(* "20160314T215921Z" *)
let make_amz_date t =
  let date = Nldate.create t in
  Nldate.format ~fmt:"%Y%m%dT%H%M%SZ" date

let make_canonical_headers ~host ~date =
  let canonical_headers =
    sprintf "host:%s\n\
             x-amz-date:%s\n"
      host
      (make_amz_date date)
  in
  let signed_headers = "host;x-amz-date" in
  canonical_headers, signed_headers

let make_canonical_request
    ~http_request_method
    ~host
    ~date
    ~path
    ?(query_parameters = [])
    ~request_payload
    () =
  let canonical_uri = path in
  let canonical_query_string = make_canonical_query_string query_parameters in
  let canonical_headers, signed_headers = make_canonical_headers ~host ~date in
  let canonical_request =
    String.concat "\n" [
      http_request_method; (* "GET", "POST", etc. *)
      canonical_uri; (* path, stopping before the '?' *)
      canonical_query_string; (* query string w/o '?', e.g. "x=0&y=1" *)
      canonical_headers;
      signed_headers; (* names of the headers included in canonical_headers *)
      hex_encode (sha256 request_payload);
    ]
  in
  signed_headers, canonical_request

let test_canonical_request () =
 let signed_headers, canonical_request =
  make_canonical_request
    ~http_request_method: "GET"
    ~host: "iam.amazonaws.com"
    ~date: Util_time.(to_float (of_string "2015-08-30T12:36:00Z"))
    ~path: "/"
    ~query_parameters: [ "Version", "2010-05-08";
                         "Action", "ListUsers" ]
    ~request_payload: ""
    ()
 in
 let expected = "\
GET
/
Action=ListUsers&Version=2010-05-08
host:iam.amazonaws.com
x-amz-date:20150830T123600Z

host;x-amz-date
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
  in
  canonical_request = expected

(* "20150830/us-east-1/iam/aws4_request\n" *)
let make_credential_scope ~date ~region ~service =
  sprintf "%s/%s/%s/aws4_request"
    (make_amz_dateonly date) region service

let make_string_to_sign
    ~http_request_method
    ~host
    ~region
    ~service
    ~date
    ~path
    ?query_parameters
    ~request_payload
    () =
  let credential_scope = make_credential_scope ~date ~region ~service in
  let signed_headers, canonical_request =
    make_canonical_request
      ~http_request_method
      ~host
      ~date
      ~path
      ?query_parameters
      ~request_payload
      ()
  in
  let string_to_sign =
    sprintf "\
      AWS4-HMAC-SHA256\n\
      %s\n\
      %s\n\
      %s"
      (make_amz_date date)
      credential_scope
      (hex_encode (sha256 canonical_request))
  in
  credential_scope, signed_headers, string_to_sign

(*
   GET https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08 HTTP/1.1
   Host: iam.amazonaws.com
   X-Amz-Date: 20150830T123600Z
*)
let test_string_to_sign () =
  let credential_scope, signed_headers, string_to_sign =
    make_string_to_sign
      ~http_request_method: "GET"
      ~host: "iam.amazonaws.com"
      ~region: "us-east-1"
      ~service: "iam"
      ~date: Util_time.(to_float (of_string "2015-08-30T12:36:00Z"))
      ~path: "/"
      ~query_parameters: [ "Action", "ListUsers";
                           "Version", "2010-05-08" ]
      ~request_payload: ""
      ()
  in
  let expected = "\
AWS4-HMAC-SHA256
20150830T123600Z
20150830/us-east-1/iam/aws4_request
d990da287c07a9e88f333eb5e1730f6d5a2ff912af59bb342c1cf40596c5d334"
  in
  string_to_sign = expected

let make_signing_key
    ~secret_access_key
    ~date
    ~region
    ~service
    () =
  let k_date =
    hmac_sha256
      ("AWS4" ^ secret_access_key)
      (make_amz_dateonly date)
  in
  let k_region = hmac_sha256 k_date region in
  let k_service = hmac_sha256 k_region service in
  let k_signing = hmac_sha256 k_service "aws4_request" in
  k_signing

let test_signing_key () =
  let signing_key =
    make_signing_key
      ~secret_access_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
      ~date: Util_time.(to_float (of_string "2015-08-30T12:36:00Z"))
      ~region: "us-east-1"
      ~service: "iam"
      ()
  in
  let expected =
    "\196\175\177\204\087\113\216\113\118\058\057\062\068\183\003\087\
     \027\085\204\040\066\077\026\094\134\218\110\211\193\084\164\185"
  in
  signing_key = expected

let make_signature
    ~secret_access_key
    ~http_request_method
    ~host
    ~date
    ~region
    ~service
    ~path
    ?query_parameters
    ~request_payload
    () =
  let credential_scope, signed_headers, string_to_sign =
    make_string_to_sign
      ~http_request_method
      ~host
      ~region
      ~service
      ~date
      ~path
      ?query_parameters
      ~request_payload
      ()
  in
  let signing_key =
    make_signing_key
      ~secret_access_key
      ~date
      ~region
      ~service
      ()
  in
  let signature = hex_encode (hmac_sha256 signing_key string_to_sign) in
  credential_scope, signed_headers, signature

let make_authorization_header
    ~secret_access_key
    ~http_request_method
    ~host
    ~date
    ~region
    ~service
    ~path
    ?query_parameters
    ~request_payload
    () =
  let credential_scope, signed_headers, signature =
    make_signature
      ~secret_access_key
      ~http_request_method
      ~host
      ~date
      ~region
      ~service
      ~path
      ?query_parameters
      ~request_payload
      ()
  in
  sprintf "\
AWS4-HMAC-SHA256 \
Credential=%s, \
SignedHeaders=%s, \
Signature=%s"
    credential_scope
    signed_headers
    signature

let make_headers
    ~secret_access_key
    ~content_type
    ?target
    ~http_request_method
    ~host
    ~region
    ~service
    ~path
    ?query_parameters
    ~request_payload
    () =

  let date = Unix.time () in
  let authorization =
    make_authorization_header
      ~secret_access_key
      ~http_request_method
      ~host
      ~date
      ~region
      ~service
      ~path
      ?query_parameters
      ~request_payload
      ()
  in
  let target =
    match target with
    | None -> []
    | Some s -> [ "x-amz-target", s ]
  in
  BatList.flatten [
    [ "authorization", authorization;
      "x-amz-date", Nldate.mk_mail_date date;
      "content-type", content_type ];
    target;
  ]

let tests = [
  "sha256", test_sha256;
  "canonical request", test_canonical_request;
  "string to sign", test_string_to_sign;
  "signing key", test_signing_key;
]