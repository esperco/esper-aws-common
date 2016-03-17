(*
   HTTP requests for all AWS APIs.
*)

type method_ = [
  | `GET
  | `POST
  | `PUT
  | `DELETE
  | `HEAD
  | `PATCH
]

val json_content_type : string

val make_headers :
  access_key_id:string ->
  secret_access_key:string ->
  content_type:string ->
  ?target:string ->
  http_request_method:method_ ->
  host:string ->
  region:string ->
  service:string ->
  path:string ->
  ?query_parameters:(string * string) list ->
  request_payload:string -> unit -> (string * string) list

val test_sha256 : unit -> bool
val test_canonical_request : unit -> bool
val test_string_to_sign : unit -> bool
val test_signing_key : unit -> bool
val test_signature : unit -> bool

val tests : (string * (unit -> bool)) list
