(*
   HTTP requests for all AWS APIs.
*)

val json_content_type : string

val make_headers :
  secret_access_key:string ->
  content_type:string ->
  ?target:string ->
  http_request_method:string ->
  host:string ->
  region:string ->
  service:string ->
  path:string ->
  ?query_parameters:(string * string) list ->
  request_payload:string -> unit -> (string * string) list

val tests : (string * (unit -> bool)) list