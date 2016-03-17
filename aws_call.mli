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

val tests : (string * (unit -> bool)) list
