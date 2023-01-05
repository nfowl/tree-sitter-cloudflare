(string) @string
(number) @number
(boolean) @constant.builtin
(comment) @comment
(ERROR) @error

[
  (string_func)
  (bool_func)
  (number_func)
] @function

[
  (ip_range)
  (ipv4)
  (ip_list)
] @variable

[
 (number_field)
 (ip_field)
 (string_field)
 (bool_field)
] @type

[
  "not"
  "!"
  "and"
  "&&"
  "or"
  "||"
  "xor"
  "^^"
  "eq"
  "=="
  "ne"
  "!="
  "lt"
  "<"
  "le"
  "<="
  "gt"
  ">"
  "ge"
  ">="
  "contains"
  "matches"
  "~"
  "in"
] @operator

[
  "{"
  "}"
  "("
  ")"
] @punctuation.bracket
