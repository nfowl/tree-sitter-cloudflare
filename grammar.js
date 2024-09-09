const NUMBER_COMPARISON_OPS = [
  "eq",
  "ne",
  "lt",
  "le",
  "gt",
  "ge",
  "==",
  "!=",
  "<",
  "<=",
  ">",
  ">=",
];

const STRING_COMPARISON_OPS = [
  "eq",
  "ne",
  "lt",
  "le",
  "gt",
  "ge",
  "==",
  "!=",
  "<",
  "<=",
  ">",
  ">=",
  "contains",
  "matches",
  "strict wildcard",
  "wildcard",
  "~",
];

module.exports = grammar({
  name: "cloudflare",

  extras: ($) => [$.comment, /\s/],

  rules: {
    source_file: ($) => repeat($._expression),

    _expression: ($) =>
      choice(
        $.not_expression,
        $.compound_expression,
        $.group,
        $.simple_expression,
        $._bool_lhs,
        $.in_expression,
      ),

    not_expression: ($) => prec(4, seq($.not_operator, $._expression)),

    in_expression: ($) => {
      const in_options = [
        [$.ip_field, choice($.ip_set, $.ip_list)],
        [$.stringlike_field, $.string_set],
        [$._number_lhs, $.number_set],
      ];

      return choice(
        ...in_options.map(([field_type, target]) =>
          seq(
            field("lhs", field_type),
            field("operator", "in"),
            field("rhs", target),
          ),
        ),
      );
    },

    compound_expression: ($) => {
      const precs = [
        ["&&", 3],
        ["and", 3],
        ["xor", 2],
        ["^^", 2],
        ["or", 1],
        ["||", 1],
      ];

      return choice(
        ...precs.map(([operator, precedence]) =>
          prec.left(
            precedence,
            seq(
              field("lhs", $._expression),
              field("operator", operator),
              field("rhs", $._expression),
            ),
          ),
        ),
      );
    },

    ip_set: ($) => seq("{", repeat1($._ip), "}"),

    string_set: ($) => seq("{", repeat1($.string), "}"),

    comment: ($) => token(seq("#", /.*/)),

    number_set: ($) => seq("{", repeat1($.number), "}"),

    simple_expression: ($) => {
      const comps = [
        [STRING_COMPARISON_OPS, $.stringlike_field, $.string],
        [NUMBER_COMPARISON_OPS, $._number_lhs, $.number],
        [["eq", "ne", "==", "!="], $.ip_field, $._ip],
      ];

      return choice(
        ...comps.map(([operators, f, type]) =>
          seq(
            field("lhs", f),
            field("operator", choice(...operators)),
            field("rhs", type),
          ),
        ),
      );
    },

    _bool_lhs: ($) => choice($.boollike_field, $.boolean),

    _number_lhs: ($) => choice($.numberlike_field, $.number_func),

    // _string_lhs: ($) => choice($.stringlike_field, $.string_func),

    // functions grouped by return type for use in expressions
    string_func: ($) =>
      choice(
        concatFunc(
          choice($.string, $.stringlike_field),
          choice($.string, $.stringlike_field),
        ),
        lookupFunc($.stringlike_field, choice($.string, $.number)),
        lowerFunc($.stringlike_field),
        regexReplaceFunc($.stringlike_field, $.string),
        removeBytesFunc(choice($.stringlike_field, $.bytes_field), $.string),
        toStringFunc(choice($.numberlike_field, $.ip_field, $.boollike_field)),
        upperFunc($.stringlike_field),
        urlDecodeFunc($.stringlike_field),
        uuidv4Func($.stringlike_field),
      ),

    number_func: ($) =>
      choice(lenFunc(choice($.stringlike_field, $.bytes_field))),

    bool_func: ($) =>
      choice(
        $.array_func,
        endsWithFunc($.stringlike_field, $.string),
        startsWithFunc($.stringlike_field, $.string),
      ),

    array_func: ($) => {
      // Needs to support simple expressions and in and bool
      const in_func = [
        [arrayExpander($.number_array), $.number_set],
        [arrayExpander($.string_array), $.string_set],
      ];
      const inOptions = choice(
        ...in_func.map(([field_type, target]) =>
          seq(
            field("lhs", field_type),
            field("operator", "in"),
            field("rhs", target),
          ),
        ),
      );

      const simple = [
        [STRING_COMPARISON_OPS, arrayExpander($.string_array), $.string],
        [NUMBER_COMPARISON_OPS, arrayExpander($.number_array), $.number],
      ];

      const simpleOptions = choice(
        ...simple.map(([operators, f, type]) =>
          seq(
            field("lhs", f),
            field("operator", choice(...operators)),
            field("rhs", type),
          ),
        ),
      );

      return seq(
        field("func", choice("any", "all")),
        "(",
        choice(simpleOptions, inOptions, arrayExpander($.bool_array)),
        ")",
      );
    },

    //TODO(nfowl): Implement these
    // bit_slice_func: $ => seq(),
    // is_timed_hmac_valid_v0: $ => seq(),

    group: ($) => seq("(", field("inner", $._expression), ")"),

    number: ($) => /\d+/,

    //TODO(nfowl): Get this working with escaped characters and fix hacky mess
    string: ($) => /"([^"]*)"/,

    // _escape_sequence: $ => token(prec(1, seq(
    //   '\\',
    //   /["\\]/,
    // ))),

    boolean: ($) => choice("true", "false"),

    _ip: ($) =>
      choice(
        $.ipv4,
        $.ip_range,
        //TODO(nfowl): Add ipv6
      ),
    ipv4: ($) =>
      /(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}/,

    ip_range: ($) =>
      seq(field("ip", $.ipv4), "/", field("mask", /(?:3[0-2]|[0-2]?[0-9])/)),

    ip_list: ($) =>
      token(
        seq(
          "$",
          choice(
            /[a-z\d_]*/,
            "cf.open_proxies",
            "cf.anonymizer",
            "cf.vpn",
            "cf.malware",
            "cf.botnetcc",
          ),
        ),
      ),

    not_operator: ($) => choice("not", "!"),

    number_array: ($) =>
      choice($.array_number_field, lenFunc($._string_array_expansion)),

    bool_array: ($) =>
      choice(
        endsWithFunc($._string_array_expansion, $.string),
        startsWithFunc($._string_array_expansion, $.string),
      ),

    string_array: ($) =>
      choice(
        $.array_string_field,
        seq($.map_string_array_field, "[", field("key", $.string), "]"),
        concatFunc(
          $._string_array_expansion,
          choice($.string, $.stringlike_field),
        ),
        lookupFunc($._string_array_expansion, choice($.string, $.number)),
        lowerFunc($._string_array_expansion),
        regexReplaceFunc($._string_array_expansion, $.string),
        removeBytesFunc($._string_array_expansion, $.string),
        toStringFunc(arrayExpander(choice($.number_array, $.bool_array))),
        upperFunc($._string_array_expansion),
        urlDecodeFunc($._string_array_expansion),
        uuidv4Func($._string_array_expansion),
      ),

    _string_array_expansion: ($) =>
      arrayExpander(
        choice(
          seq($.map_string_array_field, "[", field("key", "*"), "]"),
          $.string_array,
        ),
      ),

    boollike_field: ($) =>
      choice(
        $.bool_field,
        seq($.bool_array, "[", field("index", $.number), "]"),
        $.bool_func,
      ),

    numberlike_field: ($) =>
      choice(
        $.number_field,
        seq($.number_array, "[", field("index", $.number), "]"),
      ),

    stringlike_field: ($) =>
      choice(
        $.string_field,
        seq($.string_array, "[", field("index", $.number), "]"),
        $.string_func,
      ),

    // Cloudflare Ruleset Fields
    // see: https://developers.cloudflare.com/ruleset-engine/rules-language/fields/

    number_field: ($) =>
      choice(
        // Standard fields
        "http.request.timestamp.sec",
        "http.request.timestamp.msec",
        "ip.geoip.asnum",
        "ip.src.asnum",
        // Dynamic fields
        "cf.bot_management.score",
        "cf.edge.server_port",
        "cf.threat_score",
        "cf.waf.score",
        "cf.waf.score.sqli",
        "cf.waf.score.xss",
        "cf.waf.score.rce",
        // Magic Firewall fields
        "icmp.type",
        "icmp.code",
        "ip.hdr_len",
        "ip.len",
        "ip.opt.type",
        "ip.ttl",
        "tcp.flags",
        "tcp.srcport",
        "tcp.dstport",
        "udp.dstport",
        "udp.srcport",
        // HTTP request body fields
        "http.request.body.size",
        // HTTP response fields
        "http.response.code",
        "http.response.1xxx_code",
      ),

    ip_field: ($) =>
      choice(
        // Standard fields
        "ip.src",
        // Dyanmic fields
        "cf.edge.server_ip",
        // Magic Firewall fields
        "ip.dst",
        "ip.src",
      ),

    string_field: ($) =>
      choice(
        // Standard fields
        "http.cookie",
        "http.host",
        "http.referer",
        "http.request.full_uri",
        "http.request.method",
        "http.request.uri",
        "http.request.uri.path",
        "http.request.uri.path.extension",
        "http.request.uri.query",
        "http.user_agent",
        "http.request.version",
        "http.x_forwarded_for",
        "ip.src.lat",
        "ip.src.lon",
        "ip.src.city",
        "ip.src.postal_code",
        "ip.src.metro_code",
        "ip.src.region",
        "ip.src.region_code",
        "ip.src.timezone.name",
        "ip.geoip.continent",
        "ip.geoip.country",
        "ip.geoip.subdivision_1_iso_code",
        "ip.geoip.subdivision_2_iso_code",
        "ip.src.continent",
        "ip.src.country",
        "ip.src.subdivision_1_iso_code",
        "ip.src.subdivision_2_iso_code",
        "raw.http.request.full_uri",
        "raw.http.request.uri",
        "raw.http.request.uri.path",
        "raw.http.request.uri.query",
        // Dyanmic fields
        "cf.bot_management.ja3_hash",
        "cf.verified_bot_category",
        "cf.hostname.metadata",
        "cf.worker.upstream_zone",
        // Magic Firewall fields
        "cf.colo.name",
        "cf.colo.region",
        "icmp",
        "ip",
        "ip.dst.country",
        "ip.geoip.country",
        "ip.src.country",
        "tcp",
        "udp",
        // HTTP request body fields
        "http.request.body.raw",
        "http.request.body.mime",
        // HTTP response fields
        "cf.response.error_type",
      ),

    bytes_field: ($) => choice("cf.random_seed"),

    map_string_array_field: ($) =>
      choice(
        // Standard fields
        "http.request.cookies",
        // URI argument fields
        "http.request.uri.args",
        "raw.http.request.uri.args",
        // HTTP request header fields
        "http.request.headers",
        // HTTP request body fields
        "http.request.body.form",
        // HTTP response fields
        "http.response.headers",
      ),

    array_string_field: ($) =>
      choice(
        // URI argument fields
        "http.request.uri.args.names",
        "http.request.uri.args.values",
        "raw.http.request.uri.args.names",
        "raw.http.request.uri.args.values",
        // HTTP request header fields
        "http.request.headers.names",
        "http.request.headers.values",
        "http.request.accepted_languages",
        // HTTP request body fields
        "http.request.body.form.names",
        "http.request.body.form.values",
        // HTTP response fields
        "http.response.headers.names",
        "http.response.headers.values",
      ),

    array_number_field: ($) => choice("cf.bot_management.detection_ids"),

    bool_field: ($) =>
      choice(
        // Standard fields
        "ip.geoip.is_in_european_union",
        "ip.src.is_in_european_union",
        "ssl",
        // Dyanmic fields
        "cf.bot_management.verified_bot",
        "cf.bot_management.js_detection.passed",
        "cf.bot_management.corporate_proxy",
        "cf.bot_management.static_resource",
        "cf.client.bot",
        "cf.tls_client_auth.cert_revoked",
        "cf.tls_client_auth.cert_verified",
        // Magic Firewall fields
        "sip",
        "tcp.flags.ack",
        "tcp.flags.cwr",
        "tcp.flags.ecn",
        "tcp.flags.fin",
        "tcp.flags.push",
        "tcp.flags.reset",
        "tcp.flags.syn",
        "tcp.flags.urg",
        // HTTP request header fields
        "http.request.headers.truncated",
        // HTTP request body fields
        "http.request.body.truncated",
      ),
  },
});

// Cloudflare ruleset functions
// https://developers.cloudflare.com/ruleset-engine/rules-language/functions/
// TODO(nfowl): Verify if functions can take raw values as well

// Caveats discovered via validation:
// - Concat takes minimum 2 args
// - Concat does not support numbers (TODO: chase this up)
function concatFunc(rule, args) {
  return seq(
    field("func", "concat"),
    "(",
    rule,
    ",",
    repeat1(seq(args, optional(","))),
    ")",
  );
}

function endsWithFunc(rule, value) {
  return seq(
    field("func", "ends_with"),
    "(",
    field("field", rule),
    ",",
    field("value", value),
    ")",
  );
}

function lenFunc(rule) {
  return seq(field("func", "len"), "(", field("field", rule), ")");
}

function lookupFunc(rule, args) {
  return seq(
    field("func", "lookup_json_string"),
    "(",
    field("field", rule),
    field("keys", repeat1(seq(args, optional(",")))),
    ")",
  );
}

function lowerFunc(rule) {
  return seq(field("func", "lower"), "(", field("field", rule), ")");
}

function regexReplaceFunc(rule, value) {
  return seq(
    field("func", "regex_replace"),
    "(",
    field("source", rule),
    ",",
    field("regex", value),
    ",",
    field("replacement", value),
    ")",
  );
}

function removeBytesFunc(rule, value) {
  return seq(
    field("func", "remove_bytes"),
    "(",
    field("field", rule),
    ",",
    field("replacement", value),
    ")",
  );
}

function startsWithFunc(rule, value) {
  return seq(
    field("func", "starts_with"),
    "(",
    field("field", rule),
    ",",
    field("value", value),
    ")",
  );
}

function toStringFunc(rule) {
  return seq(field("func", "to_string"), "(", field("field", rule), ")");
}

function upperFunc(rule) {
  return seq(field("func", "upper"), "(", field("field", rule), ")");
}

function urlDecodeFunc(rule) {
  return seq(field("func", "url_decode"), "(", field("field", rule), ")");
}

function uuidv4Func(rule) {
  return seq(field("func", "uuidv4"), "(", field("seed", rule), ")");
}

function arrayExpander(rule) {
  return seq(rule, "[*]");
}
