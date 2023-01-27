module.exports = grammar({
  name: 'cloudflare',

  extras: $ => [
    $.comment, /\s/
  ],

  rules: {
    source_file: $ => repeat($._expression),

    _expression: $ => choice(
      $.not_expression,
      $.compound_expression,
      $.group,
      $.simple_expression,
      $._bool_lhs,
      $.in_expression,
    ),

    not_expression: $ => prec(4,seq(
      $.not_operator,
      $._expression,
    )),
    
    in_expression: $ => {
      const in_options = [
        [$.ip_field, choice($.ip_set,$.ip_list)],
        [$._string_lhs,$.string_set],
        [$._number_lhs,$.number_set],
      ];

      return choice(...in_options.map(([field_type,target]) => seq(
        field('lhs', field_type),
        field('operator','in'),
        field('rhs',target),
      )));
    },


    compound_expression: $ => {
      const precs = [
        ['&&',3],
        ['and',3],
        ['xor',2],
        ['^^',2],
        ['or',1],
        ['||',1],
      ];

      return choice(...precs.map(([operator,precedence]) => prec.left(
        precedence,seq(
          field('lhs', $._expression),
          field('operator', operator),
          field('rhs', $._expression)
        )
      )));
    },

    ip_set: $ => seq(
      "{",
      repeat1($._ip),
      "}"
    ),

    string_set: $ => seq(
      "{",
      repeat1($.string),
      "}"
    ),

    comment: $ => token(seq("#",/.*/)),

    number_set: $ => seq(
      "{",
      repeat1($.number),
      "}"
    ),

    simple_expression: $ => {
        const comps = [[
          [
            'eq','ne','lt','le','gt','ge',
            '==','!=','<','<=','>','>=',
            'contains','matches','~',
          ],$._string_lhs,$.string],
          [[
            'eq','ne','lt','le','gt','ge',
            '==','!=','<','<=','>','>='
          ],$._number_lhs,$.number],
          [[
            'eq','ne','==','!='
          ],$.ip_field,$._ip],
        ];

      return choice(
      ...comps.map(([operators,f,type]) => seq(
        field('lhs',f),
        field('operator',choice(...operators)),
        field('rhs',type)
      )));
    },

    _bool_lhs: $ => choice(
      $.bool_field,
      $.bool_func,
      $.boolean
    ),

    _number_lhs: $ => choice(
      $.number_field,
      $.number_func
    ),

    _string_lhs: $ => choice(
      $._stringlike_field,
      $.string_func,
    ),
    
    // functions grouped by return type for use in expressions
    string_func: $ => choice(
      concatFunc(choice($.string,$._stringlike_field),choice($.string,$._stringlike_field)),
      lookupFunc($._stringlike_field,choice($.string,$.number)),
      lowerFunc($._stringlike_field),
      regexReplaceFunc($._stringlike_field,$.string),
      removeBytesFunc(choice($._stringlike_field,$.bytes_field),$.string),
      toStringFunc(choice($.number_field,$.ip_field,$.bool_field)),
      upperFunc($._stringlike_field),
      urlDecodeFunc($._stringlike_field),
      uuidv4Func($._stringlike_field),
    ),

    number_func: $ => choice(
      lenFunc(choice($._stringlike_field,$.bytes_field)),
    ),

    bool_func: $ => choice(
      // $.any_func,
      // $.all_func
      endsWithFunc($._stringlike_field,$.string),
      startsWithFunc($._stringlike_field,$.string),
    ),


    //TODO(nfowl): Implement these
    // all_func: $ => seq(),
    // any_func: $ => seq(),
    // bit_slice_func: $ => seq(),
    // is_timed_hmac_valid_v0: $ => seq(),
    
    group: $ => seq(
      '(',
      field('inner',$._expression),
      ')',
    ),

    number: $ => /\d+/,
    
    //TODO(nfowl): Get this working with escaped characters and fix hacky mess
    string: $ => /"([^"]*)"/,

    // _escape_sequence: $ => token(prec(1, seq(
    //   '\\',
    //   /["\\]/,
    // ))),

    boolean: $ => choice(
      'true',
      'false',
    ),

    _ip: $ => choice(
      $.ipv4,
      $.ip_range,
      //TODO(nfowl): Add ipv6
    ),
    ipv4: $ => /(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}/,

    ip_range: $ => seq(
      field('ip',$.ipv4),
      '/',
      field('mask',/(?:3[0-2]|[0-2]?[0-9])/),
    ),

    ip_list: $ => token(seq(
      "$",
      choice(
        /[a-z\d_]*/,
        'cf.open_proxies',
        'cf.anonymizer',
        'cf.vpn',
        'cf.malware',
        'cf.botnetcc',
      )
    )),

    not_operator: $ => choice('not','!'),

    _array_lhs: $ => seq(choice(
      $.array_string_field,
      seq(
        $.map_string_array_field,
        '[',
        field('key',$.string),
        ']',
      ),
      concatFunc($.array_field_expansion,choice($.string,$._stringlike_field)),
      endsWithFunc($.array_field_expansion,$.string),
      lenFunc($.array_field_expansion),
      lookupFunc($.array_field_expansion,choice($.string,$.number)),
      lowerFunc($.array_field_expansion),
      regexReplaceFunc($.array_field_expansion,$.string),
      removeBytesFunc($.array_field_expansion,$.string),
      startsWithFunc($.array_field_expansion,$.string),
      toStringFunc($.array_field_expansion),
      upperFunc($.array_field_expansion),
      urlDecodeFunc($.array_field_expansion),
      uuidv4Func($.array_field_expansion),
    )),

    array_field_expansion: $ => seq(choice(
      seq($.map_string_array_field,'[',field('key','*'),']'),
      $._array_lhs
    ),
    '[*]'
    ),

    _stringlike_field: $ => choice(
      $.string_field,
      seq($._array_lhs,'[',field('index',$.number),']')
    ),

// Cloudflare Ruleset Fields
// see: https://developers.cloudflare.com/ruleset-engine/rules-language/fields/
// TODO(nfowl):
//    - Magic Firewall
//    - URI argument
//    - request body
//    - response

    number_field: $ => choice(
      'http.request.timestamp.sec',
      'http.request.timestamp.msec',
      'ip.geoip.asnum',
      'cf.bot_management.score',
      'cf.edge.server_port',
      'cf.threat_score',
      'cf.waf.score',
      'cf.waf.score.sqli',
      'cf.waf.score.xss',
      'cf.waf.score.rce',
    ),

    ip_field: $ => choice(
      'ip.src',
      'cf.edge.server_ip'
    ),

    string_field: $ => choice(
      'http.cookie',
      'http.host',
      'http.referer',
      'http.request.full_uri',
      'http.request.method',
      'http.request.uri',
      'http.request.uri.path',
      'http.request.uri.query',
      'http.user_agent',
      'http.request.version',
      'http.x_forwarded_for',
      'ip.src.lat',
      'ip.src.lon',
      'ip.src.city',
      'ip.src.postal_code',
      'ip.src.metro_code',
      'ip.geoip.continent',
      'ip.geoip.country',
      'ip.geoip.subdivision_1_iso_code',
      'ip.geoip.subdivision_2_iso_code',
      'raw.http.request.full_uri',
      'raw.http.request.uri',
      'raw.http.request.uri.path',
      'raw.http.request.uri.query',
      'cf.bot_management.ja3_hash',
      'cf.hostname.metadata',
      'cf.worker.upstream_zone',
    ),

    bytes_field: $ => choice(
      'cf.random_seed',
    ),
    
    map_string_array_field: $ => choice(
      'http.request.cookies',
      'http.request.headers',
    ),

    array_string_field: $ => choice(
      'http.request.headers.names',
      'http.request.headers.values',
      'http.request.accepted_languages',
    ),


    bool_field: $ => choice(
      'ip.geoip.is_in_european_union',
      'ssl',
      'cf.bot_management.verified_bot',
      'cf.bot_management.js_detection.passed',
      'cf.client.bot',
      'cf.tls_client_auth.cert_revoked',
      'cf.tls_client_auth.cert_verified',
      'http.request.headers.truncated',
    ),
  }
});

// Cloudflare ruleset functions
// https://developers.cloudflare.com/ruleset-engine/rules-language/functions/
// TODO(nfowl): Verify if functions can take raw values as well


// Caveats discovered via validation:
// - Concat takes minimum 2 args
// - Concat does not support numbers (TODO: chase this up)
function concatFunc(rule,args) {
    return seq(
      field('func','concat'),
      "(",
      rule,
      ',',
      repeat1(seq(args,optional(','))),
      ")",
    )
}

function endsWithFunc(rule,value) {
    return seq(
      field('func',"ends_with"),
      "(",
      field('field',rule),
      ',',
      field('value',value),
      ')',
    )
}

function lenFunc(rule) {
    return seq(
      field('func','len'),
      '(',
      field('field', rule),
      ')',
    )
}

function lookupFunc(rule,args) {
    return seq(
      field('func','lookup_json_string'),
      '(',
      field('field',rule),
      field('keys',repeat1(seq(args,optional(',')))),
      ')',
    )
}

function lowerFunc(rule) {
    return seq(
      field('func','lower'),
      '(',
      field('field',rule),
      ')'
    )
}

function regexReplaceFunc(rule,value) {
    return seq(
      field('func','regex_replace'),
      '(',
      field('source',rule),
      ',',
      field('regex',value),
      ',',
      field('replacement',value),
      ')',
    )
}

function removeBytesFunc(rule,value) {
    return seq(
      field('func','remove_bytes'),
      '(',
      field('field',rule),
      ',',
      field('replacement',value),
      ')',
    )
}

function startsWithFunc(rule,value) {
    return seq(
      field('func','starts_with'),
      "(",
      field('field',rule),
      ',',
      field('value',value),
      ')',
    )
}

function toStringFunc(rule) {
    return seq(
      field('func','to_string'),
      '(',
      field('field',rule),
      ')',
    )
}

function upperFunc(rule) {
    return seq(
      field('func','upper'),
      '(',
      field('field',rule),
      ')'
    )
}

function urlDecodeFunc(rule) {
    return seq(
      field('func','url_decode'),
      '(',
      field('field',rule),
      ')',
    )
}

function uuidv4Func(rule) {
    return seq(
      field('func','uuidv4'),
      '(',
      field('seed',rule),
      ')'
    )
}

