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

    // _simple_expression: $ => seq(
    //   field('field', $._field),
    //   field('operator',$.comparison_operator),
    //   field('value', $._value)
    // ),

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
          [[
            'eq','ne','==','!='
          ],$._bool_lhs,$.boolean],
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
    ),

    _number_lhs: $ => choice(
      $.number_field,
      $.number_func
    ),

    _string_lhs: $ => choice(
      $.string_field,
      $.string_func,
    ),
    
    // functions grouped by return type for use in expressions
    string_func: $ => choice(
      $.concat_func,
      $.lookup_func,
      $.lower_func,
      $.regex_replace_func,
      $.remove_bytes_func,
      $.to_string_func,
      $.upper_func,
      $.url_decode_func,
      $.uuid_func
    ),

    number_func: $ => choice(
      $.len_func
    ),

    bool_func: $ => choice(
      // $.any_func,
      // $.all_func
      $.ends_with_func,
      $.starts_with_func,
    ),

// Cloudflare ruleset functions
// https://developers.cloudflare.com/ruleset-engine/rules-language/functions/
// TODO(nfowl): Verify if functions can take raw values as well

    //TODO(nfowl): Implement these
    // all_func: $ => seq(),
    // any_func: $ => seq(),
    // bit_slice_func: $ => seq(),
    // is_timed_hmac_valid_v0: $ => seq(),
    
    // Caveats discovered via validation:
    // - Concat takes minimum 2 args
    // - Concat does not support numbers (TODO: chase this up)
    concat_func: $ => {
      const arg_type = choice(
        $.string,
        $.string_field,
        // $.number,
        // $.number_field,
      )

      return seq(
        "concat",
        "(",
        arg_type,
        ',',
        repeat1(seq(arg_type,optional(','))),
        ")",
      )
    },

    ends_with_func: $ => seq(
      "ends_with",
      "(",
      field('field',$.string_field),
      ',',
      field('value',$.string),
      ')',
    ),

    len_func: $ => seq(
      "len",
      "(",
      field('field', choice($.string_field,$.bytes_field)),
      ')',
    ),

    lookup_func: $ => seq(
      'lookup_json_string',
      '(',
      field('field',$.string_field),
      field('keys',repeat1(seq(choice($.string,$.number),optional(',')))),
      ')',
    ),

    lower_func: $ => seq(
      'lower',
      '(',
      field('field',$.string_field),
      ')'
    ),

    regex_replace_func: $ => seq(
      'regex_replace',
      '(',
      field('source',choice($.string_field,$.string)),
      ',',
      field('regex',$.string),
      ',',
      field('replacement',$.string),
      ')',
    ),

    remove_bytes_func: $ => seq(
      'remove_bytes',
      '(',
      field('field',choice($.string_field,$.bytes_field)),
      ',',
      field('replacement',$.string),
      ')',
    ),

    starts_with_func: $ => seq(
      "starts_with",
      "(",
      field('field',$.string_field),
      ',',
      field('value',$.string),
      ')',
    ),

    to_string_func: $ => seq(
      'to_string',
      '(',
      field('field',choice($.number_field,$.ip_field,$.bool_field)),
      ')',
    ),

    upper_func: $ => seq(
      'upper',
      '(',
      field('field',$.string_field),
      ')'
    ),

    url_decode_func: $ => seq(
      'url_decode',
      '(',
      field('field',$.string_field),
      ')',
    ),

    uuid_func: $ => seq(
      'uuidv4',
      '(',
      field('seed',$.bytes_field),
      ')'
    ),

    group: $ => seq(
      '(',
      $._expression,
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

    ip_list: $ => token(seq("$",/[a-z\d_]*/)),

    not_operator: $ => choice('not','!'),

// Cloudflare Ruleset Fields
// see: https://developers.cloudflare.com/ruleset-engine/rules-language/fields/
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
      'http.request.cookies',
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
    ),


    bool_field: $ => choice(
      'ip.geoip.is_in_european_union',
      'ssl',
      'cf.bot_management.verified_bot',
      'cf.bot_management.js_detection.passed',
      'cf.client.bot',
      'cf.tls_client_auth.cert_revoked',
      'cf.tls_client_auth.cert_verified',
    ),
  }
})
