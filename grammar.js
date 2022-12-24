module.exports = grammar({
  name: 'cloudflare',

  rules: {
    source_file: $ => repeat($._expression),

    _expression: $ => choice(
      $.not_expression,
      $.compound_expression,
      $.group,
      $.simple_expression,
      $.boolean_field,
      $.in_expression,
    ),

    not_expression: $ => prec(4,seq(
      $.not_operator,
      $._expression,
    )),
    
    //TODO(nfowl): Make this cleaner
    in_expression: $ => choice(
      seq(
        field('field', $.ip_field),
        field('operator','in'),
        field('value',$.ip_set),
      ),
      seq(
        field('field', $.string_field),
        field('operator','in'),
        field('value',$.string_set),
      ),
      seq(
        field('field', $.number_field),
        field('operator','in'),
        field('value',$.number_set),
      ),
    ),

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
          field('left', $._expression),
          field('operator', operator),
          field('right', $._expression)
        )
      )));
    },

    _simple_expression: $ => seq(
      field('field', $._field),
      field('operator',$.comparison_operator),
      field('value', $._value)
    ),

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
          ],$.string_field,$.string],
          [[
            'eq','ne','lt','le','gt','ge',
            '==','!=','<','<=','>','>='
          ],$.number_field,$.number],
          [[
            'eq','ne','==','!='
          ],$.ip_field,$._ip],
          [[
            'eq','ne','==','!='
          ],$.boolean_field,$.boolean],
        ];

      return choice(
      ...comps.map(([operators,f,type]) => seq(
        field('field',f),
        field('operator',choice(...operators)),
        field('value',type)
      )));
    },

    _field: $ => choice(
      $.string_field,
      $.number_field,
      $.boolean_field,
      // $.list_field,
      // $.map_field
    ),

    group: $ => seq(
      '(',
      $._expression,
      ')',
    ),

    _value: $ => choice(
      $.number,
      $.boolean,
    ),

    number: $ => /\d+/,
    
    //TODO(nfowl): Get this working with escaped characters
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
    ip_range: $ => /(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}(\/(?:3[0-2]|[0-2]?[0-9]))/,

    logical_operator: $ => choice(
      prec(4, choice('not','!')),
      prec(3, choice('and','&&')),
      prec(2, choice('xor','^^')),
      prec(1, choice('or','||')),
    ),

    comparison_operator: $ => choice(
      '==',
      'eq',
    ),

    not_operator: $ => choice('not','!'),

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


    boolean_field: $ => choice(
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
